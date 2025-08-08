use super::error::KemError;
use super::traits::{AsBytes, EncapsDerand, HybridKemLabel, Kdf, Kem, NominalGroup, Prg};
use super::utils::{concat, min, split, HybridValue};

/// QSF Hybrid KEM implementation
///
/// Optimized construction for the case where the traditional component is a
/// nominal group and the PQ component has strong binding properties.
#[derive(Default)]
pub struct QsfHybridKem<GroupT, KemPq, KdfImpl, PrgImpl, Label, const SEED_LENGTH: usize> {
    _phantom: std::marker::PhantomData<(GroupT, KemPq, KdfImpl, PrgImpl, Label)>,
}

impl<GroupT, KemPq, KdfImpl, PrgImpl, Label, const SEED_LENGTH: usize>
    QsfHybridKem<GroupT, KemPq, KdfImpl, PrgImpl, Label, SEED_LENGTH>
where
    GroupT: NominalGroup,
    KemPq: Kem,
    KdfImpl: Kdf,
    PrgImpl: Prg,
    Label: HybridKemLabel,
{
    fn expand_decapsulation_key(
        seed: &[u8],
    ) -> Result<
        (
            KemPq::EncapsulationKey,
            GroupT::Element,
            KemPq::DecapsulationKey,
            GroupT::Scalar,
        ),
        KemError,
    > {
        // Expand seed using PRG
        let seed_full = PrgImpl::prg(seed);

        // Split expanded seed into post-quantum and traditional portions
        let (seed_pq, seed_t) = split(KemPq::SEED_LENGTH, GroupT::SEED_LENGTH, &seed_full)?;

        // Generate traditional component using group operations
        let dk_t = GroupT::random_scalar(seed_t).map_err(|_| KemError::Traditional)?;
        let ek_t = GroupT::exp(&GroupT::generator(), &dk_t);

        // Generate post-quantum key pair
        let (ek_pq, dk_pq) = KemPq::derive_key_pair(seed_pq).map_err(|_| KemError::PostQuantum)?;

        Ok((ek_pq, ek_t, dk_pq, dk_t))
    }
}

impl<GroupT, KemPq, KdfImpl, PrgImpl, Label, const SEED_LENGTH: usize> Kem
    for QsfHybridKem<GroupT, KemPq, KdfImpl, PrgImpl, Label, SEED_LENGTH>
where
    GroupT: NominalGroup,
    KemPq: Kem,
    KdfImpl: Kdf,
    PrgImpl: Prg,
    Label: HybridKemLabel,
{
    // Hybrid constants derived from group and KEM
    const ENCAPSULATION_KEY_LENGTH: usize =
        KemPq::ENCAPSULATION_KEY_LENGTH + GroupT::ELEMENT_LENGTH;
    const CIPHERTEXT_LENGTH: usize = KemPq::CIPHERTEXT_LENGTH + GroupT::ELEMENT_LENGTH;

    const SEED_LENGTH: usize = SEED_LENGTH;
    const SHARED_SECRET_LENGTH: usize =
        min(KemPq::SHARED_SECRET_LENGTH, GroupT::SHARED_SECRET_LENGTH);

    const DECAPSULATION_KEY_LENGTH: usize = Self::SEED_LENGTH;

    type EncapsulationKey = HybridValue;
    type DecapsulationKey = Vec<u8>;
    type Ciphertext = HybridValue;
    type SharedSecret = Vec<u8>;
    // Error type is handled in trait implementations

    fn generate_key_pair<R: rand::CryptoRng>(
        rng: &mut R,
    ) -> Result<(Self::EncapsulationKey, Self::DecapsulationKey), KemError> {
        // Generate random seed
        let mut seed = vec![0u8; Self::SEED_LENGTH];
        rng.fill_bytes(&mut seed);

        Self::derive_key_pair(&seed)
    }

    fn derive_key_pair(
        seed: &[u8],
    ) -> Result<(Self::EncapsulationKey, Self::DecapsulationKey), KemError> {
        if seed.len() != Self::SEED_LENGTH {
            return Err(KemError::InvalidInputLength);
        }

        let (ek_pq, ek_t, _dk_pq, _dk_t) = Self::expand_decapsulation_key(seed)?;
        let ek_hybrid = Self::EncapsulationKey::new(&ek_pq, &ek_t);
        let dk_hybrid = seed.to_vec();

        Ok((ek_hybrid, dk_hybrid))
    }

    fn encaps<R: rand::CryptoRng>(
        ek: &Self::EncapsulationKey,
        rng: &mut R,
    ) -> Result<(Self::Ciphertext, Self::SharedSecret), KemError> {
        // Deserialize component encapsulation keys
        let (ek_pq_bytes, ek_t_bytes) =
            ek.split(KemPq::ENCAPSULATION_KEY_LENGTH, GroupT::ELEMENT_LENGTH)?;

        let ek_pq = KemPq::EncapsulationKey::from(ek_pq_bytes);
        let ek_t = GroupT::Element::from(ek_t_bytes);

        // Encapsulate with post-quantum KEM
        let (ct_pq, ss_pq) = KemPq::encaps(&ek_pq, rng).map_err(|_| KemError::PostQuantum)?;

        // Generate ephemeral scalar for traditional component using secure randomness
        let mut ephemeral_seed = vec![0u8; GroupT::SEED_LENGTH];
        rng.fill_bytes(&mut ephemeral_seed);
        let sk_e = GroupT::random_scalar(&ephemeral_seed).map_err(|_| KemError::Traditional)?;

        // Traditional component: Diffie-Hellman
        let ct_t = GroupT::exp(&GroupT::generator(), &sk_e);
        let shared_point = GroupT::exp(&ek_t, &sk_e);
        let ss_t = GroupT::element_to_shared_secret(&shared_point);

        // Create hybrid ciphertext
        let ct_hybrid = Self::Ciphertext::new(&ct_pq, &ct_t);

        // Compute hybrid shared secret using KDF
        // QSF optimization: KDF input is concat(ss_PQ, ss_T, ct_T, ek_T, label)
        // Note: ct_PQ and ek_PQ are omitted due to C2PRI property of PQ KEM
        let kdf_input = concat(&[
            ss_pq.as_bytes(),
            &ss_t,
            ct_t.as_bytes(),
            ek_t.as_bytes(),
            Label::LABEL,
        ]);

        let ss_hybrid = KdfImpl::kdf(&kdf_input);

        Ok((ct_hybrid, ss_hybrid))
    }

    fn decaps(
        dk: &Self::DecapsulationKey,
        ct: &Self::Ciphertext,
    ) -> Result<Self::SharedSecret, KemError> {
        // Generate component decapsulation keys
        let (_ek_pq, _ek_t, dk_pq, dk_t) = Self::expand_decapsulation_key(dk)?;

        // Deserialize component ciphertexts
        let (ct_pq_bytes, ct_t_bytes) =
            ct.split(KemPq::CIPHERTEXT_LENGTH, GroupT::ELEMENT_LENGTH)?;

        let ct_pq = KemPq::Ciphertext::from(ct_pq_bytes);
        let ct_t = GroupT::Element::from(ct_t_bytes);

        // Traditional component: Diffie-Hellman
        let shared_point = GroupT::exp(&ct_t, &dk_t);
        let ss_t = GroupT::element_to_shared_secret(&shared_point);

        // Decapsulate with post-quantum KEM
        let ss_pq = KemPq::decaps(&dk_pq, &ct_pq).map_err(|_| KemError::PostQuantum)?;

        // Derive traditional encapsulation key
        let ek_t = GroupT::exp(&GroupT::generator(), &dk_t);

        // Compute hybrid shared secret using KDF
        // QSF optimization: KDF input is concat(ss_PQ, ss_T, ct_T, ek_T, label)
        let kdf_input = concat(&[
            ss_pq.as_bytes(),
            &ss_t,
            ct_t.as_bytes(),
            ek_t.as_bytes(),
            Label::LABEL,
        ]);

        let ss_hybrid = KdfImpl::kdf(&kdf_input);

        Ok(ss_hybrid)
    }

    fn to_encapsulation_key(
        dk: &Self::DecapsulationKey,
    ) -> Result<Self::EncapsulationKey, KemError> {
        let (ek_pq, ek_t, _dk_pq, _dk_t) = Self::expand_decapsulation_key(dk)?;
        Ok(Self::EncapsulationKey::new(&ek_pq, &ek_t))
    }
}

impl<GroupT, KemPq, KdfImpl, PrgImpl, Label, const SEED_LENGTH: usize> EncapsDerand
    for QsfHybridKem<GroupT, KemPq, KdfImpl, PrgImpl, Label, SEED_LENGTH>
where
    GroupT: NominalGroup,
    KemPq: Kem + EncapsDerand,
    KdfImpl: Kdf,
    PrgImpl: Prg,
    Label: HybridKemLabel,
{
    const RANDOMNESS_LENGTH: usize = KemPq::RANDOMNESS_LENGTH + GroupT::SEED_LENGTH;

    fn encaps_derand(
        ek: &Self::EncapsulationKey,
        randomness: &[u8],
    ) -> Result<(Self::Ciphertext, Self::SharedSecret), KemError> {
        // Deserialize component encapsulation keys
        let (ek_pq_bytes, ek_t_bytes) =
            ek.split(KemPq::ENCAPSULATION_KEY_LENGTH, GroupT::ELEMENT_LENGTH)?;

        let ek_t = GroupT::Element::from(ek_t_bytes);
        let ek_pq = KemPq::EncapsulationKey::from(ek_pq_bytes);

        // Split randomness for post-quantum and traditional components
        let (rand_pq, rand_t) = split(KemPq::RANDOMNESS_LENGTH, GroupT::SEED_LENGTH, randomness)?;

        // Generate ephemeral scalar deterministically for traditional component
        let sk_e = GroupT::random_scalar(rand_t).map_err(|_| KemError::Traditional)?;

        // Traditional component: Diffie-Hellman
        let ct_t = GroupT::exp(&GroupT::generator(), &sk_e);
        let shared_point = GroupT::exp(&ek_t, &sk_e);
        let ss_t = GroupT::element_to_shared_secret(&shared_point);

        // Deterministic encapsulation with post-quantum KEM
        let (ct_pq, ss_pq) =
            KemPq::encaps_derand(&ek_pq, rand_pq).map_err(|_| KemError::PostQuantum)?;

        // Create hybrid ciphertext
        let ct_hybrid = Self::Ciphertext::new(&ct_pq, &ct_t);

        // Compute hybrid shared secret using KDF
        // QSF optimization: KDF input is concat(ss_PQ, ss_T, ct_T, ek_T, label)
        // Note: Groups always support deterministic operations
        let kdf_input = concat(&[
            ss_pq.as_bytes(),
            &ss_t,
            ct_t.as_bytes(),
            ek_t.as_bytes(),
            Label::LABEL,
        ]);

        let ss_hybrid = KdfImpl::kdf(&kdf_input);

        Ok((ct_hybrid, ss_hybrid))
    }
}
