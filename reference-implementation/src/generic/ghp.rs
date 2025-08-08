use super::error::KemError;
use super::traits::{AsBytes, EncapsDerand, HybridKemLabel, Kdf, Kem, Prg};
use super::utils::{concat, max, min, split, HybridValue};

/// GHP Hybrid KEM implementation
///
/// Generic hybrid KEM construction based on the GHP scheme described in
/// draft-irtf-cfrg-hybrid-kems, combining a traditional KEM and a post-quantum KEM.
#[derive(Default)]
pub struct GhpHybridKem<KemT, KemPq, KdfImpl, PrgImpl, Label> {
    _phantom: std::marker::PhantomData<(KemT, KemPq, KdfImpl, PrgImpl, Label)>,
}

impl<KemT, KemPq, KdfImpl, PrgImpl, Label> GhpHybridKem<KemT, KemPq, KdfImpl, PrgImpl, Label>
where
    KemT: Kem,
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
            KemT::EncapsulationKey,
            KemPq::DecapsulationKey,
            KemT::DecapsulationKey,
        ),
        KemError,
    > {
        // Expand seed using PRG
        let seed_full = PrgImpl::prg(seed);

        // Split expanded seed into post-quantum and traditional portions
        let (seed_pq, seed_t) = split(KemPq::SEED_LENGTH, KemT::SEED_LENGTH, &seed_full)?;

        // Generate key pairs for each component
        let (ek_t, dk_t) = KemT::derive_key_pair(seed_t).map_err(|_| KemError::Traditional)?;
        let (ek_pq, dk_pq) = KemPq::derive_key_pair(seed_pq).map_err(|_| KemError::PostQuantum)?;

        Ok((ek_pq, ek_t, dk_pq, dk_t))
    }
}

impl<KemT, KemPq, KdfImpl, PrgImpl, Label> Kem
    for GhpHybridKem<KemT, KemPq, KdfImpl, PrgImpl, Label>
where
    KemT: Kem,
    KemPq: Kem,
    KdfImpl: Kdf,
    PrgImpl: Prg,
    Label: HybridKemLabel,
{
    // Hybrid constants derived from constituent KEMs
    const ENCAPSULATION_KEY_LENGTH: usize =
        KemPq::ENCAPSULATION_KEY_LENGTH + KemT::ENCAPSULATION_KEY_LENGTH;
    const CIPHERTEXT_LENGTH: usize = KemPq::CIPHERTEXT_LENGTH + KemT::CIPHERTEXT_LENGTH;

    const SEED_LENGTH: usize = max(KemPq::SEED_LENGTH, KemT::SEED_LENGTH);
    const SHARED_SECRET_LENGTH: usize =
        min(KemPq::SHARED_SECRET_LENGTH, KemT::SHARED_SECRET_LENGTH);

    const DECAPSULATION_KEY_LENGTH: usize = Self::SEED_LENGTH;

    type EncapsulationKey = HybridValue;
    type DecapsulationKey = Vec<u8>;
    type Ciphertext = HybridValue;
    type SharedSecret = Vec<u8>;

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
        let (ek_pq_bytes, ek_t_bytes) = ek.split(
            KemPq::ENCAPSULATION_KEY_LENGTH,
            KemT::ENCAPSULATION_KEY_LENGTH,
        )?;

        let ek_t = KemT::EncapsulationKey::from(ek_t_bytes);
        let ek_pq = KemPq::EncapsulationKey::from(ek_pq_bytes);

        // Encapsulate with post-quantum KEM
        let (ct_pq, ss_pq) = KemPq::encaps(&ek_pq, rng).map_err(|_| KemError::PostQuantum)?;

        // Encapsulate with traditional KEM
        let (ct_t, ss_t) = KemT::encaps(&ek_t, rng).map_err(|_| KemError::Traditional)?;

        // Create hybrid ciphertext
        let ct_hybrid = Self::Ciphertext::new(&ct_pq, &ct_t);

        // Compute hybrid shared secret using KDF
        // KDF input: concat(ss_PQ, ss_T, ct_PQ, ct_T, ek_PQ, ek_T, label)
        let kdf_input = concat(&[
            ss_pq.as_bytes(),
            ss_t.as_bytes(),
            ct_pq.as_bytes(),
            ct_t.as_bytes(),
            ek_pq.as_bytes(),
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
            ct.split(KemPq::CIPHERTEXT_LENGTH, KemT::CIPHERTEXT_LENGTH)?;

        let ct_t = KemT::Ciphertext::from(ct_t_bytes);
        let ct_pq = KemPq::Ciphertext::from(ct_pq_bytes);

        // Decapsulate with post-quantum KEM
        let ss_pq = KemPq::decaps(&dk_pq, &ct_pq).map_err(|_| KemError::PostQuantum)?;

        // Decapsulate with traditional KEM
        let ss_t = KemT::decaps(&dk_t, &ct_t).map_err(|_| KemError::Traditional)?;

        // Derive encapsulation keys from decapsulation keys
        let ek_pq = KemPq::to_encapsulation_key(&dk_pq).map_err(|_| KemError::PostQuantum)?;
        let ek_t = KemT::to_encapsulation_key(&dk_t).map_err(|_| KemError::Traditional)?;

        // Compute hybrid shared secret using KDF
        // KDF input: concat(ss_PQ, ss_T, ct_PQ, ct_T, ek_PQ, ek_T, label)
        let kdf_input = concat(&[
            ss_pq.as_bytes(),
            ss_t.as_bytes(),
            ct_pq.as_bytes(),
            ct_t.as_bytes(),
            ek_pq.as_bytes(),
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

impl<KemT, KemPq, KdfImpl, PrgImpl, Label> EncapsDerand
    for GhpHybridKem<KemT, KemPq, KdfImpl, PrgImpl, Label>
where
    KemT: Kem + EncapsDerand,
    KemPq: Kem + EncapsDerand,
    KdfImpl: Kdf,
    PrgImpl: Prg,
    Label: HybridKemLabel,
{
    const RANDOMNESS_LENGTH: usize = KemPq::RANDOMNESS_LENGTH + KemT::RANDOMNESS_LENGTH;

    fn encaps_derand(
        ek: &Self::EncapsulationKey,
        randomness: &[u8],
    ) -> Result<(Self::Ciphertext, Self::SharedSecret), KemError> {
        // Deserialize component encapsulation keys
        let (ek_pq_bytes, ek_t_bytes) = ek.split(
            KemPq::ENCAPSULATION_KEY_LENGTH,
            KemT::ENCAPSULATION_KEY_LENGTH,
        )?;

        let ek_t = KemT::EncapsulationKey::from(ek_t_bytes);
        let ek_pq = KemPq::EncapsulationKey::from(ek_pq_bytes);

        // Split randomness for post-quantum and traditional components
        let (rand_pq, rand_t) = split(
            KemPq::RANDOMNESS_LENGTH,
            KemT::RANDOMNESS_LENGTH,
            randomness,
        )?;

        // Deterministic encapsulation with post-quantum KEM
        let (ct_pq, ss_pq) =
            KemPq::encaps_derand(&ek_pq, rand_pq).map_err(|_| KemError::PostQuantum)?;

        // Deterministic encapsulation with traditional KEM
        let (ct_t, ss_t) = KemT::encaps_derand(&ek_t, rand_t).map_err(|_| KemError::Traditional)?;

        // Create hybrid ciphertext
        let ct_hybrid = Self::Ciphertext::new(&ct_pq, &ct_t);

        // Compute hybrid shared secret using KDF
        // KDF input: concat(ss_PQ, ss_T, ct_PQ, ct_T, ek_PQ, ek_T, label)
        let kdf_input = concat(&[
            ss_pq.as_bytes(),
            ss_t.as_bytes(),
            ct_pq.as_bytes(),
            ct_t.as_bytes(),
            ek_pq.as_bytes(),
            ek_t.as_bytes(),
            Label::LABEL,
        ]);

        let ss_hybrid = KdfImpl::kdf(&kdf_input);

        Ok((ct_hybrid, ss_hybrid))
    }
}
