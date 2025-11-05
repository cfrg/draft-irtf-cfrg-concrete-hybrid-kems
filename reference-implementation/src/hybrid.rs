use crate::group::*;
use crate::kdf::*;
use crate::kem::*;
use crate::prg::*;
use rand::{CryptoRng, Rng};

/// Split a vector into two parts
fn split(v: &[u8], m: usize, n: usize) -> (Vec<u8>, Vec<u8>) {
    assert_eq!(
        v.len(),
        m + n,
        "split: expected length {}, got {}",
        m + n,
        v.len()
    );
    let first = v[..m].to_vec();
    let second = v[m..].to_vec();
    (first, second)
}

fn expand_decaps_key_group<PQ: PqKem, T: NominalGroup, PRG: Prg>(
    seed: &[u8],
) -> (DecapsulationKey, Scalar, EncapsulationKey, Element) {
    let mut seed_full = vec![0; PQ::SEED_SIZE + T::SEED_SIZE];
    PRG::generate(seed, &mut seed_full);
    let (seed_pq, seed_t) = split(&seed_full, PQ::SEED_SIZE, T::SEED_SIZE);

    let (dk_pq, ek_pq, _key_info) = PQ::derive_key_pair(&seed_pq);
    let dk_t = T::random_scalar(&seed_t);
    let ek_t = T::exp(&T::generator(), &dk_t);

    (dk_pq, dk_t, ek_pq, ek_t)
}

fn prepare_encaps_group<PQ: PqKem, T: NominalGroup>(
    ek_pq: &EncapsulationKey,
    ek_t: &Element,
    rng: &mut impl CryptoRng,
) -> (SharedSecret, SharedSecret, Ciphertext, Element) {
    let (ss_pq, ct_pq) = PQ::encaps(&ek_pq, rng);

    let mut seed_e = vec![0u8; T::SEED_SIZE];
    rng.fill(seed_e.as_mut_slice());
    let sk_e = T::random_scalar(&seed_e);
    let ct_t = T::exp(&T::generator(), &sk_e);
    let ss_t = T::element_to_shared_secret(&T::exp(&ek_t, &sk_e));

    (ss_pq, ss_t, ct_pq, ct_t)
}

fn prepare_encaps_group_derand<PQ: PqKem + EncapsDerand, T: NominalGroup>(
    ek_pq: &EncapsulationKey,
    ek_t: &Element,
    randomness: &[u8],
) -> (SharedSecret, SharedSecret, Ciphertext, Element) {
    assert_eq!(
        randomness.len(),
        PQ::RANDOMNESS_SIZE + T::SEED_SIZE,
        "prepare_encaps_group_derand: expected {} bytes of randomness, got {}",
        PQ::RANDOMNESS_SIZE + T::SEED_SIZE,
        randomness.len()
    );

    let (randomness_pq, seed_e) = split(randomness, PQ::RANDOMNESS_SIZE, T::SEED_SIZE);

    let (ss_pq, ct_pq) = PQ::encaps_derand(&ek_pq, &randomness_pq);

    let sk_e = T::random_scalar(&seed_e);
    let ct_t = T::exp(&T::generator(), &sk_e);
    let ss_t = T::element_to_shared_secret(&T::exp(&ek_t, &sk_e));

    (ss_pq, ss_t, ct_pq, ct_t)
}

fn prepare_decaps_group<PQ: PqKem, T: NominalGroup>(
    ct_pq: &Ciphertext,
    ct_t: &Element,
    dk_pq: &DecapsulationKey,
    dk_t: &Scalar,
) -> (SharedSecret, SharedSecret) {
    let ss_pq = PQ::decaps(dk_pq, ct_pq);
    let ss_t = T::element_to_shared_secret(&T::exp(ct_t, dk_t));
    (ss_pq, ss_t)
}

fn expand_decaps_key_kem<PQ: PqKem, T: TKem, PRG: Prg>(
    seed: &[u8],
) -> (
    DecapsulationKey,
    DecapsulationKey,
    EncapsulationKey,
    EncapsulationKey,
) {
    let mut seed_full = vec![0; PQ::SEED_SIZE + T::SEED_SIZE];
    PRG::generate(seed, &mut seed_full);
    let (seed_pq, seed_t) = split(&seed_full, PQ::SEED_SIZE, T::SEED_SIZE);

    let (dk_pq, ek_pq, _key_info) = PQ::derive_key_pair(&seed_pq);
    let (dk_t, ek_t, _key_info) = T::derive_key_pair(&seed_t);

    (dk_pq, dk_t, ek_pq, ek_t)
}

fn prepare_encaps_kem<PQ: PqKem, T: TKem>(
    ek_pq: &EncapsulationKey,
    ek_t: &EncapsulationKey,
    rng: &mut impl CryptoRng,
) -> (SharedSecret, SharedSecret, Ciphertext, Ciphertext) {
    let (ss_pq, ct_pq) = PQ::encaps(&ek_pq, rng);
    let (ss_t, ct_t) = T::encaps(&ek_t, rng);
    (ss_pq, ss_t, ct_pq, ct_t)
}

fn prepare_decaps_kem<PQ: PqKem, T: TKem>(
    ct_pq: &Ciphertext,
    ct_t: &Ciphertext,
    dk_pq: &DecapsulationKey,
    dk_t: &DecapsulationKey,
) -> (SharedSecret, SharedSecret) {
    let ss_pq = PQ::decaps(dk_pq, ct_pq);
    let ss_t = T::decaps(dk_t, ct_t);
    (ss_pq, ss_t)
}

fn universal_combiner<K: Kdf>(
    ss_pq: &[u8],
    ss_t: &[u8],
    ct_pq: &[u8],
    ct_t: &[u8],
    ek_pq: &[u8],
    ek_t: &[u8],
    label: &[u8],
) -> Output {
    K::compute(
        ss_pq
            .iter()
            .chain(ss_t.iter())
            .chain(ct_pq.iter())
            .chain(ct_t.iter())
            .chain(ek_pq.iter())
            .chain(ek_t.iter())
            .chain(label.iter())
            .cloned(),
    )
}

fn c2pri_combiner<K: Kdf>(
    ss_pq: &[u8],
    ss_t: &[u8],
    ct_t: &[u8],
    ek_t: &[u8],
    label: &[u8],
) -> Output {
    K::compute(
        ss_pq
            .iter()
            .chain(ss_t.iter())
            .chain(ct_t.iter())
            .chain(ek_t.iter())
            .chain(label.iter())
            .cloned(),
    )
}

/// Common decapsulation logic for GC hybrid KEM
/// Takes the component keys and ciphertext, performs decapsulation and combining
fn decaps_with_keys_group<PQ: PqKem, T: NominalGroup, K: Kdf>(
    dk_pq: &DecapsulationKey,
    dk_t: &Scalar,
    ek_t: &Element,
    ct: &Ciphertext,
    label: &[u8],
) -> SharedSecret {
    // Split ciphertext into components
    let (ct_pq, ct_t) = split(ct, PQ::CIPHERTEXT_SIZE, T::ELEMENT_SIZE);

    // Decapsulate components
    let (ss_pq, ss_t) = prepare_decaps_group::<PQ, T>(&ct_pq, &ct_t, dk_pq, dk_t);

    // Combine using C2-PRI
    c2pri_combiner::<K>(&ss_pq, &ss_t, &ct_t, ek_t, label)
}

pub trait HybridKemConstants: SeedSize + SharedSecretSize {
    const LABEL: &'static [u8];
}

// We use this struct to smuggle out intermediate values to the test vectors
pub struct HybridSubKeys {
    pub dk_pq: Vec<u8>,
    pub dk_t: Vec<u8>,
}

pub trait HybridKem: Kem<KeyInfo = HybridSubKeys> + EncapsDerand {}

impl<K> HybridKem for K where K: Kem<KeyInfo = HybridSubKeys> + EncapsDerand {}

#[derive(Default)]
pub struct GU<PQ, T, P, K, C> {
    _phantom: core::marker::PhantomData<(PQ, T, P, K, C)>,
}

impl<PQ, T, P, K, C> SeedSize for GU<PQ, T, P, K, C>
where
    C: SeedSize,
{
    const SEED_SIZE: usize = C::SEED_SIZE;
}

impl<PQ, T, P, K, C> SharedSecretSize for GU<PQ, T, P, K, C>
where
    C: SharedSecretSize,
{
    const SHARED_SECRET_SIZE: usize = C::SHARED_SECRET_SIZE;
}

impl<PQ, T, P, K, C> Kem for GU<PQ, T, P, K, C>
where
    PQ: PqKem,
    T: NominalGroup,
    P: Prg,
    K: Kdf,
    C: HybridKemConstants,
{
    const ENCAPSULATION_KEY_SIZE: usize = PQ::ENCAPSULATION_KEY_SIZE + T::ELEMENT_SIZE;
    const DECAPSULATION_KEY_SIZE: usize = C::SEED_SIZE;
    const CIPHERTEXT_SIZE: usize = PQ::CIPHERTEXT_SIZE + T::ELEMENT_SIZE;

    type KeyInfo = HybridSubKeys;

    fn derive_key_pair(seed: &[u8]) -> (DecapsulationKey, EncapsulationKey, Self::KeyInfo) {
        assert_eq!(seed.len(), Self::SEED_SIZE);
        let (dk_pq, dk_t, ek_pq, ek_t) = expand_decaps_key_group::<PQ, T, P>(&seed);
        let mut ek = ek_pq;
        ek.append(&mut ek_t.clone());
        (seed.to_vec(), ek, HybridSubKeys { dk_pq, dk_t })
    }

    fn encaps(ek: &EncapsulationKey, rng: &mut impl CryptoRng) -> (SharedSecret, Ciphertext) {
        assert_eq!(ek.len(), Self::ENCAPSULATION_KEY_SIZE);
        let (ek_pq, ek_t) = split(ek, PQ::ENCAPSULATION_KEY_SIZE, T::ELEMENT_SIZE);
        let (ss_pq, ss_t, ct_pq, ct_t) = prepare_encaps_group::<PQ, T>(&ek_pq, &ek_t, rng);
        let ss_h = universal_combiner::<K>(&ss_pq, &ss_t, &ct_pq, &ct_t, &ek_pq, &ek_t, C::LABEL);
        let mut ct_h = ct_pq;
        ct_h.append(&mut ct_t.clone());
        (ss_h, ct_h)
    }

    fn decaps(dk: &DecapsulationKey, ct: &Ciphertext) -> SharedSecret {
        assert_eq!(dk.len(), Self::DECAPSULATION_KEY_SIZE);
        assert_eq!(ct.len(), Self::CIPHERTEXT_SIZE);
        let (ct_pq, ct_t) = split(ct, PQ::CIPHERTEXT_SIZE, T::ELEMENT_SIZE);
        let (dk_pq, dk_t, ek_pq, ek_t) = expand_decaps_key_group::<PQ, T, P>(dk);
        let (ss_pq, ss_t) = prepare_decaps_group::<PQ, T>(&ct_pq, &ct_t, &dk_pq, &dk_t);
        let ss_h = universal_combiner::<K>(&ss_pq, &ss_t, &ct_pq, &ct_t, &ek_pq, &ek_t, C::LABEL);
        ss_h
    }
}

impl<PQ, T, P, K, C> EncapsDerand for GU<PQ, T, P, K, C>
where
    PQ: PqKem + EncapsDerand,
    T: NominalGroup,
    P: Prg,
    K: Kdf,
    C: HybridKemConstants,
{
    const RANDOMNESS_SIZE: usize = PQ::RANDOMNESS_SIZE + T::SEED_SIZE;

    fn encaps_derand(ek: &EncapsulationKey, randomness: &[u8]) -> (SharedSecret, Ciphertext) {
        assert_eq!(ek.len(), Self::ENCAPSULATION_KEY_SIZE);
        assert_eq!(randomness.len(), Self::RANDOMNESS_SIZE);

        let (ek_pq, ek_t) = split(ek, PQ::ENCAPSULATION_KEY_SIZE, T::ELEMENT_SIZE);
        let (ss_pq, ss_t, ct_pq, ct_t) =
            prepare_encaps_group_derand::<PQ, T>(&ek_pq, &ek_t, randomness);
        let ss_h = universal_combiner::<K>(&ss_pq, &ss_t, &ct_pq, &ct_t, &ek_pq, &ek_t, C::LABEL);

        let mut ct_h = ct_pq;
        ct_h.append(&mut ct_t.clone());

        (ss_h, ct_h)
    }
}

#[derive(Default)]
pub struct GC<PQ, T, P, K, C> {
    _phantom: core::marker::PhantomData<(PQ, T, P, K, C)>,
}

impl<PQ, T, P, K, C> SeedSize for GC<PQ, T, P, K, C>
where
    C: SeedSize,
{
    const SEED_SIZE: usize = C::SEED_SIZE;
}

impl<PQ, T, P, K, C> SharedSecretSize for GC<PQ, T, P, K, C>
where
    C: SharedSecretSize,
{
    const SHARED_SECRET_SIZE: usize = C::SHARED_SECRET_SIZE;
}

impl<PQ, T, P, K, C> Kem for GC<PQ, T, P, K, C>
where
    PQ: PqKem,
    T: NominalGroup,
    P: Prg,
    K: Kdf,
    C: HybridKemConstants,
{
    const ENCAPSULATION_KEY_SIZE: usize = PQ::ENCAPSULATION_KEY_SIZE + T::ELEMENT_SIZE;
    const DECAPSULATION_KEY_SIZE: usize = C::SEED_SIZE;
    const CIPHERTEXT_SIZE: usize = PQ::CIPHERTEXT_SIZE + T::ELEMENT_SIZE;

    type KeyInfo = HybridSubKeys;

    fn derive_key_pair(seed: &[u8]) -> (DecapsulationKey, EncapsulationKey, Self::KeyInfo) {
        assert_eq!(seed.len(), Self::SEED_SIZE);
        let (dk_pq, dk_t, ek_pq, ek_t) = expand_decaps_key_group::<PQ, T, P>(&seed);
        let mut ek = ek_pq;
        ek.append(&mut ek_t.clone());
        (seed.to_vec(), ek, HybridSubKeys { dk_pq, dk_t })
    }

    fn encaps(ek: &EncapsulationKey, rng: &mut impl CryptoRng) -> (SharedSecret, Ciphertext) {
        assert_eq!(ek.len(), Self::ENCAPSULATION_KEY_SIZE);
        let (ek_pq, ek_t) = split(ek, PQ::ENCAPSULATION_KEY_SIZE, T::ELEMENT_SIZE);
        let (ss_pq, ss_t, ct_pq, ct_t) = prepare_encaps_group::<PQ, T>(&ek_pq, &ek_t, rng);
        let ss_h = c2pri_combiner::<K>(&ss_pq, &ss_t, &ct_t, &ek_t, C::LABEL);
        let mut ct_h = ct_pq;
        ct_h.append(&mut ct_t.clone());
        (ss_h, ct_h)
    }

    fn decaps(dk: &DecapsulationKey, ct: &Ciphertext) -> SharedSecret {
        assert_eq!(dk.len(), Self::DECAPSULATION_KEY_SIZE);
        assert_eq!(ct.len(), Self::CIPHERTEXT_SIZE);

        // Expand seed-based DK to get component keys
        let (dk_pq, dk_t, _ek_pq, ek_t) = expand_decaps_key_group::<PQ, T, P>(dk);

        // Use common decapsulation logic
        decaps_with_keys_group::<PQ, T, K>(&dk_pq, &dk_t, &ek_t, ct, C::LABEL)
    }
}

impl<PQ, T, P, K, C> EncapsDerand for GC<PQ, T, P, K, C>
where
    PQ: PqKem + EncapsDerand,
    T: NominalGroup,
    P: Prg,
    K: Kdf,
    C: HybridKemConstants,
{
    const RANDOMNESS_SIZE: usize = PQ::RANDOMNESS_SIZE + T::SEED_SIZE;

    fn encaps_derand(ek: &EncapsulationKey, randomness: &[u8]) -> (SharedSecret, Ciphertext) {
        assert_eq!(ek.len(), Self::ENCAPSULATION_KEY_SIZE);
        assert_eq!(randomness.len(), Self::RANDOMNESS_SIZE);

        let (ek_pq, ek_t) = split(ek, PQ::ENCAPSULATION_KEY_SIZE, T::ELEMENT_SIZE);
        let (ss_pq, ss_t, ct_pq, ct_t) =
            prepare_encaps_group_derand::<PQ, T>(&ek_pq, &ek_t, randomness);
        let ss_h = c2pri_combiner::<K>(&ss_pq, &ss_t, &ct_t, &ek_t, C::LABEL);

        let mut ct_h = ct_pq;
        ct_h.append(&mut ct_t.clone());

        (ss_h, ct_h)
    }
}

impl<PQ, T, P, K, C> GC<PQ, T, P, K, C>
where
    PQ: PqKem,
    T: NominalGroup,
    P: Prg,
    K: Kdf,
    C: HybridKemConstants,
{
    /// Decapsulate using a compound decapsulation key (LAMPS format)
    ///
    /// Compound DK format: mlkemSeed (64 bytes) || lenTradPK (2 bytes, LE) || tradPK || tradSK
    pub fn decaps_compound(compound_dk: &[u8], ct: &Ciphertext, trad_sk: &Scalar) -> SharedSecret {
        assert_eq!(ct.len(), PQ::CIPHERTEXT_SIZE + T::ELEMENT_SIZE);

        // Extract ML-KEM seed from compound DK (first 64 bytes)
        let dk_pq = compound_dk[0..64].to_vec();

        // Get traditional EK (stored in compound DK after length field)
        let trad_pk_len = u16::from_le_bytes([compound_dk[64], compound_dk[65]]) as usize;
        let ek_t = compound_dk[66..66 + trad_pk_len].to_vec();

        // Use common decapsulation logic
        decaps_with_keys_group::<PQ, T, K>(&dk_pq, trad_sk, &ek_t, ct, C::LABEL)
    }

    /// Generate encapsulation key from compound decapsulation key
    pub fn encapsulation_key_from_compound(compound_dk: &[u8], trad_sk: &Scalar) -> EncapsulationKey {
        // Extract ML-KEM seed and derive ML-KEM EK
        let dk_pq = compound_dk[0..64].to_vec();
        let (_, ek_pq, _) = PQ::derive_key_pair(&dk_pq);

        // Compute traditional public key
        let ek_t = T::exp(&T::generator(), trad_sk);

        // Combine
        let mut ek = ek_pq;
        ek.extend_from_slice(&ek_t);
        ek
    }
}

#[derive(Default)]
pub struct KU<PQ, T, P, K, C> {
    _phantom: core::marker::PhantomData<(PQ, T, P, K, C)>,
}

impl<PQ, T, P, K, C> SeedSize for KU<PQ, T, P, K, C>
where
    C: SeedSize,
{
    const SEED_SIZE: usize = C::SEED_SIZE;
}

impl<PQ, T, P, K, C> SharedSecretSize for KU<PQ, T, P, K, C>
where
    C: SharedSecretSize,
{
    const SHARED_SECRET_SIZE: usize = C::SHARED_SECRET_SIZE;
}

impl<PQ, T, P, K, C> Kem for KU<PQ, T, P, K, C>
where
    PQ: PqKem,
    T: TKem,
    P: Prg,
    K: Kdf,
    C: HybridKemConstants,
{
    const ENCAPSULATION_KEY_SIZE: usize = PQ::ENCAPSULATION_KEY_SIZE + T::ENCAPSULATION_KEY_SIZE;
    const DECAPSULATION_KEY_SIZE: usize = C::SEED_SIZE;
    const CIPHERTEXT_SIZE: usize = PQ::CIPHERTEXT_SIZE + T::CIPHERTEXT_SIZE;

    type KeyInfo = HybridSubKeys;

    fn derive_key_pair(seed: &[u8]) -> (DecapsulationKey, EncapsulationKey, Self::KeyInfo) {
        assert_eq!(seed.len(), Self::SEED_SIZE);
        let (dk_pq, dk_t, ek_pq, ek_t) = expand_decaps_key_kem::<PQ, T, P>(&seed);
        let mut ek = ek_pq;
        ek.append(&mut ek_t.clone());
        (seed.to_vec(), ek, HybridSubKeys { dk_pq, dk_t })
    }

    fn encaps(ek: &EncapsulationKey, rng: &mut impl CryptoRng) -> (SharedSecret, Ciphertext) {
        assert_eq!(ek.len(), Self::ENCAPSULATION_KEY_SIZE);
        let (ek_pq, ek_t) = split(ek, PQ::ENCAPSULATION_KEY_SIZE, T::ENCAPSULATION_KEY_SIZE);
        let (ss_pq, ss_t, ct_pq, ct_t) = prepare_encaps_kem::<PQ, T>(&ek_pq, &ek_t, rng);
        let ss_h = universal_combiner::<K>(&ss_pq, &ss_t, &ct_pq, &ct_t, &ek_pq, &ek_t, C::LABEL);
        let mut ct_h = ct_pq;
        ct_h.append(&mut ct_t.clone());
        (ss_h, ct_h)
    }

    fn decaps(dk: &DecapsulationKey, ct: &Ciphertext) -> SharedSecret {
        assert_eq!(dk.len(), Self::DECAPSULATION_KEY_SIZE);
        assert_eq!(ct.len(), Self::CIPHERTEXT_SIZE);
        let (ct_pq, ct_t) = split(ct, PQ::CIPHERTEXT_SIZE, T::CIPHERTEXT_SIZE);
        let (dk_pq, dk_t, ek_pq, ek_t) = expand_decaps_key_kem::<PQ, T, P>(dk);
        let (ss_pq, ss_t) = prepare_decaps_kem::<PQ, T>(&ct_pq, &ct_t, &dk_pq, &dk_t);
        let ss_h = universal_combiner::<K>(&ss_pq, &ss_t, &ct_pq, &ct_t, &ek_pq, &ek_t, C::LABEL);
        ss_h
    }
}

#[derive(Default)]
pub struct KC<PQ, T, P, K, C> {
    _phantom: core::marker::PhantomData<(PQ, T, P, K, C)>,
}

impl<PQ, T, P, K, C> SeedSize for KC<PQ, T, P, K, C>
where
    C: SeedSize,
{
    const SEED_SIZE: usize = C::SEED_SIZE;
}

impl<PQ, T, P, K, C> SharedSecretSize for KC<PQ, T, P, K, C>
where
    C: SharedSecretSize,
{
    const SHARED_SECRET_SIZE: usize = C::SHARED_SECRET_SIZE;
}

impl<PQ, T, P, K, C> Kem for KC<PQ, T, P, K, C>
where
    PQ: PqKem,
    T: TKem,
    P: Prg,
    K: Kdf,
    C: HybridKemConstants,
{
    const ENCAPSULATION_KEY_SIZE: usize = PQ::ENCAPSULATION_KEY_SIZE + T::ENCAPSULATION_KEY_SIZE;
    const DECAPSULATION_KEY_SIZE: usize = C::SEED_SIZE;
    const CIPHERTEXT_SIZE: usize = PQ::CIPHERTEXT_SIZE + T::CIPHERTEXT_SIZE;

    type KeyInfo = HybridSubKeys;

    fn derive_key_pair(seed: &[u8]) -> (DecapsulationKey, EncapsulationKey, Self::KeyInfo) {
        assert_eq!(seed.len(), Self::SEED_SIZE);
        let (dk_pq, dk_t, ek_pq, ek_t) = expand_decaps_key_kem::<PQ, T, P>(&seed);
        let mut ek = ek_pq;
        ek.append(&mut ek_t.clone());
        (seed.to_vec(), ek, HybridSubKeys { dk_pq, dk_t })
    }

    fn encaps(ek: &EncapsulationKey, rng: &mut impl CryptoRng) -> (SharedSecret, Ciphertext) {
        assert_eq!(ek.len(), Self::ENCAPSULATION_KEY_SIZE);
        let (ek_pq, ek_t) = split(ek, PQ::ENCAPSULATION_KEY_SIZE, T::ENCAPSULATION_KEY_SIZE);
        let (ss_pq, ss_t, ct_pq, ct_t) = prepare_encaps_kem::<PQ, T>(&ek_pq, &ek_t, rng);
        let ss_h = c2pri_combiner::<K>(&ss_pq, &ss_t, &ct_t, &ek_t, C::LABEL);
        let mut ct_h = ct_pq;
        ct_h.append(&mut ct_t.clone());
        (ss_h, ct_h)
    }

    fn decaps(dk: &DecapsulationKey, ct: &Ciphertext) -> SharedSecret {
        assert_eq!(dk.len(), Self::DECAPSULATION_KEY_SIZE);
        assert_eq!(ct.len(), Self::CIPHERTEXT_SIZE);
        let (ct_pq, ct_t) = split(ct, PQ::CIPHERTEXT_SIZE, T::CIPHERTEXT_SIZE);
        let (dk_pq, dk_t, _ek_pq, ek_t) = expand_decaps_key_kem::<PQ, T, P>(dk);
        let (ss_pq, ss_t) = prepare_decaps_kem::<PQ, T>(&ct_pq, &ct_t, &dk_pq, &dk_t);
        let ss_h = c2pri_combiner::<K>(&ss_pq, &ss_t, &ct_t, &ek_t, C::LABEL);
        ss_h
    }
}
