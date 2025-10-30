use hybrid_array::typenum::Unsigned;
use ml_kem::{
    kem::{Decapsulate, Encapsulate},
    EncapsulateDeterministic, EncodedSizeUser, KemCore,
};
use rand::{CryptoRng, Rng};

pub type Seed = Vec<u8>;
pub type EncapsulationKey = Vec<u8>;
pub type DecapsulationKey = Vec<u8>;
pub type Ciphertext = Vec<u8>;
pub type SharedSecret = Vec<u8>;

pub trait SeedSize {
    const SEED_SIZE: usize;
}

pub trait SharedSecretSize {
    const SHARED_SECRET_SIZE: usize;
}

pub trait Kem: SeedSize + SharedSecretSize {
    const ENCAPSULATION_KEY_SIZE: usize;
    const DECAPSULATION_KEY_SIZE: usize;
    const CIPHERTEXT_SIZE: usize;

    // Additional information about derived keys (e.g., subkeys)
    type KeyInfo;

    fn derive_key_pair(seed: &[u8]) -> (DecapsulationKey, EncapsulationKey, Self::KeyInfo);
    fn encaps(ek: &EncapsulationKey, rng: &mut impl CryptoRng) -> (SharedSecret, Ciphertext);
    fn decaps(dk: &DecapsulationKey, ct: &Ciphertext) -> SharedSecret;

    fn generate_key_pair(
        rng: &mut impl CryptoRng,
    ) -> (DecapsulationKey, EncapsulationKey, Self::KeyInfo) {
        let mut seed = vec![0; Self::SEED_SIZE];
        rng.fill(seed.as_mut_slice());
        Self::derive_key_pair(&seed)
    }
}

pub trait EncapsDerand: Kem {
    const RANDOMNESS_SIZE: usize;

    fn encaps_derand(ek: &EncapsulationKey, randomness: &[u8]) -> (Ciphertext, SharedSecret);
}

/// Marker trait for traditional KEMs
pub trait TKem: Kem {}

/// Marker trait for post-quantum KEMs
pub trait PqKem: Kem {}

macro_rules! define_ml_kem {
    ($mlkem:ident, $params:ty) => {
        pub struct $mlkem;

        // Implementation of the bis traits
        impl SeedSize for $mlkem {
            const SEED_SIZE: usize = 64;
        }

        impl SharedSecretSize for $mlkem {
            const SHARED_SECRET_SIZE: usize = 32;
        }

        impl Kem for $mlkem {
            const ENCAPSULATION_KEY_SIZE: usize =
                <<ml_kem::$mlkem as KemCore>::EncapsulationKey as EncodedSizeUser>::EncodedSize::USIZE;
            const DECAPSULATION_KEY_SIZE: usize = 64;
            const CIPHERTEXT_SIZE: usize = <ml_kem::$mlkem as KemCore>::CiphertextSize::USIZE;

            type KeyInfo = ();

            fn derive_key_pair(
                seed: &[u8],
            ) -> (
                DecapsulationKey,
                EncapsulationKey,
                Self::KeyInfo,
            ) {
                use ml_kem::$mlkem;

                assert_eq!(seed.len(), Self::SEED_SIZE);
                let (_dk_inner, ek_inner) = $mlkem::from_seed(seed.try_into().unwrap());

                let ek = ek_inner.as_bytes().as_slice().to_vec();
                (seed.to_vec(), ek, ())
            }

            fn encaps(
                ek: &EncapsulationKey,
                rng: &mut impl rand::CryptoRng,
            ) -> (SharedSecret, Ciphertext) {
                assert_eq!(ek.len(), Self::ENCAPSULATION_KEY_SIZE);
                let ek_inner: ml_kem::kem::EncapsulationKey<$params> =
                    ml_kem::kem::EncapsulationKey::from_bytes(ek.as_slice().try_into().expect("Invalid EK size"));
                let (ct_inner, ss_inner) = ek_inner
                    .encapsulate(rng)
                    .expect("Encapsulation failed");

                let ss = ss_inner.as_slice().to_vec();
                let ct = ct_inner.as_slice().to_vec();

                (ss, ct)
            }

            fn decaps(
                dk: &DecapsulationKey,
                ct: &Ciphertext,
            ) -> SharedSecret {
                use ml_kem::$mlkem;

                assert_eq!(dk.len(), Self::DECAPSULATION_KEY_SIZE);
                assert_eq!(ct.len(), Self::CIPHERTEXT_SIZE);
                let (dk_inner, _ek_inner) = $mlkem::from_seed(dk.as_slice().try_into().unwrap());

                let ct_inner = ml_kem::Ciphertext::<$mlkem>::try_from(ct.as_slice()).expect("Invalid CT");
                let ss_inner = dk_inner
                    .decapsulate(&ct_inner)
                    .expect("Decapsulation failed");

                ss_inner.as_slice().to_vec()
            }
        }

        impl PqKem for $mlkem {}

        impl EncapsDerand for $mlkem {
            const RANDOMNESS_SIZE: usize = 32;

            fn encaps_derand(
                ek: &EncapsulationKey,
                randomness: &[u8],
            ) -> (SharedSecret, Ciphertext) {
                assert_eq!(
                    ek.len(),
                    <Self as Kem>::ENCAPSULATION_KEY_SIZE
                );
                assert_eq!(randomness.len(), Self::RANDOMNESS_SIZE);

                let m = ml_kem::B32::try_from(randomness).expect("Invalid randomness length");

                let ek_inner: ml_kem::kem::EncapsulationKey<$params> =
                    ml_kem::kem::EncapsulationKey::from_bytes(
                        ek.as_slice().try_into().expect("Invalid EK size"),
                    );
                let (ct_inner, ss_inner) = ek_inner
                    .encapsulate_deterministic(&m)
                    .expect("Deterministic encapsulation failed");

                let ct = ct_inner.as_slice().to_vec();
                let ss = ss_inner.as_slice().to_vec();

                (ss, ct)
            }
        }
    }
}

define_ml_kem! { MlKem512, ml_kem::MlKem512Params }
define_ml_kem! { MlKem768, ml_kem::MlKem768Params }
define_ml_kem! { MlKem1024, ml_kem::MlKem1024Params }

#[cfg(test)]
pub mod test {
    use super::*;

    fn test_deterministic_derivation<K: Kem>() {
        // Create test seed
        let seed: Vec<u8> = (0..K::SEED_SIZE)
            .map(|i| (i as u8).wrapping_mul(31).wrapping_add(13))
            .collect();

        // Test deterministic key derivation
        let (dk1, ek1, _) = K::derive_key_pair(&seed);
        let (dk2, ek2, _) = K::derive_key_pair(&seed);

        assert_eq!(
            ek1, ek2,
            "Deterministic key derivation should produce same encapsulation key"
        );
        assert_eq!(
            dk1, dk2,
            "Deterministic key derivation should produce same decapsulation key"
        );

        // Test key sizes
        assert_eq!(
            dk1.len(),
            K::DECAPSULATION_KEY_SIZE,
            "Decapsulation key size mismatch"
        );
        assert_eq!(
            ek1.len(),
            K::ENCAPSULATION_KEY_SIZE,
            "Encapsulation key size mismatch"
        );
    }

    fn test_roundtrip<K: Kem>() {
        use rand::Rng;
        let mut rng = rand::rng();

        // Generate key pair
        let mut seed = vec![0u8; K::SEED_SIZE];
        rng.fill(seed.as_mut_slice());
        let (dk, ek, _) = K::derive_key_pair(&seed);

        // Test encapsulation
        let (ss1, ct) = K::encaps(&ek, &mut rng);

        // Test sizes
        assert_eq!(ct.len(), K::CIPHERTEXT_SIZE, "Ciphertext size mismatch");
        assert_eq!(
            ss1.len(),
            K::SHARED_SECRET_SIZE,
            "Shared secret size mismatch"
        );

        // Test decapsulation
        let ss2 = K::decaps(&dk, &ct);

        assert_eq!(
            ss1, ss2,
            "Encapsulation and decapsulation should produce same shared secret"
        );

        // Test that different encapsulations produce different ciphertexts (with very high probability)
        let (_ss3, ct3) = K::encaps(&ek, &mut rng);
        let (_ss4, ct4) = K::encaps(&ek, &mut rng);

        // With proper randomness, ciphertexts should be different
        assert_ne!(
            ct3, ct4,
            "Different encapsulations should produce different ciphertexts"
        );
    }

    pub fn test_deterministic_encaps<K: Kem + EncapsDerand>() {
        // Generate key pair
        let seed = vec![1u8; K::SEED_SIZE];
        let (dk, ek, _) = K::derive_key_pair(&seed);

        // Create deterministic randomness
        let randomness = vec![42u8; K::RANDOMNESS_SIZE];

        // Test deterministic encapsulation
        let (ss1, ct1) = K::encaps_derand(&ek, &randomness);
        let (ss2, ct2) = K::encaps_derand(&ek, &randomness);

        assert_eq!(
            ct1, ct2,
            "Deterministic encapsulation should produce same ciphertext"
        );
        assert_eq!(
            ss1, ss2,
            "Deterministic encapsulation should produce same shared secret"
        );

        // Test sizes
        assert_eq!(ct1.len(), K::CIPHERTEXT_SIZE, "Ciphertext size mismatch");
        assert_eq!(
            ss1.len(),
            K::SHARED_SECRET_SIZE,
            "Shared secret size mismatch"
        );

        // Test that it decapsulates correctly
        let ss3 = K::decaps(&dk, &ct1);

        assert_eq!(
            ss1, ss3,
            "Deterministic encapsulation should be compatible with decapsulation"
        );

        // Test that different randomness produces different outputs
        let randomness2 = vec![43u8; K::RANDOMNESS_SIZE];
        let (ss4, ct4) = K::encaps_derand(&ek, &randomness2);

        assert_ne!(
            ct1, ct4,
            "Different randomness should produce different ciphertext"
        );
        assert_ne!(
            ss1, ss4,
            "Different randomness should produce different shared secret"
        );
    }

    pub fn test_all<K: Kem + EncapsDerand>() {
        test_deterministic_derivation::<K>();
        test_roundtrip::<K>();
        test_deterministic_encaps::<K>();
    }

    #[test]
    fn mlkem512() {
        test_all::<MlKem512>();
    }

    #[test]
    fn mlkem768() {
        test_all::<MlKem768>();
    }

    #[test]
    fn mlkem1024() {
        test_all::<MlKem1024>();
    }
}
