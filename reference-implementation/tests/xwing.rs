//! Tests verifying MLKEM768-X25519 test vectors using the x-wing crate

use concrete_hybrid_kem::test_vectors::HybridKemTestVector;
use concrete_hybrid_kem::MlKem768X25519;
use x_wing::{Ciphertext, Decapsulate, DecapsulationKey};

fn array_from<const N: usize>(slice: &[u8]) -> [u8; N] {
    slice
        .try_into()
        .expect(&format!("{} != {}", N, slice.len()))
}

#[test]
fn verify_xwing_compat() {
    const NUM_VECTORS: u8 = 5;

    for i in 0..NUM_VECTORS {
        // Generate test vector using the library
        let vector = HybridKemTestVector::generate::<MlKem768X25519>(i);

        // Construct keys and ciphertext from bytes
        let dk = DecapsulationKey::from(array_from(&vector.decapsulation_key));
        let ct = Ciphertext::from(&array_from(&vector.ciphertext));

        // Verify that the encapsulation key produced by `dk` is correct
        let ek_bytes = dk.encapsulation_key().to_bytes().to_vec();
        assert_eq!(
            ek_bytes, vector.encapsulation_key,
            "Encapsulation key mismatch for test vector {}",
            i
        );

        // Verify decapsulation produces the expected shared secret
        let ss = dk.decapsulate(&ct).expect("Decapsulation failed");
        let ss_bytes: &[u8] = ss.as_ref();

        assert_eq!(
            ss_bytes,
            vector.shared_secret.as_slice(),
            "Shared secret mismatch for test vector {}",
            i
        );
    }
}
