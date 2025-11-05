//! Verification binary for composite KEM test vectors from
//! https://github.com/lamps-wg/draft-composite-kem/blob/main/src/testvectors.json

use base64::prelude::*;
use concrete_hybrid_kem::group::NominalGroup;
use concrete_hybrid_kem::hybrid::HybridKem;
use concrete_hybrid_kem::kem::{Kem, SeedSize, SharedSecretSize};
use concrete_hybrid_kem::{MlKem1024P384, MlKem768P256, MlKem768X25519};
use serde::{Deserialize, Serialize};
use std::env;
use std::fs;
use std::process;

/// Test vector structure matching the JSON format
#[derive(Debug, Deserialize, Serialize)]
struct TestVectors {
    tests: Vec<TestVector>,
}

/// Individual test vector
#[derive(Debug, Deserialize, Serialize)]
struct TestVector {
    #[serde(rename = "tcId")]
    tc_id: String,
    /// Encapsulation key (base64-encoded)
    ek: String,
    /// Decapsulation key (base64-encoded)
    dk: String,
    /// Ciphertext (base64-encoded)
    c: String,
    /// Shared secret (base64-encoded)
    k: String,
}

/// Parsed compound decapsulation key
struct CompoundDK {
    mlkem_seed: Vec<u8>,
    trad_pk: Vec<u8>,
    trad_sk: Vec<u8>,
}

/// Parse the compound decapsulation key format:
/// mlkemSeed (64 bytes) || lenTradPK (2 bytes, little-endian) || tradPK || tradSK
fn parse_compound_dk(dk: &[u8]) -> Result<CompoundDK, String> {
    if dk.len() < 66 {
        return Err(format!("DK too short: {} bytes", dk.len()));
    }

    // Extract ML-KEM seed (first 64 bytes)
    let mlkem_seed = dk[0..64].to_vec();

    // Extract traditional PK length (2 bytes, little-endian)
    let trad_pk_len = u16::from_le_bytes([dk[64], dk[65]]) as usize;

    // Check that we have enough bytes
    if dk.len() < 66 + trad_pk_len {
        return Err(format!(
            "DK too short for trad_pk: expected at least {} bytes, got {}",
            66 + trad_pk_len,
            dk.len()
        ));
    }

    // Extract traditional public key
    let trad_pk = dk[66..66 + trad_pk_len].to_vec();

    // Extract traditional secret key (remaining bytes)
    let trad_sk = dk[66 + trad_pk_len..].to_vec();

    Ok(CompoundDK {
        mlkem_seed,
        trad_pk,
        trad_sk,
    })
}

/// Parse X25519 or X448 private key (raw scalar bytes)
fn parse_x_private_key(sk_bytes: &[u8]) -> Result<Vec<u8>, String> {
    // X25519/X448 private keys are just the raw scalar bytes
    Ok(sk_bytes.to_vec())
}

/// Parse ECPrivateKey DER structure to extract the private scalar
/// ECPrivateKey ::= SEQUENCE {
///   version INTEGER { ecPrivkeyVer1(1) },
///   privateKey OCTET STRING,
///   ...
/// }
fn parse_ec_private_key(sk_bytes: &[u8]) -> Result<Vec<u8>, String> {
    // Simple DER parser for ECPrivateKey
    if sk_bytes.len() < 8 {
        return Err("ECPrivateKey too short".to_string());
    }

    // Expect SEQUENCE tag (0x30)
    if sk_bytes[0] != 0x30 {
        return Err(format!("Expected SEQUENCE tag, got 0x{:02x}", sk_bytes[0]));
    }

    let mut offset = 2; // Skip SEQUENCE tag and length

    // Expect INTEGER tag (0x02) for version
    if sk_bytes[offset] != 0x02 {
        return Err(format!("Expected INTEGER tag, got 0x{:02x}", sk_bytes[offset]));
    }
    offset += 1;

    // Skip version integer (length byte + data)
    let version_len = sk_bytes[offset] as usize;
    offset += 1 + version_len;

    // Expect OCTET STRING tag (0x04) for privateKey
    if sk_bytes[offset] != 0x04 {
        return Err(format!(
            "Expected OCTET STRING tag, got 0x{:02x}",
            sk_bytes[offset]
        ));
    }
    offset += 1;

    // Read privateKey length
    let pk_len = sk_bytes[offset] as usize;
    offset += 1;

    // Extract private key bytes
    if offset + pk_len > sk_bytes.len() {
        return Err("ECPrivateKey truncated".to_string());
    }

    Ok(sk_bytes[offset..offset + pk_len].to_vec())
}

/// Information needed to verify a compound DK test vector for a specific hybrid KEM
trait CompoundDKVerifier {
    type HybridKem: HybridKem + SeedSize + SharedSecretSize;
    type Group: NominalGroup;
    type PqKem: concrete_hybrid_kem::kem::PqKem;

    fn label() -> &'static [u8];
    fn parse_trad_sk(sk_bytes: &[u8]) -> Result<Vec<u8>, String>;
}

/// Verifier for MlKem768X25519
struct MlKem768X25519Verifier;
impl CompoundDKVerifier for MlKem768X25519Verifier {
    type HybridKem = MlKem768X25519;
    type Group = concrete_hybrid_kem::group::X25519;
    type PqKem = concrete_hybrid_kem::kem::MlKem768;

    fn label() -> &'static [u8] {
        b"\x5C\x2E\x2F\x2F\x5E\x5C"
    }

    fn parse_trad_sk(sk_bytes: &[u8]) -> Result<Vec<u8>, String> {
        parse_x_private_key(sk_bytes)
    }
}

/// Verifier for MlKem768P256
struct MlKem768P256Verifier;
impl CompoundDKVerifier for MlKem768P256Verifier {
    type HybridKem = MlKem768P256;
    type Group = concrete_hybrid_kem::group::P256;
    type PqKem = concrete_hybrid_kem::kem::MlKem768;

    fn label() -> &'static [u8] {
        b"MLKEM768-P256"
    }

    fn parse_trad_sk(sk_bytes: &[u8]) -> Result<Vec<u8>, String> {
        parse_ec_private_key(sk_bytes)
    }
}

/// Verifier for MlKem1024P384
struct MlKem1024P384Verifier;
impl CompoundDKVerifier for MlKem1024P384Verifier {
    type HybridKem = MlKem1024P384;
    type Group = concrete_hybrid_kem::group::P384;
    type PqKem = concrete_hybrid_kem::kem::MlKem1024;

    fn label() -> &'static [u8] {
        b"MLKEM1024-P384"
    }

    fn parse_trad_sk(sk_bytes: &[u8]) -> Result<Vec<u8>, String> {
        parse_ec_private_key(sk_bytes)
    }
}

/// Verify a test vector using the hybrid KEM implementation
fn verify_test_vector<V: CompoundDKVerifier>(
    tc_id: &str,
    ek_expected: &[u8],
    dk_bytes: &[u8],
    c: &[u8],
    k_expected: &[u8],
) -> Result<(), String> {
    println!("\nVerifying test vector: {}", tc_id);

    // Step 1: Validate sizes against hybrid KEM constants
    if ek_expected.len() != V::HybridKem::ENCAPSULATION_KEY_SIZE {
        return Err(format!(
            "EK length mismatch: expected {}, got {}",
            V::HybridKem::ENCAPSULATION_KEY_SIZE,
            ek_expected.len()
        ));
    }

    if c.len() != V::HybridKem::CIPHERTEXT_SIZE {
        return Err(format!(
            "Ciphertext length mismatch: expected {}, got {}",
            V::HybridKem::CIPHERTEXT_SIZE,
            c.len()
        ));
    }

    if k_expected.len() != V::HybridKem::SHARED_SECRET_SIZE {
        return Err(format!(
            "Shared secret length mismatch: expected {}, got {}",
            V::HybridKem::SHARED_SECRET_SIZE,
            k_expected.len()
        ));
    }

    // Step 2: Parse the compound decapsulation key
    let compound_dk = parse_compound_dk(dk_bytes)?;
    println!("  ✓ Parsed compound DK");

    // Step 3: Parse traditional private key
    let trad_sk = V::parse_trad_sk(&compound_dk.trad_sk)?;
    println!("  ✓ Parsed traditional private key ({} bytes)", trad_sk.len());

    // Step 4: Generate and verify traditional public key
    let trad_pk_generated = V::Group::exp(&V::Group::generator(), &trad_sk);
    if trad_pk_generated != compound_dk.trad_pk {
        return Err("Traditional public key mismatch".to_string());
    }
    println!("  ✓ Traditional public key verified");

    // Step 5: Reconstruct and verify encapsulation key
    let (_, ek_pq, _) = V::PqKem::derive_key_pair(&compound_dk.mlkem_seed);
    let mut ek_reconstructed = ek_pq;
    ek_reconstructed.extend_from_slice(&compound_dk.trad_pk);

    if ek_reconstructed != ek_expected {
        return Err(format!(
            "EK mismatch:\n  Reconstructed: {}\n  Expected:     {}",
            hex::encode(&ek_reconstructed),
            hex::encode(ek_expected)
        ));
    }
    println!("  ✓ Encapsulation key matches");

    // Step 6: Decapsulate ciphertext components
    let pq_ct_size = V::HybridKem::CIPHERTEXT_SIZE - V::Group::ELEMENT_SIZE;
    let ct_pq = &c[..pq_ct_size];
    let ct_t = &c[pq_ct_size..];

    let ss_pq = V::PqKem::decaps(&compound_dk.mlkem_seed, &ct_pq.to_vec());
    let ss_t_elem = V::Group::exp(&ct_t.to_vec(), &trad_sk);
    let ss_t = V::Group::element_to_shared_secret(&ss_t_elem);

    // Step 7: Combine using C2-PRI combiner (matching GC hybrid KEM)
    use concrete_hybrid_kem::kdf::{Kdf, Sha3_256};
    let ss_combined = Sha3_256::compute(
        ss_pq
            .iter()
            .chain(ss_t.iter())
            .chain(ct_t.iter())
            .chain(compound_dk.trad_pk.iter())
            .chain(V::label().iter())
            .cloned(),
    );

    if ss_combined != k_expected {
        return Err(format!(
            "Shared secret mismatch:\n  Computed: {}\n  Expected: {}",
            hex::encode(&ss_combined),
            hex::encode(k_expected)
        ));
    }
    println!("  ✓ Shared secret matches");

    Ok(())
}

fn main() {
    let args: Vec<String> = env::args().collect();
    if args.len() != 2 {
        eprintln!("Usage: {} <testvectors.json>", args[0]);
        process::exit(1);
    }

    let filename = &args[1];
    let content = match fs::read_to_string(filename) {
        Ok(content) => content,
        Err(err) => {
            eprintln!("Error reading file {}: {}", filename, err);
            process::exit(1);
        }
    };

    let test_vectors: TestVectors = match serde_json::from_str(&content) {
        Ok(vectors) => vectors,
        Err(err) => {
            eprintln!("Error parsing JSON: {}", err);
            process::exit(1);
        }
    };

    println!("Successfully parsed {} test vectors", test_vectors.tests.len());

    let mut all_passed = true;

    // Verify MLKEM768-X25519-SHA3-256
    if let Some(tv) = test_vectors
        .tests
        .iter()
        .find(|t| t.tc_id == "id-MLKEM768-X25519-SHA3-256")
    {
        let ek = BASE64_STANDARD.decode(&tv.ek).expect("Failed to decode ek");
        let dk = BASE64_STANDARD.decode(&tv.dk).expect("Failed to decode dk");
        let c = BASE64_STANDARD.decode(&tv.c).expect("Failed to decode c");
        let k = BASE64_STANDARD.decode(&tv.k).expect("Failed to decode k");

        match verify_test_vector::<MlKem768X25519Verifier>(&tv.tc_id, &ek, &dk, &c, &k) {
            Ok(()) => println!("  ✅ PASSED"),
            Err(e) => {
                println!("  ❌ FAILED: {}", e);
                all_passed = false;
            }
        }
    } else {
        println!("\n❌ Test vector not found: id-MLKEM768-X25519-SHA3-256");
        all_passed = false;
    }

    // Verify MLKEM768-ECDH-P256-SHA3-256
    if let Some(tv) = test_vectors
        .tests
        .iter()
        .find(|t| t.tc_id == "id-MLKEM768-ECDH-P256-SHA3-256")
    {
        let ek = BASE64_STANDARD.decode(&tv.ek).expect("Failed to decode ek");
        let dk = BASE64_STANDARD.decode(&tv.dk).expect("Failed to decode dk");
        let c = BASE64_STANDARD.decode(&tv.c).expect("Failed to decode c");
        let k = BASE64_STANDARD.decode(&tv.k).expect("Failed to decode k");

        match verify_test_vector::<MlKem768P256Verifier>(&tv.tc_id, &ek, &dk, &c, &k) {
            Ok(()) => println!("  ✅ PASSED"),
            Err(e) => {
                println!("  ❌ FAILED: {}", e);
                all_passed = false;
            }
        }
    } else {
        println!("\n❌ Test vector not found: id-MLKEM768-ECDH-P256-SHA3-256");
        all_passed = false;
    }

    // Verify MLKEM1024-ECDH-P384-SHA3-256
    if let Some(tv) = test_vectors
        .tests
        .iter()
        .find(|t| t.tc_id == "id-MLKEM1024-ECDH-P384-SHA3-256")
    {
        let ek = BASE64_STANDARD.decode(&tv.ek).expect("Failed to decode ek");
        let dk = BASE64_STANDARD.decode(&tv.dk).expect("Failed to decode dk");
        let c = BASE64_STANDARD.decode(&tv.c).expect("Failed to decode c");
        let k = BASE64_STANDARD.decode(&tv.k).expect("Failed to decode k");

        match verify_test_vector::<MlKem1024P384Verifier>(&tv.tc_id, &ek, &dk, &c, &k) {
            Ok(()) => println!("  ✅ PASSED"),
            Err(e) => {
                println!("  ❌ FAILED: {}", e);
                all_passed = false;
            }
        }
    } else {
        println!("\n❌ Test vector not found: id-MLKEM1024-ECDH-P384-SHA3-256");
        all_passed = false;
    }

    if all_passed {
        println!("\n✅ All test vectors passed!");
    } else {
        println!("\n❌ Some test vectors failed!");
        process::exit(1);
    }
}
