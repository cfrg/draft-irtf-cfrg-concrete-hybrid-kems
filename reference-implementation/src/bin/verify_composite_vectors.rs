//! Verification binary for composite KEM test vectors from
//! https://github.com/lamps-wg/draft-composite-kem/blob/main/src/testvectors.json

use base64::prelude::*;
use concrete_hybrid_kem::group::NominalGroup;
use concrete_hybrid_kem::kdf::Kdf;
use concrete_hybrid_kem::kem::PqKem;
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

/// Generate encapsulation key from compound DK for X25519/X448 based KEMs
fn generate_ek_x<MLKEM>(
    mlkem_seed: &[u8],
    trad_sk: &[u8],
) -> Result<Vec<u8>, String>
where
    MLKEM: PqKem,
{
    // Generate ML-KEM encapsulation key from seed
    let (_, ek_pq, _) = MLKEM::derive_key_pair(mlkem_seed);

    // For X25519, the public key is just the scalar multiplied by the base point
    use concrete_hybrid_kem::group::X25519;
    let trad_pk = X25519::exp(&X25519::generator(), &trad_sk.to_vec());

    // Combine: EK_PQ || EK_trad
    let mut ek = ek_pq;
    ek.extend_from_slice(&trad_pk);

    Ok(ek)
}

/// Generate encapsulation key from compound DK for EC-based KEMs
fn generate_ek_ec<MLKEM, G>(
    mlkem_seed: &[u8],
    trad_sk_scalar: &[u8],
) -> Result<Vec<u8>, String>
where
    MLKEM: PqKem,
    G: NominalGroup,
{
    // Generate ML-KEM encapsulation key from seed
    let (_, ek_pq, _) = MLKEM::derive_key_pair(mlkem_seed);

    // Generate EC public key from scalar
    let trad_pk = G::exp(&G::generator(), &trad_sk_scalar.to_vec());

    // Combine: EK_PQ || EK_trad
    let mut ek = ek_pq;
    ek.extend_from_slice(&trad_pk);

    Ok(ek)
}

/// Compute C2-PRI combiner for verification
fn c2pri_combiner(
    ss_pq: &[u8],
    ss_t: &[u8],
    ct_t: &[u8],
    ek_t: &[u8],
    label: &[u8],
) -> Vec<u8> {
    use concrete_hybrid_kem::kdf::Sha3_256;
    Sha3_256::compute(
        ss_pq
            .iter()
            .chain(ss_t.iter())
            .chain(ct_t.iter())
            .chain(ek_t.iter())
            .chain(label.iter())
            .cloned(),
    )
}

/// Verify a test vector for X25519-based hybrid KEM
fn verify_test_vector_x<MLKEM>(
    tc_id: &str,
    ek_expected: &[u8],
    dk_bytes: &[u8],
    c: &[u8],
    k_expected: &[u8],
    label: &[u8],
    pq_ct_size: usize,
) -> Result<(), String>
where
    MLKEM: PqKem,
{
    println!("\nVerifying test vector: {}", tc_id);

    // Step 1: Parse the compound decapsulation key
    let compound_dk = parse_compound_dk(dk_bytes)?;
    println!("  ✓ Parsed compound DK");

    // Step 2: Parse traditional private key
    let trad_sk = parse_x_private_key(&compound_dk.trad_sk)?;
    println!("  ✓ Parsed traditional private key ({} bytes)", trad_sk.len());

    // Step 3: Generate encapsulation key and verify
    let ek_generated = generate_ek_x::<MLKEM>(&compound_dk.mlkem_seed, &trad_sk)?;
    if ek_generated != ek_expected {
        return Err(format!(
            "EK mismatch:\n  Generated: {}\n  Expected:  {}",
            hex::encode(&ek_generated),
            hex::encode(ek_expected)
        ));
    }
    println!("  ✓ Encapsulation key matches");

    // Step 4: Decapsulate and verify shared secret
    // Split ciphertext into PQ and traditional parts
    let ct_pq = &c[..pq_ct_size];
    let ct_t = &c[pq_ct_size..];

    // Decapsulate ML-KEM part
    let ss_pq = MLKEM::decaps(&compound_dk.mlkem_seed, &ct_pq.to_vec());

    // Decapsulate traditional part (DH)
    use concrete_hybrid_kem::group::X25519;
    let ss_t_elem = X25519::exp(&ct_t.to_vec(), &trad_sk);
    let ss_t = X25519::element_to_shared_secret(&ss_t_elem);

    // Get traditional EK from compound_dk
    let ek_t = &compound_dk.trad_pk;

    // Combine using C2-PRI combiner
    let ss_combined = c2pri_combiner(&ss_pq, &ss_t, ct_t, ek_t, label);

    if ss_combined != k_expected {
        return Err(format!(
            "Shared secret mismatch:\n  Generated: {}\n  Expected:  {}",
            hex::encode(&ss_combined),
            hex::encode(k_expected)
        ));
    }
    println!("  ✓ Shared secret matches");

    Ok(())
}

/// Verify a test vector for EC-based hybrid KEM
fn verify_test_vector_ec<MLKEM, G>(
    tc_id: &str,
    ek_expected: &[u8],
    dk_bytes: &[u8],
    c: &[u8],
    k_expected: &[u8],
    label: &[u8],
    pq_ct_size: usize,
) -> Result<(), String>
where
    MLKEM: PqKem,
    G: NominalGroup,
{
    println!("\nVerifying test vector: {}", tc_id);

    // Step 1: Parse the compound decapsulation key
    let compound_dk = parse_compound_dk(dk_bytes)?;
    println!("  ✓ Parsed compound DK");

    // Step 2: Parse traditional private key (EC DER format)
    let trad_sk_scalar = parse_ec_private_key(&compound_dk.trad_sk)?;
    println!("  ✓ Parsed traditional private key ({} bytes)", trad_sk_scalar.len());

    // Step 3: Generate encapsulation key and verify
    let ek_generated = generate_ek_ec::<MLKEM, G>(&compound_dk.mlkem_seed, &trad_sk_scalar)?;
    if ek_generated != ek_expected {
        return Err(format!(
            "EK mismatch:\n  Generated: {}\n  Expected:  {}",
            hex::encode(&ek_generated),
            hex::encode(ek_expected)
        ));
    }
    println!("  ✓ Encapsulation key matches");

    // Step 4: Decapsulate and verify shared secret
    // Split ciphertext into PQ and traditional parts
    let ct_pq = &c[..pq_ct_size];
    let ct_t = &c[pq_ct_size..];

    // Decapsulate ML-KEM part
    let ss_pq = MLKEM::decaps(&compound_dk.mlkem_seed, &ct_pq.to_vec());

    // Decapsulate traditional part (ECDH)
    let ss_t_elem = G::exp(&ct_t.to_vec(), &trad_sk_scalar);
    let ss_t = G::element_to_shared_secret(&ss_t_elem);

    // Get traditional EK from compound_dk
    let ek_t = &compound_dk.trad_pk;

    // Combine using C2-PRI combiner
    let ss_combined = c2pri_combiner(&ss_pq, &ss_t, ct_t, ek_t, label);

    if ss_combined != k_expected {
        return Err(format!(
            "Shared secret mismatch:\n  Generated: {}\n  Expected:  {}",
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

        match verify_test_vector_x::<concrete_hybrid_kem::kem::MlKem768>(
            &tv.tc_id,
            &ek,
            &dk,
            &c,
            &k,
            b"\x5C\x2E\x2F\x2F\x5E\x5C", // Label for MLKEM768-X25519
            1088,                         // ML-KEM768 ciphertext size
        ) {
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

        match verify_test_vector_ec::<
            concrete_hybrid_kem::kem::MlKem768,
            concrete_hybrid_kem::group::P256,
        >(
            &tv.tc_id,
            &ek,
            &dk,
            &c,
            &k,
            b"MLKEM768-P256", // Label for MLKEM768-P256
            1088,             // ML-KEM768 ciphertext size
        ) {
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

        match verify_test_vector_ec::<
            concrete_hybrid_kem::kem::MlKem1024,
            concrete_hybrid_kem::group::P384,
        >(
            &tv.tc_id,
            &ek,
            &dk,
            &c,
            &k,
            b"MLKEM1024-P384", // Label for MLKEM1024-P384
            1568,              // ML-KEM1024 ciphertext size
        ) {
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
