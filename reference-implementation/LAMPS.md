# LAMPS Composite KEM Test Vector Verification

This document describes the verification of LAMPS composite KEM test vectors using the hybrid KEM reference implementation.

## Overview

The `verify_composite_vectors` binary verifies that the hybrid KEM reference implementation from draft-irtf-cfrg-concrete-hybrid-kems is compatible with the composite KEM test vectors from draft-ietf-lamps-pq-composite-kem.

## Test Vectors

The test vectors are sourced from:
- Repository: https://github.com/lamps-wg/draft-composite-kem
- File: `src/testvectors.json`
- Specification: [draft-ietf-lamps-pq-composite-kem-09](https://datatracker.ietf.org/doc/html/draft-ietf-lamps-pq-composite-kem-09)

### Verified Algorithms

The following three composite KEM algorithms are verified:

1. **id-MLKEM768-X25519-SHA3-256**
   - Post-quantum component: ML-KEM-768
   - Traditional component: X25519
   - Combiner: C2-PRI with SHA3-256
   - Label: `\x5C\x2E\x2F\x2F\x5E\x5C`

2. **id-MLKEM768-ECDH-P256-SHA3-256**
   - Post-quantum component: ML-KEM-768
   - Traditional component: ECDH with P-256
   - Combiner: C2-PRI with SHA3-256
   - Label: `MLKEM768-P256`

3. **id-MLKEM1024-ECDH-P384-SHA3-256**
   - Post-quantum component: ML-KEM-1024
   - Traditional component: ECDH with P-384
   - Combiner: C2-PRI with SHA3-256
   - Label: `MLKEM1024-P384`

## How to Run

### Download Test Vectors

```bash
curl -o testvectors.json https://raw.githubusercontent.com/lamps-wg/draft-composite-kem/main/src/testvectors.json
```

### Run Verification

```bash
cargo run --bin verify_composite_vectors testvectors.json
```

### Expected Output

```
Successfully parsed 14 test vectors

Verifying test vector: id-MLKEM768-X25519-SHA3-256
  ✓ Parsed compound DK
  ✓ Parsed traditional private key (32 bytes)
  ✓ Encapsulation key matches
  ✓ Shared secret matches
  ✅ PASSED

Verifying test vector: id-MLKEM768-ECDH-P256-SHA3-256
  ✓ Parsed compound DK
  ✓ Parsed traditional private key (32 bytes)
  ✓ Encapsulation key matches
  ✓ Shared secret matches
  ✅ PASSED

Verifying test vector: id-MLKEM1024-ECDH-P384-SHA3-256
  ✓ Parsed compound DK
  ✓ Parsed traditional private key (48 bytes)
  ✓ Encapsulation key matches
  ✓ Shared secret matches
  ✅ PASSED

✅ All test vectors passed!
```

## What Gets Verified

For each test vector, the verification binary performs the following checks:

### 1. Compound Decapsulation Key Parsing

The decapsulation key (`dk` field) is parsed according to the format specified in Section 5.2 of draft-ietf-lamps-pq-composite-kem-09:

```
mlkemSeed (64 bytes) || lenTradPK (2 bytes, little-endian) || tradPK || tradSK
```

Components extracted:
- **ML-KEM seed** (64 bytes): Used to derive the ML-KEM key pair
- **Traditional public key** (variable): The public key of the traditional component
- **Traditional private key** (variable): The private key of the traditional component

### 2. Traditional Private Key Parsing

Depending on the algorithm:

- **X25519/X448**: Private key is the raw 32/57 byte scalar value
- **ECDH (P-256/P-384)**: Private key is parsed from ECPrivateKey DER structure per RFC 5915:
  ```
  ECPrivateKey ::= SEQUENCE {
    version INTEGER { ecPrivkeyVer1(1) },
    privateKey OCTET STRING,
    ...
  }
  ```

### 3. Encapsulation Key Generation

The encapsulation key is regenerated from the compound decapsulation key:

1. Derive ML-KEM encapsulation key from the 64-byte seed
2. Compute traditional public key:
   - For X25519: `pk = scalar * basepoint`
   - For ECDH: `pk = scalar * G` (where G is the curve generator)
3. Concatenate: `EK = EK_MLKEM || EK_trad`

**Verification**: The generated EK must match the `ek` field in the test vector.

### 4. Decapsulation and Shared Secret Verification

The ciphertext is decapsulated to produce a shared secret:

1. Split ciphertext into ML-KEM and traditional components
2. Decapsulate ML-KEM component: `ss_pq = MLKEM.Decaps(dk_pq, ct_pq)`
3. Decapsulate traditional component:
   - For X25519: `ss_t = X25519(sk_t, ct_t)`
   - For ECDH: `ss_t = x-coordinate of (sk_t * ct_t)`
4. Combine using C2-PRI combiner:
   ```
   K = SHA3-256(ss_pq || ss_t || ct_t || ek_t || label)
   ```

**Verification**: The computed shared secret must match the `k` field in the test vector.

## Implementation Details

### File Structure

- **Binary**: `src/bin/verify_composite_vectors.rs`
- **Dependencies added**: `base64 = "0.22"`

### Architecture

The verification leverages the hybrid KEM implementation in `hybrid.rs` by calling the hybrid KEM's methods directly:

1. **Extended GC hybrid KEM** with compound DK support:
   - `GC::decaps_compound()` - Decapsulates using LAMPS compound DK format
   - `GC::encapsulation_key_from_compound()` - Generates EK from compound DK
   - `decaps_with_keys_group()` - **Common decapsulation logic** shared by both `decaps()` and `decaps_compound()`

2. **Type-safe verification** using `CompoundDKVerifier` trait:
   - Links each test vector to its corresponding hybrid KEM type
   - Provides algorithm-specific parameters (PqKem, Group, Prg, Kdf, Constants)
   - Handles traditional key parsing (X25519 raw vs ECDH DER format)

**Key design principle**: The core decapsulation logic exists in one place (`decaps_with_keys_group()`), ensuring:
- **Correctness**: Uses the actual hybrid KEM implementation, not a reimplementation
- **No code duplication**: Both seed-based and compound DK formats use the same decapsulation logic
- **Type safety**: Compiler-enforced linkage between test vectors and hybrid KEM types
- **Extensibility**: Easy to add new hybrid KEM algorithms or key formats

### Key Components

#### Trait: `CompoundDKVerifier`

Provides algorithm-specific information for verifying compound DK test vectors:

```rust
trait CompoundDKVerifier {
    type HybridKem: HybridKem + SeedSize + SharedSecretSize;
    type Group: NominalGroup;
    type PqKem: concrete_hybrid_kem::kem::PqKem;

    fn label() -> &'static [u8];
    fn parse_trad_sk(sk_bytes: &[u8]) -> Result<Vec<u8>, String>;
}
```

#### Verifier Implementations

- `MlKem768X25519Verifier`: For id-MLKEM768-X25519-SHA3-256
- `MlKem768P256Verifier`: For id-MLKEM768-ECDH-P256-SHA3-256
- `MlKem1024P384Verifier`: For id-MLKEM1024-ECDH-P384-SHA3-256

#### Key Functions

**In `hybrid.rs` (library code)**:
- `decaps_with_keys_group()`: Common decapsulation logic (used by both formats)
- `GC::decaps()`: Decapsulates using seed-based DK (calls `decaps_with_keys_group`)
- `GC::decaps_compound()`: Decapsulates using LAMPS compound DK (calls `decaps_with_keys_group`)
- `GC::encapsulation_key_from_compound()`: Reconstructs EK from compound DK

**In `verify_composite_vectors.rs` (test binary)**:
- `parse_compound_dk()`: Parses the compound decapsulation key format
- `parse_ec_private_key()`: Parses ECPrivateKey DER structure
- `parse_x_private_key()`: Parses X25519/X448 raw private keys
- `verify_test_vector<V>()`: Generic verification function that calls hybrid KEM methods

### Combiner Algorithm

The C2-PRI (Concatenate-then-PRF with Implicit rejection) combiner is implemented as:

```rust
K = SHA3-256(ss_pq || ss_t || ct_t || ek_t || label)
```

Where:
- `ss_pq`: ML-KEM shared secret
- `ss_t`: Traditional shared secret
- `ct_t`: Traditional ciphertext component
- `ek_t`: Traditional public key
- `label`: Algorithm-specific label

This differs from the universal combiner (GU) which also includes `ct_pq` and `ek_pq`.

## Mapping Between Specifications

The reference implementation uses the "GC" (Group-Combiner) construction which corresponds to the C2-PRI combiner used in the LAMPS specification:

| LAMPS Term | Reference Implementation | Description |
|------------|-------------------------|-------------|
| ML-KEM seed | `dk_pq` | 64-byte seed for ML-KEM key derivation |
| Traditional SK | `dk_t` | Traditional component private key |
| Traditional PK | `ek_t` | Traditional component public key |
| C2-PRI combiner | `c2pri_combiner` in hybrid.rs | SHA3-256 combiner |

## Test Vector Format

Each test vector in the JSON file contains:

- `tcId`: Test case identifier (e.g., "id-MLKEM768-X25519-SHA3-256")
- `ek`: Encapsulation key (base64-encoded)
- `dk`: Decapsulation key (base64-encoded, in compound format)
- `c`: Ciphertext (base64-encoded)
- `k`: Shared secret (base64-encoded)
- `dk_pkcs8`: PKCS#8 format (not used in verification)
- `x5c`: Certificate chain (not used in verification)

## Compatibility

This verification demonstrates that:

1. The hybrid KEM reference implementation correctly implements the key encapsulation mechanisms described in draft-irtf-cfrg-concrete-hybrid-kems
2. The implementation is compatible with the composite KEM format from draft-ietf-lamps-pq-composite-kem
3. The C2-PRI combiner implementation matches the LAMPS specification
4. Key derivation, encapsulation, and decapsulation operations produce results consistent with the LAMPS test vectors

## References

- [draft-irtf-cfrg-concrete-hybrid-kems](https://datatracker.ietf.org/doc/draft-irtf-cfrg-concrete-hybrid-kems/)
- [draft-ietf-lamps-pq-composite-kem-09](https://datatracker.ietf.org/doc/html/draft-ietf-lamps-pq-composite-kem-09)
- [LAMPS Test Vectors](https://github.com/lamps-wg/draft-composite-kem/blob/main/src/testvectors.json)
- [ML-KEM (FIPS 203)](https://csrc.nist.gov/pubs/fips/203/final)
