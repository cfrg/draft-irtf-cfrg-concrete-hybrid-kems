---
title: "Concrete Hybrid PQ/T Key Encapsulation Mechanisms"
abbrev: concrete-hybrid-kems
category: info

docname: draft-irtf-cfrg-concrete-hybrid-kems-latest
submissiontype: IRTF
number:
date:
consensus: true
v: 3
area: "IRTF"
workgroup: "Crypto Forum"
keyword:
 - post quantum
 - kem
 - PQ
 - hpke
 - hybrid encryption

venue:
  group: "Crypto Forum"
  type: "Research Group"
  mail: "cfrg@ietf.org"
  arch: "https://mailarchive.ietf.org/arch/search/?email_list=cfrg"
  github: "cfrg/draft-irtf-cfrg-concrete-hybrid-kems"
  latest: "https://cfrg.github.io/draft-irtf-cfrg-concrete-hybrid-kems/draft-irtf-cfrg-concrete-hybrid-kems.html"

author:
 -
    fullname: Deirdre Connolly
    organization: SandboxAQ
    email: durumcrustulum@gmail.com

normative:
  FIPS202: DOI.10.6028/NIST.FIPS.202
  FIPS203: DOI.10.6028/NIST.FIPS.203

informative:
  ANSIX9.62:
    title: "Public Key Cryptography for the Financial Services Industry: the Elliptic Curve Digital Signature Algorithm (ECDSA)"
    date: Nov, 2005
    seriesinfo:
      "ANS": X9.62-2005
    author:
      -
        org: ANS
  SCHMIEG2024:
    title: "Unbindable Kemmy Schmidt: ML-KEM is neither MAL-BIND-K-CT nor MAL-BIND-K-PK"
    target: https://eprint.iacr.org/2024/523.pdf
    date: 2024
    author:
      -
        ins: S. Schmieg
        name: Sophie Schmieg
  SEC1:
    title: "Elliptic Curve Cryptography, Standards for Efficient Cryptography Group, ver. 2"
    target: https://secg.org/sec1-v2.pdf
    date: 2009
  XWING:
    title: "X-Wing: The Hybrid KEM You’ve Been Looking For"
    target: https://eprint.iacr.org/2024/039.pdf
    date: 2024
  CDM23:
    title: "Keeping Up with the KEMs: Stronger Security Notions for KEMs and automated analysis of KEM-based protocols"
    target: https://eprint.iacr.org/2023/1933.pdf
    date: 2023
    author:
      -
        ins: C. Cremers
        name: Cas Cremers
        org: CISPA Helmholtz Center for Information Security
      -
        ins: A. Dax
        name: Alexander Dax
        org: CISPA Helmholtz Center for Information Security
      -
        ins: N. Medinger
        name: Niklas Medinger
        org: CISPA Helmholtz Center for Information Security
  FIPS186: DOI.10.6028/NIST.FIPS.186-5 #https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.186-5.pdf
  KSMW2024:
    target: https://eprint.iacr.org/2024/1233
    title: "Binding Security of Implicitly-Rejecting KEMs and Application to BIKE and HQC"
    author:
      -
        ins: J. Kraemer
      -
        ins: P. Struck
      -
        ins: M. Weishaupl



--- abstract

PQ/T Hybrid Key Encapsulation Mechanisms (KEMs) combine "post-quantum" cryptographic
algorithms, which are safe from attack by a quantum computer, with "traditional"
algorithms, which are not.  CFRG has developed a general framework for creating
hybrid KEMs.  In this document, we define concrete instantiations of this
framework to illustrate certain properties of the framework and simplify
implementors' choices.

--- middle

# Introduction

PQ/T Hybrid Key Encapsulation Mechanisms (KEMs) combine "post-quantum" cryptographic
algorithms, which are safe from attack by a quantum computer, with "traditional"
algorithms, which are not.  Such KEMs are secure against a quantum attacker as
long as the PQ algorithm is secure, and remain secure against traditional
attackers even if the PQ algorithm is not secure.

{{!I-D.irtf-cfrg-hybrid-kems}} defines a general framework for creating hybrid
KEMs. It includes multiple specific mechanisms for combining a PQ algorithm with
a traditional algorithm, with different performance properties and security
requirements for the underlying algorithms.

In this document, we describe instances of these different specific combiners,
with specific choices for the underlying algorithms.  The choices described here
illustrate the security analysis required to make choices that meet the
requirements of the general framework, and can serve as a baseline for
application designers.  We also provide test vectors for these instances so that
implementors can verify the correctness of their implementations.

# Conventions and Definitions

{::boilerplate bcp14-tagged}

We make extensive use of the terminology in {{I-D.irtf-cfrg-hybrid-kems}}.

# Concrete Hybrid KEM Instances

This section instantiates three concrete KEMs:

1. `QSF-KEM(ML-KEM-768,P-256)-XOF(SHAKE256)-KDF(SHA3-256)` {{qsf-p256}}:
   A hybrid KEM using the QSF combiner with SHA3-256 as the hash function
   based on ML-KEM-768 and P-256, along with SHAKE256 as the key derivation XOF.
2. `KitchenSink-KEM(ML-KEM-768,X25519)-XOF(SHAKE256)-KDF(HKDF-SHA-256)` {{ks-x25519}}:
   A hybrid KEM using the KitchenSink combiner based on ML-KEM-768 and X25519.
3. `QSF-KEM(ML-KEM-1024,P-384)-XOF(SHAKE256)-KDF(SHA3-256)` {{qsf-p384}}:
   A hybrid KEM using the QSF combiner with SHA3-256 as the hash function
   based on ML-KEM-1024 and P-384, along with SHAKE256 as the key derivation XOF.

Each instance specifies the PQ and traditional KEMs being combined, the
combiner construction from {{I-D.irtf-cfrg-hybrid-kems}}, the `label` to use for domain
separation in the combiner function, as well as the XOF and KDF functions to
use throughout.

## `QSF-KEM(ML-KEM-768,P-256)-XOF(SHAKE256)-KDF(SHA3-256)` {#qsf-p256}

This hybrid KEM is heavily based on {{XWING}}. In particular, it has the same
exact design but uses P-256 instead of X25519 as the the traditional
component of the algorithm. It has the following parameters.

* `label`: `QSF-KEM(ML-KEM-768,P-256)-XOF(SHAKE256)-KDF(SHA3-256)`
* `XOF`: SHAKE-256 {{FIPS202}}
* `KDF`: SHA3-256 {{FIPS202}}
* Combiner: QSF-KEM.SharedSecret
* Nseed: 32
* Npqseed: 64
* Ntradseed: 48
* Npk: 1217
* Nsk: 32
* Nct: 1121

`QSF-KEM(ML-KEM-768,P-256)-XOF(SHAKE256)-KDF(SHA3-256)` depends on P-256 as a nominal prime-order
group {{FIPS186}} (secp256r1) {{ANSIX9.62}}, where Ne = 33 and Ns = 32, with
the following functions:

- Order(): Return
  0xffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551.
- Identity(): As defined in {{ANSIX9.62}}.
- RandomScalar(): Implemented by returning a uniformly random Scalar in the
  range \[0, `G.Order()` - 1\]. Refer to {{random-scalar}} for
  implementation guidance.
- SerializeElement(A): Implemented using the compressed
  Elliptic-Curve-Point-to-Octet-String method according to {{SEC1}},
  yielding a 33-byte output. Additionally, this function validates that the
  input element is not the group identity element.
- DeserializeElement(buf): Implemented by attempting to deserialize a
  33-byte input string to a public key using the compressed
  Octet-String-to-Elliptic-Curve-Point method according to {{SEC1}}, and
  then performs public-key validation as defined in section 3.2.2.1 of
  {{SEC1}}.  This includes checking that the coordinates of the resulting
  point are in the correct range, that the point is on the curve, and that
  the point is not the point at infinity. (As noted in the specification,
  validation of the point order is not required since the cofactor is 1.)
  If any of these checks fail, deserialization returns an error.
- SerializeElementAsSharedSecret(A): Implemented by encoding the X coordinate
  of the elliptic curve point corresponding to A to a little-endian 32-byte string.
- SerializeScalar(s): Implemented using the Field-Element-to-Octet-String
  conversion according to {{SEC1}}.
- DeserializeScalar(buf): Implemented by attempting to deserialize a Scalar
  from a 32-byte string using Octet-String-to-Field-Element from
  {{SEC1}}. This function can fail if the input does not represent a Scalar
  in the range \[0, `G.Order()` - 1\].
- ScalarFromBytes(buf): Implemented by converting `buf` to an integer using
  OS2IP, and then reducing the resulting integer modulo the group order.

The rest of this section specifies the key generation, encapsulation, and
decapsulation procedures for this hybrid KEM.

### Key generation

`QSF-KEM(ML-KEM-768,P-256)-XOF(SHAKE256)-KDF(SHA3-256)` KeyGen works as follows.

<!-- TODO: is this expanding from a decaps key seed, but maybe this should
just be 'expandKeyPair` -->

<!-- TODO: annotate with the byte sizes of the parameters in terms of Nseed,
Nsk, etc -->

~~~
def expandDecapsulationKey(sk):
  expanded = SHAKE256(sk, 112)
  (pq_PK, pq_SK) = ML-KEM-768.KeyGen_internal(expanded[0:32], expanded[32:64])
  trad_SK = P-256.ScalarFromBytes(expanded[64:112])
  trad_PK = P-256.SerializeElement(P-256.ScalarMultBase(trad_SK))
  return (pq_SK, trad_SK, pq_PK, trad_PK)

def KeyGen():
  sk = random(32)
  (pq_SK, trad_SK, pq_PK, trad_PK) = expandDecapsulationKey(sk)
  return sk, concat(pq_PK, trad_PK)
~~~

Similarly, `QSF-KEM(ML-KEM-768,P-256)-XOF(SHAKE256)-KDF(SHA3-256)` DeriveKey works as follows:

~~~
def DeriveKey(seed):
  (pq_SK, trad_SK, pq_PK, trad_PK) = expandDecapsulationKey(seed)
  return sk, concat(pq_PK, trad_PK)
~~~

### Encapsulation

Given an encapsulation key `pk`, `QSF-KEM(ML-KEM-768,P-256)-XOF(SHAKE256)-KDF(SHA3-256)` Encaps
proceeds as follows.

~~~
def Encaps(pk):
  pq_PK = pk[0:1184]
  trad_PK = P-256.DeserializeElement(pk[1184:1217])
  (pq_SS, pq_CT) = ML-KEM-768.Encaps(pq_PK)
  ek = P-256.RandomScalar()
  trad_CT = P-256.SerializeElement(P-256.ScalarBaseMult(ek))
  trad_SS = P-256.SerializeElementAsSharedSecret(P-256.ScalarMult(trad_PK, ek))
  ss = SHA3-256(pq_SS, trad_SS, trad_CT, pk[1184:1217], label)
  ct = concat(pq_CT, trad_CT)
  return (ss, ct)
~~~

`pk` is a 1217-byte encapsulation key resulting from KeyGen().

Encaps() returns the 32-byte shared secret `ss` and the 1121-byte ciphertext
`ct`.

Note that `Encaps()` may raise an error if ML-KEM-768.Encaps fails, e.g., if
it does not pass the check of {{FIPS203}} §7.2.

### Derandomized

For testing, it is convenient to have a deterministic version of
encapsulation. In such cases, an implementation can provide the following
derandomized function.

~~~
def EncapsDerand(pk, randomness):
  pq_PK = pk[0:1184]
  trad_PK = P-256.DeserializeElement(pk[1184:1217])
  (pq_SS, pq_CT) = ML-KEM-768.EncapsDerand(pq_PK, randomness[0:32])
  ek = P-256.ScalarFromBytes(randomness[32:80])
  trad_CT = P-256.SerializeElement(P-256.ScalarMultBase(ek))
  trad_SS = P-256.SerializeElementAsSharedSecret(P-256.ScalarMult(ek, trad_PK))
  ss = SHA3-256(pq_SS, trad_SS, trad_CT, trad_PK, label)
  ct = concat(pq_CT, trad_CT)
  return (ss, ct)
~~~

Note that `randomness` MUST be 80 bytes.

### Decapsulation

Given a decapsulation key `sk` and ciphertext `ct`,
`QSF-KEM(ML-KEM-768,P-256)-XOF(SHAKE256)-KDF(SHA3-256)` Decaps proceeds as follows.

~~~
def Decaps(sk, ct):
  (pq_SK, trad_SK, pq_PK, trad_PK) = expandDecapsulationKey(sk)
  pq_CT = ct[0:1088]
  trad_CT = P-256.DeserializeElement(ct[1088:1121])
  pq_SS = ML-KEM-768.Decapsulate(pq_SK, pq_CT)
  trad_SS = P-256.SerializeElementAsSharedSecret(P-256.ScalarMult(trad_SK, trad_CT))
  return SHA3-256(pq_SS, trad_SS, ct[1088:1121], trad_PK, label)
~~~

`ct` is the 1121-byte ciphertext resulting from Encaps() and `sk` is a
32-byte decapsulation key resulting from KeyGen().

Decaps() returns the 32 byte shared secret.

### Security properties

The inlined DH-KEM is instantiated over the elliptic curve group P-256: as
shown in {{CDM23}}, this gives the traditional KEM maximum binding
properties (MAL-BIND-K-CT, MAL-BIND-K-PK).

ML-KEM-768 as standardized in {{FIPS203}}, when using the 64-byte seed key
format as is here, provides MAL-BIND-K-CT security and LEAK-BIND-K-PK
security, as demonstrated in {{SCHMIEG2024}}.

Therefore this concrete instance provides MAL-BIND-K-PK and MAL-BIND-K-CT
security. <!-- TODO: update XWING paper to show this -->

This implies via {{KSMW2024}} that this instance also satisfies

- MAL-BIND-K,CT-PK
- MAL-BIND-K,PK-CT
- LEAK-BIND-K-PK
- LEAK-BIND-K-CT
- LEAK-BIND-K,CT-PK
- LEAK-BIND-K,PK-CT
- HON-BIND-K-PK
- HON-BIND-K-CT
- HON-BIND-K,CT-PK
- HON-BIND-K,PK-CT

## `KitchenSink-KEM(ML-KEM-768,X25519)-XOF(SHAKE256)-KDF(HKDF-SHA-256)` {#ks-x25519}

KitchenSink-KEM(ML-KEM-768,X25519)-XOF(SHAKE256)-KDF(HKDF-SHA-256) has the following parameters.

* `label`: `KitchenSink-KEM(ML-KEM-768,X25519)-XOF(SHAKE256)-KDF(HKDF-SHA-256)`
* `XOF`: SHAKE-256 {{FIPS202}}
* `KDF`: HKDF-SHA-256 {{!RFC5869}}
* Combiner: KitchenSink-KEM.SharedSecret
* Nseed: 32
* Npqseed: 64
* Ntradseed: 32
* Npk: 1216
* Nsk: 32
* Nct: 1120

`KitchenSink-KEM(ML-KEM-768,X25519)-XOF(SHAKE256)-KDF(HKDF-SHA-256)` depends on a prime-order group
implemented using Curve25519 and X25519 {{!RFC7748}}. Additionally, it uses a
modified version of HKDF in the combiner, denoted LabeledHKDF, defined below.

<!-- TODO: double check on whether the public context should go in `*_info`
or if all concatted is fine; i think a separate label is ok? HKDF as a split
PRF seems extra?-->

~~~
def LabeledExtract(salt, label, ikm):
  labeled_ikm = concat(label, ikm)
  return HDKF-Extract(salt, labeled_ikm)

def LabeledExpand(prk, label, info, L):
  labeled_info = concat(I2OSP(L, 2), label, info)
  return HKDF-Expand(prk, labeled_info, L)

def LabeledHKDF(preimage):
  prk = LabeledExtract("", "hybrid_prk", preimage)
  shared_secret = LabeledExpand(prk, "shared_secret", "", 32)
  return shared_secret
~~~

The rest of this section specifies the key generation, encapsulation, and
decapsulation procedures for this hybrid KEM.

### Key generation

`KitchenSink-KEM(ML-KEM-768,X25519)-XOF(SHAKE256)-KDF(HKDF-SHA-256)` KeyGen works as follows.

~~~
def expandDecapsulationKey(sk):
  expanded = SHAKE256(sk, 96)
  (pq_PK, pq_SK) = ML-KEM-768.KeyGen_internal(expanded[0:32], expanded[32:64])
  trad_SK = expanded[64:96]
  trad_PK = X25519(trad_SK, 9)
  return (pq_SK, trad_SK, pq_PK, trad_PK)

def KeyGen():
  sk = random(32)
  (pq_SK, trad_SK, pq_PK, trad_PK) = expandDecapsulationKey(sk)
  return sk, concat(pq_PK, trad_PK)
~~~

Similarly, `KitchenSink-KEM(ML-KEM-768,X25519)-XOF(SHAKE256)-KDF(HKDF-SHA-256)` DeriveKey works as
follows:

~~~
def DeriveKey(seed):
  (pq_SK, trad_SK, pq_PK, trad_PK) = expandDecapsulationKey(seed)
  return sk, concat(pq_PK, trad_PK)
~~~

### Encapsulation

Given an encapsulation key `pk`, `KitchenSink-KEM(ML-KEM-768,X25519)-XOF(SHAKE256)-KDF(HKDF-SHA-256)`
Encaps proceeds as follows.

~~~
def Encaps(pk):
  pq_PK = pk[0:1184]
  trad_PK = pk[1184:1216]
  (pq_SS, pq_CT) = ML-KEM-768.Encaps(pq_PK)
  ek = random(32)
  trad_CT = X25519(ek, 9)
  trad_SS = X25519(ek, trad_PK)
  ss = LabeledHKDF(pq_SS, trad_SS, pq_CT, pq_PK, trad_CT, trad_PK, label)
  ct = concat(pq_CT, trad_CT)
  return (ss, ct)
~~~

`pk` is a 1216-byte encapsulation key resulting from KeyGen().

Encaps() returns the 32-byte shared secret ss and the 1120-byte ciphertext
ct.

Note that `Encaps()` may raise an error if ML-KEM-768.Encaps fails, e.g., if
it does not pass the check of {{FIPS203}} §7.2.

### Derandomized

For testing, it is convenient to have a deterministic version of
encapsulation. In such cases, an implementation can provide the following
derandomized function.

~~~
def EncapsDerand(pk, randomness):
  pq_PK = pk[0:1184]
  trad_PK = pk[1184:1216]
  (pq_SS, pq_CT) = PQ-KEM.EncapsDerand(pq_PK, randomness[0:32])
  ek = randomness[32:64]
  trad_CT = X25519(ek, 9)
  trad_SS = X25519(ek, trad_PK)
  ss = LabeledHKDF(pq_SS, trad_SS, pq_CT, pq_PK, trad_CT, trad_PK, label)
  ct = concat(pq_CT, trad_CT)
  return (ss, ct)
~~~

Note that `randomness` MUST be 64 bytes.

### Decapsulation

Given a decapsulation key `sk` and ciphertext `ct`,
`KitchenSink-KEM(ML-KEM-768,X25519)-XOF(SHAKE256)-KDF(HKDF-SHA-256)` Decaps proceeds as follows.

~~~
def Decaps(sk, ct):
  (pq_SK, trad_SK, pq_PK, trad_PK) = expandDecapsulationKey(sk)
  pq_CT = ct[0:1088]
  trad_CT = ct[1088:1120]
  pq_SS = ML-KEM-768.Decapsulate(pq_SK, pq_CT)
  trad_SS = X25519(trad_SK, trad_CT)
  return LabeledHKDF(pq_SS, trad_SS, pq_CT, pq_PK, trad_CT, trad_PK, label)
~~~

`ct` is the 1120-byte ciphertext resulting from Encaps() and `sk` is a
32-byte decapsulation key resulting from KeyGen().

Decaps() returns the 32 byte shared secret.

### Security properties

The inlined DH-KEM instantiated over the elliptic curve group X25519: as
shown in {{CDM23}}, this gives the traditional KEM maximum binding
properties (MAL-BIND-K-CT, MAL-BIND-K-PK).

ML-KEM-768 as standardized in {{FIPS203}}, when using the 64-byte seed key
format as is here, provides MAL-BIND-K-CT security and LEAK-BIND-K-PK
security, as demonstrated in {{SCHMIEG2024}}. Further, the ML-KEM ciphertext
and encapsulation key are included in the KDF preimage, giving
straightforward CT and PK binding for the entire bytes of the hybrid KEM
ciphertext and encapsulation key. Therefore this concrete instance provides
MAL-BIND-K-PK and MAL-BIND-K-CT security.

This implies via {{KSMW2024}} that this instance also satisfies

- MAL-BIND-K,CT-PK
- MAL-BIND-K,PK-CT
- LEAK-BIND-K-PK
- LEAK-BIND-K-CT
- LEAK-BIND-K,CT-PK
- LEAK-BIND-K,PK-CT
- HON-BIND-K-PK
- HON-BIND-K-CT
- HON-BIND-K,CT-PK
- HON-BIND-K,PK-CT

## `QSF-KEM(ML-KEM-1024,P-384)-XOF(SHAKE256)-KDF(SHA3-256)` {#qsf-p384}

<!-- TODO: include the XOF in the name?? -->

`QSF-KEM(ML-KEM-1024,P-384)-XOF(SHAKE256)-KDF(SHA3-256)` has the following parameters.

* `label`: `QSF-KEM(ML-KEM-768,P-256)-XOF(SHAKE256)-KDF(SHA3-256)`
* `XOF`: SHAKE-256 {{FIPS202}}
* `KDF`: SHA3-256 {{FIPS202}}
* Combiner: QSF-KEM.SharedSecret
* Nseed: 32
* Npqseed: 64
* Ntradseed: 72
* Npk: 1629
* Nsk: 32
* Nct: 1629

`QSF-KEM(ML-KEM-1024,P-384)-XOF(SHAKE256)-KDF(SHA3-256)` depends on P-384 as a nominal prime-order
group {{FIPS186}} (secp256r1) {{ANSIX9.62}}, where Ne = 61 and Ns = 48, with
the following functions:

- Order(): Return
  0xffffffffffffffffffffffffffffffffffffffffffffffffc7634d81f4372ddf
  581a0db248b0a77aecec196accc52973
- Identity(): As defined in {{ANSIX9.62}}.
- RandomScalar(): Implemented by returning a uniformly random Scalar in the
  range \[0, `G.Order()` - 1\]. Refer to {{random-scalar}} for
  implementation guidance.
- SerializeElement(A): Implemented using the compressed
  Elliptic-Curve-Point-to-Octet-String method according to {{SEC1}}, yielding
  a 61-byte output. Additionally, this function validates that the input
  element is not the group identity element.
- DeserializeElement(buf): Implemented by attempting to deserialize a 61-byte
  input string to a public key using the compressed
  Octet-String-to-Elliptic-Curve-Point method according to {{SEC1}}, and then
  performs public-key validation as defined in section 3.2.2.1 of {{SEC1}}.
  This includes checking that the coordinates of the resulting point are in
  the correct range, that the point is on the curve, and that the point is
  not the point at infinity. (As noted in the specification, validation of
  the point order is not required since the cofactor is 1.)  If any of these
  checks fail, deserialization returns an error.
- SerializeElementAsSharedSecret(A): Implemented by encoding the X coordinate
  of the elliptic curve point corresponding to A to a little-endian 48-byte
  string.
- SerializeScalar(s): Implemented using the Field-Element-to-Octet-String
  conversion according to {{SEC1}}.
- DeserializeScalar(buf): Implemented by attempting to deserialize a Scalar
  from a 48-byte string using Octet-String-to-Field-Element from
  {{SEC1}}. This function can fail if the input does not represent a Scalar
  in the range \[0, `G.Order()` - 1\].
- ScalarFromBytes(buf): Implemented by converting `buf` to an integer using
  OS2IP, and then reducing the resulting integer modulo the group order.

The rest of this section specifies the key generation, encapsulation, and
decapsulation procedures for this hybrid KEM.

### Key generation

`QSF-KEM(ML-KEM-1024,P-384)-XOF(SHAKE256)-KDF(SHA3-256)` KeyGen works as follows.

~~~
def expandDecapsulationKey(sk):
  expanded = SHAKE256(sk, 136)
  (pq_PK, pq_SK) = ML-KEM-1024.KeyGen_internal(expanded[0:32], expanded[32:64])
  trad_SK = P-384.ScalarFromBytes(expanded[64:136])
  trad_PK = P-384.SerializeElement(P-384.ScalarMultBase(trad_SK))
  return (pq_SK, trad_SK, pq_PK, trad_PK)

def KeyGen():
  sk = random(32)
  (pq_SK, trad_SK, pq_PK, trad_PK) = expandDecapsulationKey(sk)
  return sk, concat(pq_PK, trad_PK)
~~~

Similarly, `QSF-KEM(ML-KEM-1024,P-384)-XOF(SHAKE256)-KDF(SHA3-256)` DeriveKey works as follows:

~~~
def DeriveKey(seed):
  (pq_SK, trad_SK, pq_PK, trad_PK) = expandDecapsulationKey(seed)
  return sk, concat(pq_PK, trad_PK)
~~~

### Encapsulation

Given an encapsulation key `pk`, `QSF-KEM(ML-KEM-1024,P-384)-XOF(SHAKE256)-KDF(SHA3-256)` Encaps
proceeds as follows.

~~~
def Encaps(pk):
  pq_PK = pk[0:1568]
  trad_PK = P-384.DeserializeElement(pk[1568:1629])
  (pq_SS, pq_CT) = ML-KEM-1024.Encaps(pq_PK)
  ek = P-384.RandomScalar()
  trad_CT = P-384.SerializeElement(P-384.ScalarBaseMult(ek))
  trad_SS = P-384.SerializeElementAsSharedSecret(P-384.ScalarMult(trad_PK, ek))
  ss = SHA3-256(pq_SS, trad_SS, trad_CT, pk[1568:1629], label)
  ct = concat(pq_CT, trad_CT)
  return (ss, ct)
~~~

`pk` is a 1629-byte encapsulation key resulting from KeyGen().

Encaps() returns the 32-byte shared secret `ss` and the 1629-byte ciphertext
`ct`.

Note that `Encaps()` may raise an error if ML-KEM-1024.Encaps fails, e.g., if
it does not pass the check of {{FIPS203}} §7.2.

### Derandomized

For testing, it is convenient to have a deterministic version of
encapsulation. In such cases, an implementation can provide the following
derandomized function.

~~~
def EncapsDerand(pk, randomness):
  pq_PK = pk[0:1568]
  trad_PK = P-384.DeserializeElement(pk[1568:1629])
  (pq_SS, pq_CT) = ML-KEM-1024.EncapsDerand(pq_PK, randomness[0:32])
  ek = P-384.ScalarFromBytes(randomness[32:80])
  trad_CT = P-384.SerializeElement(P-384.ScalarMultBase(ek))
  trad_SS = P-384.SerializeElementAsSharedSecret(P-384.ScalarMult(ek, trad_PK))
  ss = SHA3-256(pq_SS, trad_SS, trad_CT, pk[1568:1629], label)
  ct = concat(pq_CT, trad_CT)
  return (ss, ct)
~~~

Note that `randomness` MUST be 80 bytes.

### Decapsulation

Given a decapsulation key `sk` and ciphertext `ct`,
`QSF-KEM(ML-KEM-1024,P-384)-XOF(SHAKE256)-KDF(SHA3-256)` Decaps proceeds as follows.

~~~
def Decaps(sk, ct):
  (pq_SK, trad_SK, pq_PK, trad_PK) = expandDecapsulationKey(sk)
  pq_CT = ct[0:1568]
  trad_CT = P-384.DeserializeElement(ct[1568:1629])
  pq_SS = ML-KEM-1024.Decapsulate(pq_SK, pq_CT)
  trad_SS = P-384.SerializeElementAsSharedSecret(P-384.ScalarMult(trad_SK, trad_CT))
  return SHA3-256(pq_SS, trad_SS, ct[1568:1629], trad_PK, label)
~~~

`ct` is the 1629-byte ciphertext resulting from Encaps() and `sk` is a
32-byte decapsulation key resulting from KeyGen().

Decaps() returns the 32-byte shared secret.

### Security properties

The inlined DH-KEM is instantiated over the elliptic curve group P-384: as
shown in {{CDM23}}, this gives the traditional KEM maximum binding
properties (MAL-BIND-K-CT, MAL-BIND-K-PK).

ML-KEM-1024 as standardized in {{FIPS203}}, when using the 64-byte seed key
format as is here, provides MAL-BIND-K-CT security and LEAK-BIND-K-PK
security, as demonstrated in {{SCHMIEG2024}}.

Therefore this concrete instance provides MAL-BIND-K-PK and MAL-BIND-K-CT
security. <!-- TODO: update XWING paper to show this -->

This implies via {{KSMW2024}} that this instance also satisfies

- MAL-BIND-K,CT-PK
- MAL-BIND-K,PK-CT
- LEAK-BIND-K-PK
- LEAK-BIND-K-CT
- LEAK-BIND-K,CT-PK
- LEAK-BIND-K,PK-CT
- HON-BIND-K-PK
- HON-BIND-K-CT
- HON-BIND-K,CT-PK
- HON-BIND-K,PK-CT

# Random Scalar Generation {#random-scalar}

Two popular algorithms for generating a random integer uniformly distributed in
the range \[0, G.Order() -1\] are as follows:

## Rejection Sampling

Generate a random byte array with `Ns` bytes, and attempt to map to a Scalar
by calling `DeserializeScalar` in constant time. If it succeeds, return the
result. If it fails, try again with another random byte array, until the
procedure succeeds. Failure to implement `DeserializeScalar` in constant time
can leak information about the underlying corresponding Scalar.

As an optimization, if the group order is very close to a power of
2, it is acceptable to omit the rejection test completely.  In
particular, if the group order is p, and there is an integer b
such that |p - 2<sup>b</sup>| is less than 2<sup>(b/2)</sup>, then
`RandomScalar` can simply return a uniformly random integer of at
most b bits.

## Wide Reduction

Generate a random byte array with `l = ceil(((3 * ceil(log2(G.Order()))) / 2)
/ 8)` bytes, and interpret it as an integer; reduce the integer modulo
`G.Order()` and return the result. See {{Section 5 of !HASH-TO-CURVE=RFC9380}}
for the underlying derivation of `l`.

# Security Considerations

TODO Security


# IANA Considerations

This document has no IANA actions.


--- back

# Test Vectors

This section describes test vectors for each of the concrete KEMs specified
in this document.

## QSF-KEM(ML-KEM-768,P-256)-XOF(SHAKE256)-KDF(SHA3-256) Test Vectors

~~~~
{::include ./spec/test-vectors-QSF-KEM(ML-KEM-768,P-256)-XOF(SHAKE256)-KDF(SHA3-256).txt}
~~~~

## KitchenSink-KEM(ML-KEM-768,X25519)-XOF(SHAKE256)-KDF(HKDF-SHA-256) Test Vectors

~~~~
{::include ./spec/test-vectors-KitchenSink-KEM(ML-KEM-768,X25519)-XOF(SHAKE256)-KDF(HKDF-SHA-256).txt}
~~~~

## QSF-KEM(ML-KEM-1024,P-384)-XOF(SHAKE256)-KDF(SHA3-256) Test Vectors

~~~~
{::include ./spec/test-vectors-QSF-KEM(ML-KEM-1024,P-384)-XOF(SHAKE256)-KDF(SHA3-256).txt}
~~~~

# Acknowledgments
{:numbered="false"}

TODO acknowledge.
