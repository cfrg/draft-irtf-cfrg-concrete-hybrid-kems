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
  XWING-SPEC: I-D.connolly-cfrg-xwing-kem
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

{{!HYBRID-KEMS=I-D.irtf-cfrg-hybrid-kems}} defines a general framework for creating hybrid
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

We make extensive use of the terminology in {{HYBRID-KEMS}}.

# Concrete Nominal Group and KEM Instances

This document introduces concrete hybrid KEM instances that in turn depend on
concrete KEM and nominal group instances. This section introduces the nominal
groups and KEM instances used for concrete hybrid KEM instances, specified in
line with the abstraction from {{HYBRID-KEMS}}. {{nominal-groups}} defines
the concrete nominal groups, and {{nominal-kems}} defines the nominal KEMs.

## Nominal Groups {#nominal-groups}

This section specifies concrete nominal groups that implement the abstraction
in {{HYBRID-KEMS}}. It includes groups based on the NIST curves P-256 and P-384 {{FIPS186}},
as well as a group based on Curve25519 from {{!RFC7748}}

### P-256 Nominal Group {#group-p256}

The following functions for the P-256 nominal group are defined:

- `Exp(p, x) -> q`: This function computes scalar multiplication between
  the input element (or point) `p` and the scalar `x` {{FIPS186}}.
- `RandomScalar(seed) -> k`: Implemented by converting `seed` to an integer using
  OS2IP, and then reducing the resulting integer modulo the group order.
- `ElementToSharedSecret(P) -> ss`: Implemented using the compressed
  Elliptic-Curve-Point-to-Octet-String method according to {{SEC1}} with input `P`,
  yielding a Nelem-byte output. Additionally, this function validates that the
  input element is not the group identity element. Finally, this function outputs the
  encoding the X coordinate of the elliptic curve point corresponding to P to a
  little-endian Nss-byte string.

The following constants are also defined.

- `Nseed`: 48
- `Nscalar`: 32
- `Nelem`: 33
- `Nss`: 32

### P-384 Nominal Group {#group-p384}

The following functions for the P-384 nominal group are defined:

- `Exp(p, x) -> q`: This function computes scalar multiplication between
  the input element (or point) `p` and the scalar `x` {{FIPS186}}.
- `RandomScalar(seed) -> k`: Implemented by converting `seed` to an integer using
  OS2IP, and then reducing the resulting integer modulo the group order.
- `ElementToSharedSecret(P) -> ss`: Implemented using the compressed
  Elliptic-Curve-Point-to-Octet-String method according to {{SEC1}} with input `P`,
  yielding a Nelem-byte output. Additionally, this function validates that the
  input element is not the group identity element. Finally, this function outputs the
  encoding the X coordinate of the elliptic curve point corresponding to P to a
  little-endian Nss-byte string.

The following constants are also defined.

- `Nseed`: 72
- `Nscalar`: 48
- `Nelem`: 48
- `Nss`: 32

### Curve25519 Nominal Group {#group-curve25519}

The following functions for the Curve25519 nominal group are defined:

- `Exp(p, x) -> q`: Implemented by X25519(x, p) from {{RFC7748}}.
- `RandomScalar(seed) -> k`: Implemented by sampling and outputting 32 random bytes
  from a cryptographically secure pseudorandom number generator.
- `ElementToSharedSecret(P) -> ss`: Implemented by the identity function, i.e., by outputting P.

The following constants are also defined.

- `Nseed`: 32
- `Nscalar`: 32
- `Nelem`: 32
- `Nss`: 32

## Concrete KEM Instances {#nominal-kems}

This section specifies concrete KEM instances that implement the KEM abstraction from
{{HYBRID-KEMS}}. It focuses solely on ML-KEM as specified in {{FIPS203}}.

### ML-KEM-768 {#mlkem-768}

The ML-KEM-768 nominal KEM implements the KEM abstraction from {{HYBRID-KEMS}} with
the following functions:

- `GenerateKeyPair() -> (ek, dk)`: Implemented as KeyGen in Section 7.1 of {{FIPS203}}.
- `DeriveKeyPair(seed) -> (ek, dk)`: Implemented as KeyGen_internal(seed[0:32], seed[32:64]),
  where KeyGen_internal is defined in Section 6 of {{FIPS203}}.
- `Encaps(ek) -> (ct, ss)`: Implemented as Encaps in Section 7.2 of {{FIPS203}}.
- `Decaps(dk, ct) -> ss`: Implemented as Encaps in Section 7.3 of {{FIPS203}}.
- `EncapsDerand(ek, randomness) -> (ct, shared_secret)`: [[TODO: citeme]

The following constants are also defined:

- `Nseed`: 64
- `Nek`: 1216
- `Ndk`: 32
- `Nct`: 1120
- `Nss`: 32

### ML-KEM-1024 {#mlkem-1024}

The ML-KEM-1024 nominal KEM implements the KEM abstraction from {{HYBRID-KEMS}} with
the following functions:

- `GenerateKeyPair() -> (ek, dk)`: Implemented as KeyGen in Section 7.1 of {{FIPS203}}.
- `DeriveKeyPair(seed) -> (ek, dk)`: Implemented as KeyGen_internal(seed[0:32], seed[32:64]),
  where KeyGen_internal is defined in Section 6 of {{FIPS203}}.
- `Encaps(ek) -> (ct, ss)`: Implemented as Encaps in Section 7.2 of {{FIPS203}}.
- `Decaps(dk, ct) -> ss`: Implemented as Encaps in Section 7.3 of {{FIPS203}}.
- `EncapsDerand(ek, randomness) -> (ct, shared_secret)`: [[TODO: citeme]

The following constants are also defined:

- `Nseed`: 64
- `Nek`: 1629
- `Ndk`: 32
- `Nct`: 1629
- `Nss`: 32

# Concrete Hybrid KEM Instances

This section instantiates three concrete KEMs:

<!-- TODO: update names to use Expand/Combine/whatever instead of XOF/KDF/old combiner names -->

1. `HNN3` {{qsf-p256}}:
   A hybrid KEM composing ML-KEM-768 and P-256 using the HashTraditionalOnly combiner with
   SHA3-256 as the Combine KDF and SHAKE256 as the Expand KDF.
1. `HNX` {{xwing}}:
   A hybrid KEM composing ML-KEM-768 and Curve25519 using the HashTraditionalOnly combiner with
   SHA3-256 as the Combine KDF and SHAKE256 as the Expand KDF. This variant is identical to X-Wing {{XWING-SPEC}}.
1. `HNN5` {{qsf-p384}}:
   A hybrid KEM composing ML-KEM-1024 and P-384 using the HashTraditionalOnly combiner with
   SHA3-256 as the Combine KDF and SHAKE256 as the Expand KDF.

Each instance specifies the PQ and traditional KEMs being combined, the
combiner construction from {{HYBRID-KEMS}}, the `label` to use for domain
separation in the combiner function, as well as the XOF and KDF functions to
use throughout.

## `HNN3` {#qsf-p256}

This hybrid KEM is heavily based on {{XWING}}, using the HashTraditionalOnly combiner
from {{HYBRID-KEMS}}. In particular, it has the same exact design but uses P-256
instead of X25519 as the the traditional component of the algorithm. It has the
following parameters.

* `Group_T`: P-256 {{group-p256}}
* `KEM_PQ`: ML-KEM-768 {{mlkem-768}}
* `Expand`: SHAKE-256 {{FIPS202}}
* `Combine`: SHA3-256 {{FIPS202}}
* `Label` - `HNN3`

The following constants for the hybrid KEM are also defined:

- `Nseed`: 32
- `Nek`: 1217
- `Ndk`: 32
- `Nct`: 1121
- `Nss`: 32

With these parameters in place, this hybrid KEM is defined as follows:

~~~
def GenerateKeyPair():
    seed = random(Nseed)
    return DeriveKeyPair(seed)

def DeriveKeyPair(seed):
    seed_full = Expand(seed)
    (seed_T, seed_PQ) = split(Group_T.Nseed, KEM_PQ.Nseed, seed)

    dk_T = Group_T.RandomScalar(seed_T)
    ek_T = Group_T.Exp(Group_T.g, dk_T)
    (ek_PQ, dk_PQ) = KEM_PQ.DeriveKeyPair(seed_PQ)

    ek_H = concat(ek_T, ek_PQ)
    dk_H = concat(dk_T, dk_PQ)
    return (ek_H, dk_H)

def Encaps(ek):
    (ek_T, ek_PQ) = split(Group_T.Nek, KEM_PQ.Nek, ek)

    sk_E = Group_T.RandomScalar(random(GroupT.nseed))
    ct_T = Group_T.Exp(GroupT.g, sk_E)
    ss_T = Group_T.ElementToSharedSecret(Group_T.Exp(ek_T, sk_E))
    (ss_PQ, ct_PQ) = KEM_PQ.Encap(ek_PQ)

    ss_H = Combine(concat(ss_PQ, ss_T, ct_T, ek_T, Label))
    ct_H = concat(ct_T, ct_PQ)
    return (ss_H, ct_H)

def Decaps(dk, ct):
    (dk_T, dk_PQ) = split(Group_T.Ndk, KEM_PQ.Ndk, dk)
    (ct_T, ct_PQ) = split(Group_T.Nct, KEM_PQ.Nct, ct)

    ek_T = Group_T.ToEncaps(dk_T)
    ek_PQ = KEM_PQ.ToEncaps(dk_PQ)

    ss_T = Group_T.ElementToSharedSecret(Group_T.Exp(ct_T, dk_T))
    ss_PQ = KEM_PQ.Decap(dk_PQ, ct_PQ)

    ss_H = Combine(concat(ss_PQ, ss_T, ct_T, ek_T, Label))
    return ss_H
~~~

## `HNX` {#xwing}

This hybrid KEM is identical to X-Wing {{XWING-SPEC}}. It has the following parameters.

* `Group_T`: Curve25519 {{group-curve25519}}
* `KEM_PQ`: ML-KEM-768 {{mlkem-768}}
* `Expand`: SHAKE-256 {{FIPS202}}
* `Combine`: SHA3-256 {{FIPS202}}
* `Label` - `HNX`

The following constants for the hybrid KEM are also defined:

- `Nseed`: 32
- `Nek`: 1216
- `Ndk`: 32
- `Nct`: 1120
- `Nss`: 32

With these parameters in place, this hybrid KEM is defined as follows:

~~~
def GenerateKeyPair():
    seed = random(Nseed)
    return DeriveKeyPair(seed)

def DeriveKeyPair(seed):
    seed_full = Expand(seed)
    (seed_T, seed_PQ) = split(Group_T.Nseed, KEM_PQ.Nseed, seed)

    dk_T = Group_T.RandomScalar(seed_T)
    ek_T = Group_T.Exp(Group_T.g, dk_T)
    (ek_PQ, dk_PQ) = KEM_PQ.DeriveKeyPair(seed_PQ)

    ek_H = concat(ek_T, ek_PQ)
    dk_H = concat(dk_T, dk_PQ)
    return (ek_H, dk_H)

def Encaps(ek):
    (ek_T, ek_PQ) = split(Group_T.Nek, KEM_PQ.Nek, ek)

    sk_E = Group_T.RandomScalar(random(GroupT.nseed))
    ct_T = Group_T.Exp(GroupT.g, sk_E)
    ss_T = Group_T.ElementToSharedSecret(Group_T.Exp(ek_T, sk_E))
    (ss_PQ, ct_PQ) = KEM_PQ.Encap(ek_PQ)

    ss_H = Combine(concat(ss_PQ, ss_T, ct_T, ek_T, Label))
    ct_H = concat(ct_T, ct_PQ)
    return (ss_H, ct_H)

def Decaps(dk, ct):
    (dk_T, dk_PQ) = split(Group_T.Ndk, KEM_PQ.Ndk, dk)
    (ct_T, ct_PQ) = split(Group_T.Nct, KEM_PQ.Nct, ct)

    ek_T = Group_T.ToEncaps(dk_T)
    ek_PQ = KEM_PQ.ToEncaps(dk_PQ)

    ss_T = Group_T.ElementToSharedSecret(Group_T.Exp(ct_T, dk_T))
    ss_PQ = KEM_PQ.Decap(dk_PQ, ct_PQ)

    ss_H = Combine(concat(ss_PQ, ss_T, ct_T, ek_T, Label))
    return ss_H
~~~

## `HNN5` {#qsf-p384}

`HNN5` has the following parameters.

* `Group_T`: P-384 {{group-p384}}
* `KEM_PQ`: ML-KEM-1024 {{mlkem-1024}}
* `Expand`: SHAKE-256 {{FIPS202}}
* `Combine`: HKDF-SHA-256 {{!RFC5869}}
* `Label` - `HNN3`

The following constants for the hybrid KEM are also defined:

- `Nseed`: 32
- `Nek`: 1629
- `Ndk`: 32
- `Nct`: 1629
- `Nss`: 32

With these parameters in place, this hybrid KEM is defined as follows:

~~~
def GenerateKeyPair():
    seed = random(Nseed)
    return DeriveKeyPair(seed)

def DeriveKeyPair(seed):
    seed_full = Expand(seed)
    (seed_T, seed_PQ) = split(Group_T.Nseed, KEM_PQ.Nseed, seed)

    dk_T = Group_T.RandomScalar(seed_T))
    ek_T = Group_T.Exp(Group_T.g, dk_T)
    (ek_PQ, dk_PQ) = KEM_PQ.DeriveKeyPair(seed_PQ)

    ek_H = concat(ek_T, ek_PQ)
    dk_H = concat(dk_T, dk_PQ)
    return (ek_H, dk_H)

def Encaps(ek):
    (ek_T, ek_PQ) = split(Group_T.Nek, KEM_PQ.Nek, ek)

    sk_E = Group_T.RandomScalar(random(GroupT.nseed))
    ct_T = Group_T.Exp(GroupT.g, sk_E)
    ss_T = Group_T.ElementToSharedSecret(Group_T.Exp(ek_T, sk_E))
    (ss_PQ, ct_PQ) = KEM_PQ.Encap(ek_PQ)

    ss_H = Combine(concat(ss_PQ, ss_T, ct_T, ek_T, Label))
    ct_H = concat(ct_T, ct_PQ)
    return (ss_H, ct_H)

def Decaps(dk, ct):
    (dk_T, dk_PQ) = split(Group_T.Ndk, KEM_PQ.Ndk, dk)
    (ct_T, ct_PQ) = split(Group_T.Nct, KEM_PQ.Nct, ct)

    ek_T = Group_T.ToEncaps(dk_T)
    ek_PQ = KEM_PQ.ToEncaps(dk_PQ)

    ss_T = Group_T.ElementToSharedSecret(Group_T.Exp(ct_T, dk_T))
    ss_PQ = KEM_PQ.Decap(dk_PQ, ct_PQ)

    ss_H = Combine(concat(ss_PQ, ss_T, ct_T, ek_T, Label))
    return ss_H
~~~

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

# Security Considerations

[[TODO: writeme]]

# IANA Considerations

This document has no IANA actions.


--- back

# Acknowledgments
{:numbered="false"}

[[TODO: writeme]]
