---
title: Usage of SPAKE with TLS 1.3
abbrev: TLS 1.3 SPAKE
docname: draft-barnes-tls-pake-latest
category: info

ipr: trust200902
area: Security
keyword: Internet-Draft

stand_alone: yes
pi: [toc, sortrefs, symrefs]

author:
 -  ins: R. Barnes
    name: Richard Barnes
    organization: Cisco
    email: rlb@ipv.sx
 -
    ins: O. Friel
    name: Owen Friel
    organization: Cisco
    email: ofriel@cisco.com


--- abstract

The pre-shared key mechanism available in TLS 1.3 is not suitable
for usage with low-entropy keys, such as passwords entered by users.
This document describes how the SPAKE2+ password-authenticated key
exchange can be used with TLS 1.3.


--- middle


# Introduction

DISCLAIMER: This is a work-in-progress draft and has not yet
seen significant security analysis. It should not be used as a basis
for building production systems.

In some applications, it is desireable to enable a client and server
to authenticate to one another using a low-entropy pre-shared value,
such as a user-entered password.

In prior versions of TLS, this functionality has been provided by
the integration of the Secure Remote Password PAKE protocol (SRP)
{{?RFC5054}}.  The specific SRP integration described in RFC 5054
does not immediately extend to TLS 1.3 becauseit relies on the
Client Key Exchange and Server Key Exchange messages, which no
longer exist in 1.3.  At a more fundamental level, the messaging
patterns required by SRP do not map cleanly to the standard TLS 1.3
handshake, which has fewer round-trips than prior versions.

TLS 1.3 itself provides a mechanism for authentication with
pre-shared keys (PSKs).  However, PSKs used with this protocol need
to be "full-entropy", because the binder values used for
authentication can be used to mount a dictionary attack on the PSK.
So while the TLS 1.3 PSK mechanism is suitable for the session
resumption cases for which it is specified, it cannot be used when
the client and server share only a low-entropy secret.

Enabling TLS to address this use case effectively requires the TLS
handshake to perform a password-authenticated key establishment
(PAKE) protocol.  This document describes an embedding of the SPAKE2
PAKE protocol in TLS 1.3 {{!I-D.irtf-cfrg-spake2}}
{{!I-D.ietf-tls-tls13}}.  This mechanism also applies to DTLS 1.3
{{!I-D.ietf-tls-dtls13}}, but for brevity, we will refer only to TLS
throughout.

# Terminology

The key words "MUST", "MUST NOT", "REQUIRED", "SHALL", "SHALL NOT",
"SHOULD", "SHOULD NOT", "RECOMMENDED", "MAY", and "OPTIONAL" in this
document are to be interpreted as described in {{!RFC2119}}.

# Setup

In order to use this protocol, a TLS client and server need to have
pre-provisioned the values required to execute the SPAKE2+ protocol
(see Section 3.1 of {{!I-D.irtf-cfrg-spake2}}):

* A DH group of order `p*h`, with `p` a large prime, and generator
  `G`
* Fixed elements `M` and `N` for the group
* A hash function `H`
* A password `pw`

Note that the hash function `H` might be different from the hash
function associated with the ciphersuite negotiated by the two
parties.  The hash function `H` MUST be a hash function suitable for
hashing passwords, e.g., Argon2 or scrypt {{?I-D.irtf-cfrg-argon2}}
{{?RFC7914}}.

The TLS client and server roles map to the `A` and `B` roles in the
SPAKE specification, respectively.  The identity of the server is
the domain name sent in the `server_name` extension of the
ClientHello message.  The identity of the client is an opaque octet
string, specified in the `spake2` ClientHello extension, defined
below.

From the shared password, each party computes two shared integers
`w0` and `w1` by running the following algorithm twice (changing the
`context` value each time):

~~~~~
struct {
  uint16 context;
  opaque client\_identity<0..255>;
  opaque server\_name<0..255>;
  opaque password<0..255>;
} PasswordInput;
~~~~~

* Encode the following values into a `PasswordInput` structure:
  * `client_identity`: The client's identity, as described above.
  * `server_name`: The server's identity, as described above.
  * `password`: The password `pw`
  * `context`: One of the following values:
    * 0x7730, when generating `w0`
    * 0x7731, when generating `w1`

* Use the hash function `H` with the encoded `PasswordInput`
  structure as input to derive an `n`-byte string, where `n` is the
  byte-length of `p`.

* Interpret the `n`-bit string as an integer `w` in network byte
  order.  Return the result `(w % p) * h` of reducing `w` mod p and
  multiplying it by `h`.

Servers MUST store only the value `w0` and the product `L = w1*G`,
where `G` is the fixed generator of the group.  Clients will need to
have access to the values `w0` and `w1` directly, but SHOULD
generate these values dynamically, rather than caching them.

# TLS Extensions

A client offers to authenticate with SPAKE2 by including an `spake2`
extension in its ClientHello.  The content of this exension is an
`SPAKE2ClientHello` value, specifying the client's identity, where
the identity matches that used in 'IdentifierAndPassword', and a
key share `T`.  The value `T` is computed as specified in
{{!I-D.irtf-cfrg-spake2}}, as `T = w*M + X`, where `M` is a fixed
value for the DH group and `X` is the public key of a fresh DH key
pair.  The format of the key share `T` is the same as for a
`KeyShareEntry` value from the same group.

If a client sends the `spake2` extension, then it MAY also send the
`key_share` and `pre_shared_key` extensions, to allow the server to
choose an authentication mode.  Unlike PSK-based authentication,
however, authentication with SPAKE2 cannot be combined with the
normal TLS ECDH mechanism.

~~~~~
struct {
    opaque identity<0..2^16-1>;
    opaque key_exchange<1..2^16-1>;
} SPAKE2Share;

struct {
    SPAKE2Share client_shares<0..2^16-1>;
} SPAKE2ClientHello;
~~~~~

A server that receives an `spake2` extension examines the list of
client shares to see if there is one with an identity the server
recognizes.  If so, the server may indicate its use of SPAKE2
authentication by including an `spake2` extension in its
ServerHello.  The content of this exension is an `SPAKE2ServerHello`
value, specifying the identity value for the password the server has
selected, and the server's key share `S`.  The value `S` is computed
as specified in {{!I-D.irtf-cfrg-spake2}}, as `S = w*N + Y`, where
`N` is a fixed value for the DH group and `Y` is the public key of a
fresh DH key pair.  The format of the key share `S` is the same as
for a `KeyShareEntry` value from the same group.

Use of SPAKE2+ authenication is compatible with standard
certificate-based authentication of both clients and servers.  If a
server includes an `spake2` extension in its ServerHello, it may
still send the Certificate and CertificateVerify messages, and/or
send a CertificateRequest message to the client.

If a server uses SPAKE2 authentication, then it MUST NOT send an
extension of type `key_share`, `pre_shared_key`, or `early_data`.

~~~~~
struct {
    SPAKE2Share server_share;
} SPAKE2ServerHello;
~~~~~

Based on these messages, both the client and server can compute the
two shared values as specified in {{!I-D.irtf-cfrg-spake2}}.

| Name | Value    | Client          | Server         |
|:-----|:---------|:----------------|:---------------|
| Z    | x\*y\*G  | x\*(S - w0\*N)  | x\*(T - w0\*M) |
| V    | w1\*y\*G | w1\*(S - w0\*N) | y\*L           |


The value `Z` is used as the "(EC)DHE" input to the TLS key
schedule.  The value `V` is used as the "PSK" input.

As with client authentication via certificates, the server has not
authenticated the client until after it has received the client's
Finished message.  When a server negotiates the use of this
mechanism for authentication, it MUST NOT send application data
before it has received the client's Finished message.

# Security Considerations

For the most part, the security properties of the password-based
authentication described in this document are the same as those
described in the Security Considerations of
{{!I-D.irtf-cfrg-spake2}}.  The TLS Finished MAC provides the key
confirmation required for the security of the protocol.  Note that
all of the elements covered by the example confirmation hash listed
in that document are also covered by the Finished MAC:

* `A`, `B`, and `T` are included via the ClientHello
* `S` via the ServerHello
* `K`, and `w` via the TLS key schedule

The `x` and `y` values used in the SPAKE2 protocol MUST have the
same ephemerality properties as the key shares sent in the
`key_shares` extension.  In particular, `x` and `y` MUST NOT be
equal to zero.   This ensures that TLS sessions using SPAKE2 have
the same forward secrecy properties as sessions using the normal TLS
(EC)DH mechanism.

The mechanism defined in this document does not provide protection
for the client's identity, in contrast to TLS client authentication
with certificates.

[[ XXX(rlb@ipv.sx): Maybe there's some HRR dance we could do.
For example: Server provides a key share in HRR, client does ECIES
on identity. ]]

TLS servers that offer this mechanism can be used by third party
attackers as an oracle for two questions:

1. Whether the server knows about a given identity
2. Whether the server recognizes a given (identity, password) pair

The former is signaled by whether the server returns an spake2
extension.  The latter is signaled by whether the connection
succeeds.  These oracles are all-or-nothing: If the attacker does
not have the correct identity or password, he does not learn
anything about the correct value.

# IANA Considerations

This document requests that IANA add a value to the TLS
ExtensionType Registry with the following contents:

| Value | Extension Name | TLS 1.3 | Reference |
|:------|:---------------|:-------:|:---------:|
| TBD   | spake2         | CH, SH  | RFC XXXX  |

[[ RFC EDITOR: Please replace "TBD" in the above table with the
value assigned by IANA, and replace "XXXX" with the RFC number
assigned to this document. ]]
