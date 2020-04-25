%%%
title = "Signalling Authoritative DoT support in DS records with key pinning"
abbrev = "ds-dot-signal-and-pin"
docName = "draft-vandijk-dprive-ds-dot-signal-and-pin-00"
category = "std"

ipr = "trust200902"
area = "General"
workgroup = "dprive"
keyword = ["Internet-Draft"]

[seriesInfo]
name = "Internet-Draft"
value = "draft-vandijk-dprive-ds-dot-signal-and-pin-00"
stream = "IETF"
status = "standard"

[pi]
toc = "yes"

[[author]]
initials = "P."
surname = "van Dijk"
fullname = "Peter van Dijk"
organization = "PowerDNS"
[author.address]
 email = "peter.van.dijk@powerdns.com"
[author.address.postal]
 city = "Den Haag"
 country = "Netherlands"

[[author]]
initials = "R."
surname = "Geuze"
fullname = "Robin Geuze"
organization = "TransIP"
[author.address]
 email = "robing@transip.nl"
[author.address.postal]
 city = "Delft"
 country = "Netherlands"

%%%


.# Abstract

This Internet-Draft specifies a way to signal the usage of DoT, and the pinned keys for that DoT usage, in authoritative servers.
This signal lives on the parent side of delegations, in DS records.
To ensure easy deployment, the signal is defined in terms of (C)DNSKEY.

{mainmatter}

# Introduction

Even quite recently, DNS was a completely unencrypted protocol, with no protection against snooping.
In recent years this landscape has shifted.
The connections between stubs and resolvers are now often protected by DoT, DoH, or other protocols that provide privacy.
This document introduces a way to signal, from the parent side of a delegation, that the name servers hosting the delegated zone support DoT, and with which TLS/X.509 keys.
This proposal does not require any changes in authoritative name servers (other than, possibly through an external process), actually offering DoT on port 853 [@!RFC7858].
DNS registry operators (such as TLD operators) also need to make no changes, unless they filter uploaded DNSKEY/DS records on acceptable DNSKEY algorithms, in which case they would need to add algorithm TBD to that list.

This document was inspired by, and borrows heavily from, [@!I-D.bretelle-dprive-dot-for-insecure-delegations].

# Conventions and Definitions

The key words "MUST", "MUST NOT", "REQUIRED", "SHALL", "SHALL NOT", "SHOULD", "SHOULD NOT", "RECOMMENDED", "NOT RECOMMENDED", "MAY", and "OPTIONAL" in this document are to be interpreted as described in BCP 14 [@!RFC2119] [@RFC8174] when, and only when, they appear in all capitals, as shown here.

CDNSKEY record
: as defined in [@!RFC7344;@!RFC8078]

DS record
: as defined in [@!RFC4034]

DNSKEY record
: as defined in [@!RFC4034]


# Summary

To enable the signaling of DoT a new DNSKEY algorithm type TBD is added.
If a resolver with support for TBD encounters a DS record with the DNSKEY algorithm type TBD it MUST connect to the authoritative servers for this domain via DoT.
It MUST use the hashes attached to the DS records with DNSKEY algorithm type TBD to check whether the public key supplied by the authoritative nameserver is valid.
If the DoT connection is unsuccessful or the public key supplied the server does not match one of the DS digests, the resolver MUST NOT fall back to unencrypted Do53.

The pseudo DNSKEY record MUST contain DER encoded SubjectPublicKeyInfo as defined in [@!RFC5280] 4.1.2.7.
Since the cert provided by the TLS server over the wire is already DER encoded this makes for easy validation.
The pseudo DNSKEY algorithm type TBD is algorithm agnostic, like the TLSA record, since the DER encoded data already contains information about the used algorithm.
Algorithm support SHOULD be handled at the TLS handshake level, which means a DNS application SHOULD NOT need to be aware of the algorithm used by its TLS library.
The pseudo DNSKEY record MUST NOT be present in the zone.
The procedure for hashing the pseudo DNSKEY record is the same as for a normal DNSKEY as defined in RFC4034.

The pseudo DNSKEY type can be used in CDNSKEY and CDS, as defined in RFC7344, records as well. These MAY be present in the zone.

# Example


# Implementation

The subsection titles in this section attempt to follow the terminology from [@RFC8499] in as far as it has suitable terms.

## Authoritative server changes

## Validating resolver changes

## Stub resolver changes

## Zone validator changes

## Domain registry changes

# Security Considerations

This document defines a way to convey, authoritatively, that resolvers must use DoT to do their queries to the name servers for a certain zone.
By doing so, that exchange gains confidentiality, data integrity, peer entity authentication.

# Implementation Status

[RFC Editor: please remove this section before publication]

This section records the status of known implementations of the protocol defined by this specification at the time of posting of this Internet-Draft, and is based on a proposal described in [@!RFC6982].
The description of implementations in this section is intended to assist the IETF in its decision processes in progressing drafts to RFCs.
Please note that the listing of any individual implementation here does not imply endorsement by the IETF.
Furthermore, no effort has been spent to verify the information presented here that was supplied by IETF contributors.
This is not intended as, and must not be construed to be, a catalog of available implementations or their features.
Readers are advised to note that other implementations may exist.

According to RFC 6982, "this will allow reviewers and working groups to assign due consideration to documents that have the benefit of running code, which may serve as evidence of valuable experimentation and feedback that have made the implemented protocols more mature.  It is up to the individual working groups to use this information as they see fit".

## PoC

Some Proof of Concept code showing the generation of the (C)DNSKEY, and the subsequent hashing by a client (which should match one of the DS records with algo TBD), in Python and Go, is available at https://github.com/PowerDNS/parent-signals-dot/tree/master/poc

# IANA Considerations

[TODO: boilerplate about requesting TBD assignment]

# Acknowledgements

This document would not have been possible without the tremendous inspiration Manu Bretelle gave us at IETF104.
Further great input was received from
Job Snijders,
Petr Spacek,
Pieter Lexis,
Ralph Dolmans,
and Vladimir Cunat.

{backmatter}

