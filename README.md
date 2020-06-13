# Goal

Figure out a way to signal DoT support (which would then be mandatory to avoid downgrade attacks) for a domain, from the delegation side, like DS records do for DNSSEC.
Ideally, this would support some kind of pinning.

# Previous work

Manu Bretelle, IETF 104 dprive

1. [presentation: DoT For insecure delegations](https://datatracker.ietf.org/meeting/104/materials/slides-104-dprive-dot-for-insecure-delegations)
1. [draft-bretelle-dprive-dot-spki-in-ns-name: Encoding DNS-over-TLS (DoT) Subject Public Key Info (SPKI) in Name Server name](https://tools.ietf.org/html/draft-bretelle-dprive-dot-spki-in-ns-name-00). Problem: NS name in delegation is not signed.
1. [draft-bretelle-dprive-dot-for-insecure-delegations: DNS-over-TLS for insecure delegations](https://tools.ietf.org/html/draft-bretelle-dprive-dot-for-insecure-delegations-01). Problems: new parent-side DSPKI RRtype requires changes in DNS auth servers and resolvers; pin is limited to the server certificate, not anything higher in the chain.

Stéphane Bortzmeyer, dprive

1. [Encryption and authentication of the DNS resolver-to-authoritative communication](https://tools.ietf.org/html/draft-bortzmeyer-dprive-resolver-to-auth-01). Relies on TLSA in the zone hosting the NS name. Problems: inconvenient indirection; relies on DNSSEC in the zone hosting the NS name; lookup of the TLSA is not encrypted.

T. April, IETF 107 dnsop:

1. [draft-tapril-ns2](https://datatracker.ietf.org/doc/draft-tapril-ns2/). New `NS2` and `NS2T` RRtypes. Covers DoT, DoH, DoQ. Problems: hard to deploy parent side (like DSPKI); lots of complexity for resolvers; risk of loops.

J. Levine, dprive:

1. [draft-levine-dprive-signal-02](https://tools.ietf.org/html/draft-levine-dprive-signal-02). Contains six proposals that all have problems with downgrades, indirection, or that they require DNSSEC.

# Other rejected ideas

Apply Manu Bretelle's DSPKI type to DS, by assigning a new DNSSEC algorithm for it.
Problem: many registries require the ability to generate DS from DNSKEY.

Put TLSA for delegated name servers in parent zone. Cannot do this with normal TLSA syntax, because `ns1.example.com` is inside the `example.com` delegation, so this requires another hack to map that name into the parent zone. Problems: this puts a limit on the maximum name length of name servers; breaks Paul Wouter's powerbind proposal; generally does not look pretty.

## Bortzmeyer+TLSA chain

If we add [draft-ietf-tls-dnssec-chain-extension-07](https://tools.ietf.org/html/draft-ietf-tls-dnssec-chain-extension-07) to Bortzmeyer's proposal above, as a mandatory configuration for DoT auths, the inconvenient indirection goes away.
Then all that is left is just the signal 'this zone has DoT' which could be a DS record with specific algorithm, ignored digest and ignored content.
This still requires DNSSEC in the zone hosting the NS name.

Problem: because the NSset in a delegation is unsigned, this does not actually provide any security.

# Proposals

## SPKI in DNSKEY

Stick SPKI (as defined by Manu Bretelle's DSPKI draft) in CDNSKEY (when we say CDNSKEY, we also mean 'submit DNSKEY via EPP to registry that does not accept DS').
When we do this, the DS, using an existing digest type, becomes hashed SPKI (with a predictable prefix from 4034 5.1.4), which TLS clients can almost work with.
Problem: as some registries insist on doing their own hashing from DNSKEY to DS, the CDNSKEY would be limited to the non-hashed variant, which prohibits any extra parameters, ~~such as pointing the pin at something higher in the chain (this is a bad idea because the NSset in a delegation is unsigned).~~

## DNSKEY-wrapped TLSA plus DS NULL digest

Define a DNSKEY algorithm that wraps TLSA contents. Define a DS digest type that does not hash - instead it copies DNSKEY content verbatim. We can call it NULL or VERBATIM or something else. Then, we are effectively publishing TLSA for the name server hosts, in the parent zone, without requiring any changes to existing auth software; resolvers will still be able to pass on DS records correctly to their forwarding clients, and can optionally use the new DNSKEY algorithm and DS digest type to confidently operate TLS to the auths.

Problems: because the NSset in a delegation is unsigned, most combinations of TLSA parameters are useless, so this might be more complicated than is useful.
The DS NULL digest type will be a pain to get deployed.

# Random notes

## TLS chain

[draft-dukhovni-tls-dnssec-chain](https://datatracker.ietf.org/doc/draft-dukhovni-tls-dnssec-chain/), [server implementation 1](https://github.com/andreasschulze/openssl-demo-server), [server implementation 2](https://github.com/shuque/chainserver)
