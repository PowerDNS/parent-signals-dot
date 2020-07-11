This document quotes draft-ieft-dprive-phase2-requirements-01 to mark each 'requirement' as satisfied by the draft, unsatisfied by the draft, or commented otherwise. Every 'Yes' should be taken as 'when deployed by the relevant operators', or in other words 'the draft protocol permits it and the operator can choose to deploy'.

> DNS Privacy Requirements for Exchanges between Recursive Resolvers and Authoritative Servers
>
>     draft-ietf-dprive-phase2-requirements-01
> 
> Abstract
> 
>    This document provides requirements for adding confidentiality to DNS
>    exchanges between recursive resolvers and authoritative servers.
> 
> 5.  Requirements
> 
>    The requirements of different interested stakeholders are outlined
>    below.
> 
> 5.1.  Mandatory Requirements
> 
>    1.   Each implementing party should be able to independently take
>         incremental steps to meet requirements without the need for
>         close coordination (e.g. loosely coupled)

Yes.

Resolver operators can go from 'not doing DoT' to 'doing DoT probing' (if software supports it, it is not in scope of this draft), to 'support this protocol in a permissive mode to see how well it would work', to 'full deployment without fallback'.
We also imagine that positive Trust Anchors could be configured for specific domains and name servers, perhaps by mutual agreement, to gain operational experience.

Zone owners are in charge of their DS records, and by extension, in charge of whether this DoT signal-and-pin is applied to their zone at all.
Thus, name server operators have the power (in coordination with their users, who are zone owners) to incrementally deploy to one zone, then ten zones, and so on.
When the operator has the ability to update DS records (because the operator is also the registrar, or because CDS/CDNSKEY is supported in a situation), that operator can even do the incremental rollout without talking to their users all the time.

>    2.   Use a secure transport protocol between a recursive resolver and
>         authoritative servers

Yes.

>    3.   Use a secure transport protocol between a recursive resolver and
>         TLD servers

Yes.

>    4.   Use a secure transport protocol between a recursive resolver and
>         the root servers

There's a trust anchor distribution problem here.
Robin proposed to special-case the root and have resolvers fetch CDS during root priming.

>    5.   The secure transport MUST only be established when referential
>         integrity can be verified, MUST NOT have circular dependencies,
>         and MUST be easily analyzed for diagnostic purposes.

Yes, yes, perhaps.
 
>    6.   Use a secure transport protocol or other DNS privacy protections
>         in a manner that enables operators to perform appropriate
>         performance and security monitoring, conduct relevant research,
>         etc.

Yes, maybe, etc.

>    7.   The authoritative domain owner or their administrator MUST have
>         the option to specify their secure transport preferences (e.g.
>         what specific protocols are supported).

The draft is limited to DoT.
We propose that other protocols update this draft by adding additional DNSKEY algorithms (TBD2 etc.).
TODO: should we have words on future protocols such as DoQ?

>         This SHALL include a
>         method to publish a list of secure transport protocols (e.g.
>         DoH, DoT and other future protocols not yet developed).  In
>         addition this SHALL include whether a secure transport protocol
>         MUST always be used (non-downgradable) or whether a secure
>         transport protocol MAY be used on an opportunistic (not strict)
>         basis.

This draft specifies that the protocol indicated (DoT) is mandatory and no downgrades shall occur.

>    8.   The authoritative domain owner or their administrator MUST have
>         the option to vary their preferences on an authoritative
>         nameserver to nameserver basis, due to the fact that
>         administration of a particular DNS zone may be delegated to
>         multiple parties (such as several CDNs), each of which may have
>         different technical capabilities.

This draft specifies that if not all authoritatives for a domain cooperate in DoT with the pinned keys, they must fail swiftly and not cause timeouts.

>    9.   The specification of secure transport preferences MUST be
>         performed using the DNS and MUST NOT depend on non-DNS
>         protocols.

Yes.

>    10.  For the secure transport, TLS 1.3 (or later versions) MUST be
>         supported and downgrades from TLS 1.3 to prior versions MUST not
>         occur.

Yes, but out of scope for this discovery/pinning draft.

> 5.2.  Optional Requirements
> 
>    1.  QNAME minimisation SHOULD be implemented in all steps of
>        recursion

Out of scope.

>    2.  DNSSEC validation SHOULD be performed

DS records used in validating pins for doing DoT MUST be validated.
Other than that, resolver DNSSEC behaviour is out of scope for this draft.

>    3.  If an authoritative domain owner or their administrator indicates
>        that (1) multiple secure transport protocols are available or
>        that (2) a secure transport and insecure transport are available,
>        then per the recommendations in [RFC8305] (aka Happy Eyeballs) a
>        recursive server SHOULD initiate concurrent connections to
>        available protocols.  Consistent with Section 2 of [RFC8305] this
>        would be: (1) Initiation of asynchronous DNS queries to determine
>        what transport protocols are supported, (2) Sorting of resolved
>        destination transport protocols, (3) Initiation of asynchronous
>        connection attempts, and (4) Establishment of one connection,
>        which cancels all other attempts.

We strongly disagree, with reference to [the bottom end of Duane Wessels' response to phase2-01](https://mailarchive.ietf.org/arch/msg/dns-privacy/eMtjqBBu6m7YhKEHkW5ZKfvZohg/).
We also believe that when the presence of any secure transport is indicated, no insecure transport should ever be permitted.

However, it would make sense for a resolver to support this protocol in a 'Permissive' mode that logs failures - just like many operators will go from 'no DNSSEC' to 'check signatures but do not SERVFAIL on Bogus' to, finally, 'full DNSSEC validation'.
TODO: write a decent paragraph in the document about this, and make it clear that this weakens various MUSTs, and that this is allowed.
