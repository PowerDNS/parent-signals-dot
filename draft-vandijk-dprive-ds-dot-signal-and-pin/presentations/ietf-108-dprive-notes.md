# slide 1

Paul Hoffman, dnsop, Wednesday: no coordination, authors pushing their own drafts forward, why not discuss requirements first?

dprive has a requirements doc - mishmash of protocol/implementation/operational

> A DS record can still be used to allow the child zone to make it
> mandatory to use DoT or hardfail.

I just want to say that if our draft ends up being nothing more than
the inspiration for this aspect of a document that makes it to
deployment, I will still be very happy with how things turned out :-)

-- Paul/Peter

We understand that our draft solves the problem narrowly and comes with some management difficulties that can be a problem for certain (large) deployments. Very happy that our draft has awoken the WG on this topic, and caused discussion that might inform an update to the requirements document.

---

# slide 2

The intro we should have written. This covers a mix of 'things we desired in the design' and 'things that happened to come out of the design'. What this does not cover are the negative properties - most importantly, having to update 100k DS records when the key on an NS is replaced. This is the weakest spot in our proposal and we fully recognise this.

---

# slide 3

protocol abuse: cannot deny. We are wedging new things into old places, because the alternative appears to be serious changes to authoritative server software, and registry software/operations.

TLSA: interesting to note that our draft, and NS2/NS2T, both take a slice of TLSA and wedge it into something else. We understand 'you should just do TLSA', but that would be an entirely different model. I don't think rewriting this draft for it makes sense - a separate draft for that would. We're happy that discussion on our draft has sparked some emails with informal TLSA-based proposals, and think it would be great if a TLSA-based proposal would be actually written out. I've repeated on the list that I don't consider 'no additional roundtrips' a core requirement, but it would be great if a TLSA-focused proposal would still have that - perhaps by using DS for signal (without pin).

---

# slide 4

---

# slide 5

---

# slide 6

---

# slide 7

---

# slide 8

---

# slide 9

---

# slide 10

insights from Ralph:
* ESNI needs DNS, can't work
* but why send SNI at all!

---

# slide 11

Not complete; specifically, Paul Wouters' suggestion about 'child confirming DS' is missing here. I don't understand the threat model.

---

# slide 12

We do not see implementation problems with setting the ZONE and/or SEP bits. We do understand that setting those bits makes this look like protocol misuse even more.

---

# slide 13

---

# slide 14

---

# slide 15
