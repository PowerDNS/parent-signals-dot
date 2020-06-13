#!/usr/bin/env python3
import dns.name
import hashlib
import socket
import ssl
import sys

from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization

if len(sys.argv) < 4:
	print("usage: test.py <algonumber> <domain> <nsname>")
	print()
	print("example: test.py 225 facebook.com a.ns.facebook.com")
	sys.exit(1)

alg = int(sys.argv[1])
domain = sys.argv[2]
nsname = sys.argv[3]

print("### got server certificate (PEM):\n{}".format(ssl.get_server_certificate((nsname, 853))))

s = socket.create_connection((nsname, 853))
c = ssl.create_default_context()
c.check_hostname = False
c.verify_mode = ssl.CERT_NONE
cs = c.wrap_socket(s, server_hostname=nsname)
print("### after connecting again, got server certificate (DER):\n{}".format(cs.getpeercert(binary_form=True)))

cert = x509.load_der_x509_certificate(cs.getpeercert(binary_form=True), default_backend())
print("### pubkey:\n{}".format(cert.public_key().public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo).decode('ascii')))
spki=cert.public_key().public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)
print("### spki:\n{}".format(spki))
tohash = dns.name.from_text(domain).to_wire()+b'\x01\x01'+bytes((3,))+bytes((alg,))+spki
digest = hashlib.sha256(tohash).hexdigest()
print("### digest for DS:\n{}".format(digest))
print("### DS:\n{} IN DS x {} 2 {}".format(domain, alg, digest))