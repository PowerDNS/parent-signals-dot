#!/usr/bin/env python3
import hashlib
import ssl
import socket
import sys

from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization

print(ssl.get_server_certificate(('a.ns.facebook.com', 853)))

s = socket.create_connection(('a.ns.facebook.com', 853))
c = ssl.create_default_context()
c.check_hostname = False
c.verify_mode = ssl.CERT_NONE
cs = c.wrap_socket(s, server_hostname='a.ns.facebook.com')
print(cs.getpeercert(binary_form=True))

cert = x509.load_der_x509_certificate(cs.getpeercert(binary_form=True), default_backend())
print('pubkey:', cert.public_key())
spki=cert.public_key().public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)
print('spki:', spki)
tohash = b'\x08facebook\3com\0'+b'\x00\x00'+bytes((3,))+bytes((225,))+spki
print(hashlib.sha256(tohash).hexdigest())
