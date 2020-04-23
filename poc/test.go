package main

import (
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"errors"
	"fmt"
)

func main() {
	fmt.Println("Hello, playground")

	config := &tls.Config{
		InsecureSkipVerify: true,
		ServerName:         "a.ns.facebook.com",
		VerifyPeerCertificate: func(certificates [][]byte, _ [][]*x509.Certificate) error {
			certs := make([]*x509.Certificate, len(certificates))
			for i, asn1Data := range certificates {
				cert, err := x509.ParseCertificate(asn1Data)
				if err != nil {
					return errors.New("tls: failed to parse certificate from server: " + err.Error())
				}
				certs[i] = cert
			}
			// Assume that the first cert is probably the right one
			cert := certs[0]
			for _, chainCert := range certs {
				// If its not CA cert it must be the right one righ? Right????
				if !chainCert.IsCA {
					cert = chainCert
					break
				}
			}
			hashData := []byte("\x08facebook\x03com\x00\x00\x00\x03\xE1")
			hashData = append(hashData, cert.RawSubjectPublicKeyInfo...)
			hash := sha256.Sum256(hashData)
			fmt.Printf("Hash: %s\n", hex.EncodeToString(hash[:]))
			return nil
		},
	}

	tls.Dial("tcp", "a.ns.facebook.com:853", config)
}
