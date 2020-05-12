package main

import (
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"strconv"
	"strings"
)

func toDnsName(domain string) []byte {
	var outBuffer []byte
	parts := strings.Split(domain, ".")
	for _, label := range parts {
		outBuffer = append(outBuffer, byte(len(label)))
		outBuffer = append(outBuffer, label...)
	}
	return outBuffer
}

func main() {
	if len(os.Args) < 4 {
		fmt.Println("usage: test <algonumber> <domain> <nsname>")
		fmt.Println("")
		fmt.Println("example: test 225 facebook.com a.ns.facebook.com")
		os.Exit(1)
	}

	alg, err := strconv.Atoi(os.Args[1])
	if err != nil || alg > 255 || alg < 0 {
		fmt.Println("Invalid algonumber specified, should be an integer between 0 and 255")
		os.Exit(1)
	}
	domain := os.Args[2]
	if !strings.HasSuffix(domain, ".") {
		domain = domain + "."
	}
	nsname := os.Args[3]

	config := &tls.Config{
		InsecureSkipVerify: true,
		ServerName:         nsname,
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
			hashData := toDnsName(domain)
			hashData = append(hashData, byte(0), byte(0), byte(3), byte(alg))
			hashData = append(hashData, cert.RawSubjectPublicKeyInfo...)
			hash := sha256.Sum256(hashData)
			fmt.Printf("%s IN DS x %d 2 %s\n", domain, alg, hex.EncodeToString(hash[:]))
			return nil
		},
	}

	tls.Dial("tcp", fmt.Sprintf("%s:853", nsname), config)
}
