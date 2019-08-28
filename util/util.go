// Copyright (c) Marius Börschig. All rights reserved.
// Licensed under the BSD-3-Clause License.
package util

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"io/ioutil"
	"math/big"
	"net"
	"os"
	"strings"
	"time"
)

//MakeSelfSigned creates a PEM  encoded self-signed certificate and a key

func MakeSelfSignedCert(keylength int) (string, error) {
	var rv strings.Builder
	hostname, err := os.Hostname()
	if err != nil {
		return "OS ERROR", err
	}

	key, err := rsa.GenerateKey(rand.Reader, keylength)
	if err != nil {
		return "ERROR", err
	}
	cert := x509.Certificate{
		SerialNumber: new(big.Int).Lsh(big.NewInt(1), 128),
		Subject: pkix.Name{
			Organization:       []string{hostname},
			PostalCode:         []string{"0815"},
			Province:           []string{"BW"},
			OrganizationalUnit: []string{"Test Server"},
			Locality:           []string{"Basement"},
			Country:            []string{"DE"},
			CommonName:         hostname,
		},
		NotBefore: time.Now(),
		NotAfter:  time.Now().Add(time.Hour * 365 * 24),
		KeyUsage: x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature |
			x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
		BasicConstraintsValid: true,
		DNSNames:              []string{hostname},
		IsCA:                  true,
	}
	if len(hostname) > 0 {
		cert.DNSNames = append(cert.DNSNames, hostname)
		hostnames, err := net.LookupHost(hostname)
		if err != nil {
			for _, h := range hostnames {
				if ip := net.ParseIP(h); ip != nil {
					cert.IPAddresses = append(cert.IPAddresses, ip)
				}
				if h != hostname {
					cert.DNSNames = append(cert.DNSNames, h)
				}
			}
		}
	}
	der, err := x509.CreateCertificate(rand.Reader, &cert, &cert, &key.PublicKey, key)
	if err := pem.Encode(&rv, &pem.Block{Type: "CERTIFICATE", Bytes: der}); err != nil {
		return "ERROR", err
	}
	if err := pem.Encode(&rv, &pem.Block{Type: "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(key)}); err != nil {
		return "ERROR", err
	}
	return rv.String(), nil
}

func MakeSelfSignedPemFile(filename string) error {
	out, err := MakeSelfSignedCert(4096)
	if err != nil {
		return err
	}
	return ioutil.WriteFile(filename, []byte(out), 0600)
}
