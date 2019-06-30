//Copyright (C) 2019  Marius Boerschig <code (at) boerschig (dot) net>
package util
import (
    "errors"
    "crypto/rand"
    "crypto/rsa"
    "encoding/pem"
    "crypto/x509"
    "crypto/x509/pkix"
    "strings"
    "math/big"
    "time"
    "io/ioutil"
    "net"
    "os"
)

//MakeSelfSigned creates a PEM  encoded self-signed certificate and a key

func MakeSelfSignedCert(myhostname string, keylength int) (string, error) {
    var rv strings.Builder
    key, err := rsa.GenerateKey(rand.Reader, keylength)
    if err != nil { return "ERROR", err }
    cert := x509.Certificate{
        SerialNumber: new(big.Int).Lsh(big.NewInt(1), 128),
        Subject: pkix.Name{
            Organization: []string{"Gosch irc"},
            PostalCode: []string{"0815"},
            Province: []string{"BW"},
            OrganizationalUnit: []string{"Test Server"},
            Locality: []string{"Basement"},
            Country: []string{"DE"},
            CommonName: myhostname,
        },
        NotBefore: time.Now(),
        NotAfter:  time.Now().Add(time.Hour * 365 * 24),
        KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature |
                               x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
        ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
        BasicConstraintsValid: true,
        DNSNames: []string{myhostname},
        IsCA: true,

    }
    hostname, err := os.Hostname()
    if err != nil {
        cert.DNSNames = append(cert.DNSNames, hostname)
        hostnames, err := net.LookupHost(hostname)
        if err != nil {
            for _, h := range hostnames {
                if ip := net.ParseIP(h); ip != nil {
                    cert.IPAddresses = append(cert.IPAddresses, ip)
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

func MakeSelfSignedPemFile(myhostname, filename string) error {
    if strings.Index(myhostname, " ")  != -1 {
        return errors.New("invalid user input as certificate hostname")
    }
    out, err := MakeSelfSignedCert(myhostname, 4096)
    if err != nil {
        return err
    }
    return ioutil.WriteFile(filename, []byte(out), 0600)
}
