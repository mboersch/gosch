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
)

//MakeSelfSigned creates a PEM  encoded self-signed certificate and a key

func MakeSelfSignedCert(myaddr string, keylength int) (string, error) {
    var rv strings.Builder
    key, err := rsa.GenerateKey(rand.Reader, keylength)
    if err != nil { return "ERROR", err }
    cert := x509.Certificate{
        SerialNumber: big.NewInt(0x0815),
        Subject: pkix.Name{
            Organization: []string{"Gosch irc"},
        },
        NotBefore: time.Now(),
        NotAfter:  time.Now().Add(time.Hour * 365 * 24),
        KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature |
                               x509.KeyUsageCertSign,
        ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
        BasicConstraintsValid: true,
        DNSNames: []string{myaddr},
        IsCA: true,

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

func MakeSelfSignedPemFile(myaddr, filename string) error {
    out, err := MakeSelfSignedCert(myaddr, 4096)
    if err != nil {
        return err
    }
    if strings.Index(myaddr, " ")  != -1 {
        return errors.New("invalid user input as certificate hostname")
    }
    return ioutil.WriteFile(filename, []byte(out), 0600)
}
