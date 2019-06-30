//Copyright (C) 2019  Marius Boerschig <code (at) boerschig (dot) net>
package util

import "testing"

func TestCreateSelfSigned(t *testing.T) {
    pem, err := MakeSelfSignedCert(4096)
    if err != nil {
        t.Fatalf("MakeSelfSigned returned error: %v", err)
    }
    if pem == "ERROR" || len(pem) < 100 {
        t.Fatalf("returned error string")
    }
    t.Logf("pem=%v", pem)
}
//TODO parse pem output and check that it's valid
