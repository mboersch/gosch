// Copyright (c) Marius Börschig. All rights reserved.
// Licensed under the BSD-3-Clause License.
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
