// Copyright (c) Marius Börschig. All rights reserved.
// Licensed under the BSD-3-Clause License.
package util
import (
    "errors"
    "fmt"
)
// linux and netbsd have daemon() in different headers

// #include <errno.h>
// #include <unistd.h>
// #include <stdlib.h>
// #include <string.h>
import "C"

func CDaemonize() error {
    _, err  :=  C.daemon(1, 0)
    if err != nil {
        return errors.New(fmt.Sprintf("daemon() failed: %s", err))
    }
    return nil
}
