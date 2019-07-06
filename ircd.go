// Copyright (c) Marius Börschig. All rights reserved.
// Licensed under the BSD-3-Clause License.
package main
import (
    . "gosch/server"
    "os"
    "flag"
)
func main() {
    server, err :=  NewServer(os.Args[1:])
    if err != nil {
        if err == flag.ErrHelp { return }
        panic(err)
    }
	server.Run()
}
