// Copyright (c) Marius Börschig. All rights reserved.
// Licensed under the BSD-3-Clause License.
package main

import (
	"flag"
	. "github.com/mboersch/gosch/server"
	"os"
)

func main() {
	server, err := NewServer(os.Args[1:])
	if err != nil {
		if err == flag.ErrHelp {
			return
		}
		panic(err)
	}
	server.Run()
}
