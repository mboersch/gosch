package main
//Copyright (C) 2019  Marius Boerschig <code (at) boerschig (dot) net>
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
