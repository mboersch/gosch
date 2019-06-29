package main
//Copyright (C) 2019  Marius Boerschig <code (at) boerschig (dot) net>

import (
    . "gosch/server"
)
func main() {
    server :=  NewServer()
	server.Run()
}
