// Copyright (c) Marius Börschig. All rights reserved.
// Licensed under the BSD-3-Clause License.
package server

import (
	"testing"
	"io/ioutil"
	"os"
	"time"
	"crypto/tls"
)
func setupServer() (rv *ircd,  err error){
	certfile, err  := ioutil.TempFile("","TestGoschServer*")
	if err != nil {
		return nil, err
	}
	tmpname := certfile.Name()
	certfile.Close()
	os.Remove(certfile.Name())


	args := []string{"-certfile",
					tmpname,
					"-selfsigned",
					"-address",
					"localhost",
	}
	rv, err = NewServer(args)
	return rv, err
}
func waitSome(duration time.Duration, callback func()) {
	//async wait, then call callback
	t := time.NewTimer(duration * time.Second)
	go func() {
		select {
		case _ = <-t.C:
			defer callback()
			return
		}
	}()

}
// connect to ssl server on localhost
func startClient(t *testing.T) {
	t.Log("Client connecting to localhost:6697")
	conn, err := tls.Dial("tcp", "localhost:6697", nil)
	if err != nil {
		t.Errorf("tls.Dial failed: %s", err)
		return
	}
	defer conn.Close()
}
func TestClientToServer(t *testing.T) {
	ircd, err := setupServer()
	if err != nil {
		t.Errorf("cannot setup test ircd on localhost with selfsigned SSL certificate: %s", err)
		return
	}
	t.Logf("certfile: %s", ircd.config.Get("certfile"))
	waitSome(10, ircd.Stop)
	waitSome(1, func() { go startClient(t)})
	ircd.Run();//blocking main
}
