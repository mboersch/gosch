// Copyright (c) Marius Börschig. All rights reserved.
// Licensed under the BSD-3-Clause License.
package server

import (
	"testing"
	"io/ioutil"
	"os"
	"time"
	"crypto/tls"
	"bufio"
	"fmt"
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
// connect to ssl server on localhost
func startClient(t *testing.T, clNum int, ctrl chan bool) error {
	done := false
	log := func(msg string, args ...interface{}) error{
		t.Logf("client%d: %s", clNum, fmt.Sprintf(msg, args...))
		return nil
	}
	die := func(msg string, args ...interface{}) error {
		t.Errorf("client%d: %s", clNum, fmt.Sprintf(msg, args...))
		ctrl <- false
		done = true
		return nil
	}
	log("Client connecting to localhost:6697")
	conn, err := tls.Dial("tcp", "localhost:6697", &tls.Config{InsecureSkipVerify: true},)
	if err != nil {
		return die("tls.Dial failed: %s", err)
	}
	defer conn.Close()
	out := bufio.NewWriter(conn)
	if out == nil {
		return die("cannot create bufio.NewWriter()")
	}
	reader := bufio.NewReader(conn)
	if reader == nil {
		return die("cannot create bufio.NewReader()")
	}

	send := func(msg string, args ...interface{}) {
		tmp := fmt.Sprintf(msg, args...)
		out.WriteString(fmt.Sprintf("%s\r\n", tmp))
		if err := out.Flush(); err != nil {
			die("sending failed %s", err)
		}
	}
	//consume input
	go func () error {
		for done == false {
			buf, err := reader.ReadString('\n')
			if err != nil {
				if done {
					ctrl <- true
					return log("disconnected")
				}
				return die("read error(%T): %s", err, err)
			}
			_ = len(buf)
			//log("read: %s", buf)
		}
		return nil
	}()
	nick := fmt.Sprintf("testConn%d", clNum)
	send("USER %s +mode unused :Test Connection %d", nick, clNum)
	send("NICK %s", nick)
	send("JOIN #test_chan")
	for i:=0; i< 1000;i++ {
		send("PRIVMSG #test_chan :test message number %i", i)
		if (i+1) % (clNum+1) == 300 {
			send("TOPIC #test_chan :Topic set by client %i", i)
		}
		if done {
			return die("done is set!")
		}
	}

	done=true
	log("done")
	ctrl <- true
	return nil
}
func TestClientToServer(t *testing.T) {
	ircd, err := setupServer()
	if err != nil {
		t.Errorf("cannot setup test ircd on localhost with selfsigned SSL certificate: %s", err)
		return
	}
	t.Logf("certfile: %s", ircd.config.Get("certfile"))

	//run async test with timeouts
	numClients := 5
	ctrl := make(chan bool)
	ircd.OnRunning(func() {
		t.Log("starting clients!")
		for i := 0; i< numClients; i++ {
			go startClient(t, i, ctrl)
		}
	})

	tmr := time.NewTimer(5 * time.Second)
	go func() {
		select {
		case _ = <-tmr.C:
			t.Log("Timeout reached!")
			ircd.Stop()
			return
		}
	}()
	go func() {
		for numClients > 0 {
			select {
			case ok := <-ctrl:
				if !ok {
					tmr.Stop()
					t.Log("stopping ircd")
					ircd.Stop()
					t.Errorf("one client reported errors")
					return
				}
				numClients--
				if numClients == 0 {
					t.Logf("all clients done")
					tmr.Stop()
					ircd.Stop()
					return
				}
			}
		}
	}()
	ircd.Run(); //must be on main thread?
}
