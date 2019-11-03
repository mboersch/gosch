// Copyright (c) Marius Börschig. All rights reserved.
// Licensed under the BSD 3-Clause License. See the LICENSE file.
package server

import (
	"crypto/tls"
	"errors"
	"flag"
	"fmt"
	"github.com/mboersch/gosch/config"
	. "github.com/mboersch/gosch/irc"
	"github.com/mboersch/gosch/util"
	"net"
	"os"
	"os/signal"
	"strconv"
	"sync"
	"time"
)

const (
	SERVER_VERSION string = "0.0.1"
)

func isNumeric(reply string) bool {
	if _, err := strconv.Atoi(reply); err == nil {
		return true
	}
	return false
}

/////////////////////////////////////////////
// ircd
type ircd struct {
	config     *config.Config
	logger     util.Logger
	channels   map[string]*ircchannel
	clients    map[string]*ircclient
	mutex      sync.Mutex
	created    time.Time
	version    string
	servername string
	listenSock net.Listener
	isRunning  bool
	onShutdown func()
	onRunning  func()
}

func (self *ircd) OnShutdown(callback func()) {
	self.onShutdown = callback
}
func (self *ircd) OnRunning(callback func()) {
	self.onRunning = callback
}
func (self *ircd) IsRunning() bool {
	self.mutex.Lock()
	defer self.mutex.Unlock()
	return self.isRunning
}
func (self *ircd) trace(msg string, args ...interface{}) {
	self.logger.Trace(msg, args...)
}
func (self *ircd) debug(msg string, args ...interface{}) {
	self.logger.Debug(msg, args...)
}
func (self *ircd) log(msg string, args ...interface{}) {
	if self.logger == nil {
		fmt.Printf(msg, args...)
		return
	}
	self.logger.Info(msg, args...)
}
func (self *ircd) fatal(msg string, args ...interface{}) {
	if self.logger == nil {
		fmt.Printf(msg, args...)
		return
	}
	self.logger.Error(msg, args...)
}
func (self *ircd) usage(msg string) error {
	self.config.Flags.PrintDefaults()
	return errors.New(fmt.Sprintf("ERROR: %s\n", msg))
}
func (self *ircd) parseArgs(args []string) error {
	self.config = config.NewConfig("gosch", self.version)
	err := self.config.Parse(args)
	if err != nil {
		return err
	}
	self.logger.SetLogLevel(util.LogLevel(self.config.DebugLevel))
	if narg := self.config.Flags.NArg(); narg > 0 {
		args := self.config.Flags.Args()
		fmt.Printf("ERROR: additional %d unknown arguments: %v\n", narg, args)
		for i := range args {
			fmt.Printf("unknown: \"%v\"\n", args[i])
		}
		self.config.Flags.PrintDefaults()
		return errors.New("unkown arguments")
	}
	if logf := self.config.Get("logfile"); self.config.IsSet("logfile") {
		fd, err := os.OpenFile(logf.String(), os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0600)
		if err != nil {
			panic(err)
		}
		self.logger.AddSink(fd)
	}
	tmp := self.config.GetInt("port")
	if tmp > int64(^uint16(0)) {
		return self.usage("the specified port is invalid")
	}
	crtflag := self.config.Get("certfile")
	if crtflag == nil {
		return self.usage("please specify a certificate file. Or use '-selfsigned' to generate one")
	}
	crt := crtflag.String()
	_, err = os.Stat(crt)
	if os.IsNotExist(err) {
		if self.config.IsSet("selfsigned") {
			self.log("creating self signed tls certificate")
			if err := util.MakeSelfSignedPemFile(crt); err != nil {
				self.log("cannot make self signed cert: %s\n", err)
				return errors.New("creating self signed certificate failed")
			}
		} else {
			return self.usage("the certificate file does not exist")
		}
	}
	if self.config.IsSet("daemon") {
		//remove --daemon from flags, and forkexec ourselves
		cmdargs := make([]string, 1)
		cmdargs[0] = os.Args[0]
		self.config.Flags.Visit(func(flg *flag.Flag) {
			if flg.Name != "daemon" {
				cmdargs = append(cmdargs, fmt.Sprintf("-%s", flg.Name))
				if flg.Value.String() != "true" {
					cmdargs = append(cmdargs, fmt.Sprintf("%v", flg.Value))
				}
			}
		})
		if self.config.Flags.NArg() > 0 {
			cmdargs = append(cmdargs, self.config.Flags.Args()...)
		}
		pwd, err := os.Getwd()
		if err != nil {
			self.log("error getting working directory: %s", err)
			os.Exit(-1)
		}
		self.log("going to background")
		pid, err := util.Daemonize(cmdargs, pwd)
		if err != nil {
			self.log("error going to background: %s", err)
			os.Exit(-1)
		}
		self.log("daemon pid is %d", pid)
		os.Exit(0)
	}
	return nil
}
func (self *ircd) getChannel(name string) *ircchannel {
	if ch, ok := self.channels[name]; ok {
		return ch
	}
	return nil
}
func (self *ircd) deliverToChannel(tgt *string, msg *clientMessage) {
	self.debug("delivering to %s: %v", *tgt, msg)
	ch := self.getChannel(*tgt)
	if ch == nil {
		self.debug("deliver: ignoring msg on non-existing channel %s", *tgt)
		return
	}
	ch.SendMessage(msg)
	return
}
func (self *ircd) deliver(msg *clientMessage) {
	//disseminate the client message, e.g. from client to channel etc
	//channels multiplex: JOIN, MODE, KICK, PART, QUIT, PRIVMSG/NOTICE
	//TODO NOTICE must not send any error replies
	msg.SetPrefix(msg.source.getIdent())
	switch cmd := *msg.Command(); cmd {
	case "JOIN", "PART", "KICK", "MODE", "QUIT", "PRIVMSG", "NOTICE":
		// XXX locking channels/members ?
		if msg.NumParameters() > 0 {
			tgt := msg.First()
			// :prefix CMD #target
			//self.log("tgt=%v, validChannelName=%v", tgt, IsChannelName(tgt))
			if IsChannelName(*tgt) {
				self.deliverToChannel(tgt, msg)
			} else {
				// :prefix CMD nick/ident
				//must be client/user
				//TODO <msgtarget> might be a hostmask ("*.foobar") for OP
				if cmd != "PRIVMSG" && cmd != "NOTICE" {
					self.log("ERROR: got directed message that is not privmsg/notice!: %v", msg)
					return
				}
				if msg.NumParameters() < 2 {
					msg.source.numericReply(ERR_NOTEXTTOSEND)
					return
				}
				cl := self.findClientByNick(*tgt)
				if cl == nil {
					msg.source.numericReply(ERR_NOSUCHNICK, *tgt)
					return
				}
				if cl.IsAway() {
					msg.source.numericReply(RPL_AWAY, cl.nickname, cl.awayMessage)
				}
				cl.send(msg.Raw())
			}
		} else {
			// :prefix CMD :trailing, only interesting for the current client?
			msg.source.send(msg.Raw())
		}
	case RPL_TOPIC.String(), RPL_TOPICWHOTIME.String():
		if msg.NumParameters() >= 2 {
			if IsChannelName(msg.Parameters()[1]) {
				self.deliverToChannel(&msg.Parameters()[1], msg)
			} else if cl := self.findClientByNick(msg.Parameters()[1]); cl != nil {
				cl.send(msg.Raw())
			}
		}
	}
}
func (self *ircd) findClientByNick(nick string) *ircclient {
	self.mutex.Lock()
	defer self.mutex.Unlock()
	for _, cl := range self.clients {
		if cl.nickname == nick {
			return cl
		}
	}
	return nil
}
func NewServer(args []string) (*ircd, error) {
	rv := new(ircd)
	rv.version = SERVER_VERSION
	rv.created = time.Now()
	rv.logger = util.NewLogger("ircd")
	if err := rv.parseArgs(args); err != nil {
		return nil, err
	}
	rv.clients = make(map[string]*ircclient)
	rv.channels = make(map[string]*ircchannel)
	rv.handleSignals()
	return rv, nil
}
func (self *ircd) addClient(client *ircclient) {
	self.mutex.Lock()
	defer self.mutex.Unlock()
	self.clients[client.id] = client
}
func (self *ircd) onDisconnect(client *ircclient) error {
	// send quit message to all channels
	for _, ch := range client.channels {
		// sanity check
		if !ch.IsMember(client) {
			self.fatal("sanity check failed: client %v is not a member of %v",
				client, ch)
		}
		self.trace("onDisconnect: removing from %v members=%v", ch.name, ch.members)
		ch.RemoveClient(client)
		if len(ch.members) > 0 {
			ch.SendMessage(client.makeMessage(":%s QUIT :%s", client.getIdent(), client.doneMessage))
		}
	}
	return nil
}
func (self *ircd) cleanup(force bool) {
	for _, cl := range self.clients {
		if force {
			cl.SetDone()
		}
		if cl.IsDone() {
			self.onDisconnect(cl)
			self.log("[%s] disconnected", cl.id)
		}
	}
}
func (self *ircd) handleSignals() {
	sigs := make(chan os.Signal, 1)
	signal.Notify(sigs, os.Interrupt, os.Kill)
	var nint int = 0
	go func() {
		for sig := range sigs {
			self.fatal("received signal %v. shutting down.", sig)
			nint++
			if nint > 1 {
				self.fatal("forcing exit")
				os.Exit(1)
			} else {
				self.Stop()
				self.cleanup(true)
			}
		}
	}()
}
func (self *ircd) Stop() {
	self.mutex.Lock()
	defer self.mutex.Unlock()
	self.log("Stopping I/O")
	if self.listenSock != nil {
		_ = self.listenSock.Close()
		self.listenSock = nil
	}
	self.isRunning = false
}
func (self *ircd) Run() {
	self.isRunning = true
	// setup ssl socket
	certfile := self.config.Get("certfile").String()
	crt, err := tls.LoadX509KeyPair(certfile, certfile)
	if err != nil {
		self.log("Cannot load cert/key pair: %s", err)
		return
	}
	cfg := &tls.Config{Certificates: []tls.Certificate{crt}}

	host := self.config.Get("address").String()
	myhost, err := os.Hostname()
	if err != nil {
		self.log("cannot get hostname: %s", err)
		myhost = self.config.Get("address").String() //back to default
	}
	self.log("hostname: %s pid %v", myhost, os.Getpid())
	if host == myhost {
		host = "" //listen to all
	}
	addr := fmt.Sprintf("%s:%d", host, self.config.GetInt("port"))
	l, err := net.Listen("tcp", addr)
	if err != nil {
		self.log("Cannot create listening socket on  %s", addr)
		return
	}
	defer l.Close()
	self.listenSock = l //saved for Stop()
	self.log("Listening on %s", l.Addr())

	self.servername = myhost
	hostnames, err := net.LookupHost(myhost)
	if err != nil {
		self.servername = hostnames[0]
	}
	if self.onRunning != nil {
		self.trace("-> onRunning")
		self.onRunning()
		self.onRunning = nil
	}
	// handle network requests
	for {
		cl, err := l.Accept()
		if !self.IsRunning() {
			break
		}
		if err != nil {
			self.log("ERROR: cannot accept client %v", err)
			continue
		}
		tlsconn := tls.Server(cl, cfg)
		client := NewClient(tlsconn, self)
		self.addClient(client)
		client.Start()
	}
	self.trace("forcing cleanup")
	self.cleanup(true)
}

func (self *ircd) joinChannel(channel, key string, client *ircclient) *ircchannel {
	//TODO key/password checks
	self.mutex.Lock()
	defer self.mutex.Unlock()
	ch := self.getChannel(channel)
	isop := false
	if ch == nil {
		//does not exist yet
		ch = NewChannel(channel)
		self.channels[ch.name] = ch
		isop = true
	}
	ch.AddClient(client)
	if isop {
		ch.SetUserFlag(client, 'O')
		ch.SetUserFlag(client, 'o')
	}
	return ch
}
func (self *ircd) partChannel(channel string, client *ircclient) bool {
	self.mutex.Lock()
	defer self.mutex.Unlock()
	ch := self.getChannel(channel)
	if ch == nil {
		return false
	}
	ch.RemoveClient(client)
	if len(ch.members) == 0 {
		self.trace("destroyed channel %v", ch.name)
		delete(self.channels, ch.name)
	}
	return true
}
func (self *ircd) registerNickname(nick string, client *ircclient) bool {
	self.mutex.Lock()
	defer self.mutex.Unlock()
	self.debug("server: register nick %s for %v", nick, client.getIdent())
	for _, cl := range self.clients {
		if cl.nickname == nick {
			//some other client has the nick
			self.trace("%v wants %s which is taken by %v", client.id, nick, cl.getIdent())
			return false
		}
	}
	client.nickname = nick
	return true
}
