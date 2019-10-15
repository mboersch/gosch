// Copyright (c) Marius Börschig. All rights reserved.
// Licensed under the BSD 3-Clause License. See the LICENSE file.
package server

import (
	"bufio"
	"bytes"
	"crypto/sha256"
	"errors"
	"fmt"
	"github.com/mboersch/gosch/irc"
	"net"
	"strconv"
	"strings"
	"time"
)

type clientMessage struct {
	irc.Message
	source *ircclient
}

type ircclient struct {
	server   *ircd
	channels map[string]*ircchannel
	// IO
	conn       net.Conn
	connwriter *bufio.Writer
	outQueue   chan string
	// state
	registered                   bool
	done                         bool
	doneMessage                  string
	nickname, username, realname string
	id                           string //for logging/handling
	lastActivity                 int64
	lastPing                     int64
	pingTimer                    *time.Timer
	permissions                  string
	password                     string
	hostname                     string
	hashedname                   string
	mode                         string
	isBroken                     bool
	badBehavior                  int
	awayMessage                  string
}

// ircclient
func NewClient(conn net.Conn, server *ircd) *ircclient {
	rv := new(ircclient)
	rv.conn = conn
	rv.server = server
	rv.id = conn.RemoteAddr().String()
	rv.lastPing = -1
	h := sha256.Sum256([]byte(rv.id))
	rv.hashedname = fmt.Sprintf("%x", h)
	rv.outQueue = make(chan string, 10)
	rv.channels = make(map[string]*ircchannel)
	addr := strings.Split(rv.id, ":")
	rv.hostname = "unknown"
	if len(addr) >= 1 {
		hosts, err := net.LookupAddr(addr[0])
		if err == nil {
			rv.hostname = hosts[0]
		}
	}
	return rv
}
func (self *ircclient) String() string {
	return fmt.Sprintf("<Client: %s!%s@%s>",
		self.username, self.realname, self.id)
}
func (self *ircclient) Kill(errormsg string, args ...interface{}) {
	if len(args) > 0 {
		errormsg = fmt.Sprintf(errormsg, args...)
	}
	self.done = true
	self.doneMessage = errormsg
	self.registered = false
	if self.pingTimer != nil {
		self.pingTimer.Stop()
	}
	self.conn.Close()
	self.log("%s killed with: %s", self.getIdent(), strconv.QuoteToASCII(errormsg))
	self.outQueue <- "" //make sure writeIO wakes up
}
func (self *ircclient) getIdent() string {
	return fmt.Sprintf("%s!%s@%s", self.nickname, self.username, self.hashedname[0:32])
}
func (self *ircclient) behavesBad() {
	const badLimit = 4
	self.badBehavior++
	if self.badBehavior > badLimit {
		self.Kill("misbehaving client")
	}
}
func (self *ircclient) onRegistered() {
	if self.registered == true {
		return
	}
	if pwd := self.server.config.Get("password"); self.
		server.config.IsSet("password") && len(pwd.String()) > 0 {
		if self.password != pwd.String() {
			self.numericReply(irc.ERR_ALREADYREGISTRED)
			self.Kill("invalid password: %v", self.password)
			return
		}
	}
	self.registered = true
	self.log("registered user %s", self.getIdent())
	self.numericReply(irc.RPL_WELCOME, self.nickname)
	self.numericReply(irc.RPL_YOURHOST, self.server.servername,
		fmt.Sprintf("gosch %s", self.server.version))
	self.numericReply(irc.RPL_CREATED, self.server.created.Format(time.RFC3339))
	self.numericReply(irc.RPL_MYINFO, self.server.servername, self.server.version, "i", "i")
	//LUSER response  (pidgin needs this)
	self.numericReply(irc.RPL_LUSERCLIENT, len(self.server.clients), 0)
	self.numericReply(irc.RPL_LUSEROP, 0)
	self.numericReply(irc.RPL_LUSERUNKOWN, 0)
	self.numericReply(irc.RPL_LUSERCHANNELS, len(self.server.channels))
	self.numericReply(irc.RPL_LUSERME, len(self.server.clients))
	go self.onTimeout()
}

func (self *ircclient) onTimeout() {
	// keep client alive
	timeout := self.server.config.GetInt("client-timeout")
	if timeout == -1 {
		panic("Invalid timeout config read")
	}
	for !self.done {
		self.pingTimer = time.NewTimer(time.Second)
		select {
		case now := <-self.pingTimer.C:
			dp := now.Unix() - self.lastPing
			if self.lastPing > 0 && dp >= int64(timeout) {
				self.Kill("Ping timeout t=%d", dp)
			}
			da := now.Unix() - self.lastActivity
			if da >= timeout {
				self.lastPing = time.Now().Unix()
				self.send("PING %d", self.lastPing)
			}
		}
	}
}
func (self *ircclient) log(msg string, args ...interface{}) {
	self.server.log("[%s] %s", self.id, fmt.Sprintf(msg, args...))
}
func (self *ircclient) debug(msg string, args ...interface{}) {
	self.server.debug("[%s] %s", self.id, fmt.Sprintf(msg, args...))
}
func (self *ircclient) trace(msg string, args ...interface{}) {
	self.server.trace("[%s] %s", self.id, fmt.Sprintf(msg, args...))
}
func (self *ircclient) trace2(msg string, args ...interface{}) {
	if self.server.config.DebugLevel > 2 {
		self.server.trace("[%s] %s", self.id, fmt.Sprintf(msg, args...))
	}
}
func (self *ircclient) handleChannelMode(msg *clientMessage) {
	//TODO implement modes:
	// i invite-only
	// m moderated
	// s secret
	// b banmask
	// e exception mask
	// I invitation mask
	tgt := msg.First()
	if tgt == nil || !irc.IsChannelName(*tgt) {
		panic(errors.New(fmt.Sprintf("trying to set a channel mode on bad channel name: %v", tgt)))
	}
	ch := self.server.getChannel(*tgt)
	if ch == nil || !ch.IsMember(msg.source) {
		self.numericReply(irc.ERR_USERNOTINCHANNEL, msg.source.nickname, *tgt)
		return
	}
	args := msg.Parameters()[1:]
	if len(args) < 1 {
		self.numericReply(irc.ERR_NEEDMOREPARAMS, msg.Command())
		return
	}
	//parsing modes
	// simple query, single char
	// might be something like: MODE +mb *@192.168.0
	if len(args) == 1 {
		if len(args[0]) == 1 {
			switch args[0][0] {
			case 'I':
				//invitation list
				self.numericReply(irc.RPL_ENDOFINVITELIST, *tgt)
				return
			case 'O':
				//channel creator
				op := ch.GetCreator()
				if op != nil {
					self.numericReply(irc.RPL_UNIQOPIS, *tgt, op.nickname)
					return
				}
			case 'e':
				//exception list
				self.numericReply(irc.RPL_ENDOFEXCEPTLIST, *tgt)
				return
			}
		}
	} else {
		self.numericReply(irc.RPL_CHANNELMODEIS, *tgt, ch.GetMode(), "") //TODO might add parameters here?
	}
}
func (self *ircclient) setMode(mod rune) {
	// add mode flag
	self.mode += string(mod)
}
func (self *ircclient) clearMode(mod rune) {
	var tmp string
	for _, t := range self.mode {
		if t != mod {
			tmp += string(t)
		}
	}
	self.mode = tmp
}
func (self *ircclient) testMode(mod rune) bool {
	for _, t := range self.mode {
		if t == mod {
			return true
		}
	}
	return false
}
func (self *ircclient) IsAway() bool {
	return self.testMode('a')
}
func (self *ircclient) IsOperator() bool {
	return self.testMode('o')
}
func (self *ircclient) IsInvisible() bool {
	return self.testMode('o')
}
func (self *ircclient) handleUserMode(msg *clientMessage) {
	tgt := msg.First()
	// User modes
	if *tgt != self.nickname {
		self.trace("invalid target in mode %v", msg)
		self.numericReply(irc.ERR_USERSDONTMATCH)
		return
	}
	if msg.NumParameters() == 2 { // MODE NICK +X
		c := msg.Parameters()[1] //the encoded mode string (+-)
		if len(c) > 1 && !irc.IsValidUserMode(rune(c[1])) {
			self.trace("invalid flag: %v", c)
			self.numericReply(irc.ERR_UMODEUNKNOWNFLAG)
			return
		}
		if len(c) == 2 {
			if c[0] == '+' {
				//set
				if irc.IsValidUserMode(rune(c[1])) && irc.UserMaySetUserMode(rune(c[1])) {
					self.setMode(rune(c[1]))
				}
			} else if c[0] == '-' && irc.UserMayClearMode(rune(c[1])) {
				//unset
				self.clearMode(rune(c[1]))
			}
		}
	}
	//get results
	self.numericReply(irc.RPL_UMODEIS, self.mode)
	return
}
func (self *ircclient) broadcastToChannel(msg *clientMessage) {
	//notify all peers in my channels
	for _, ch := range self.channels {
		self.server.deliverToChannel(&ch.name, msg)
	}
}
func (self *ircclient) handleMessage(msg *clientMessage) {
	//only handle NICK, PASS, USER, CAP for registration
	if msg == nil {
		return
	}
	defer func() {
		if r := recover(); r != nil {
			self.Kill("panic msg=%v err=%s", msg, r)
		}
		return
	}()
	self.trace2("msg=%v", msg)
	if !self.registered {
		switch cmd := *msg.Command(); cmd {
		case "CAP", "NICK", "USER", "PASS":
			//nop
		default:
			self.debug("[unregistered] received command %s",cmd)
			self.numericReply(irc.ERR_NOTREGISTERED)
			return
		}
	}
	switch cmd := *msg.Command(); cmd{
	case "CAP":
		//self.log("TODO implement capability negotiation")
	case "NICK":
		oldnick := self.nickname
		tgt := msg.First()
		if tgt == nil {
			self.numericReply(irc.ERR_NONICKNAMEGIVEN)
			return
		}
		for _, c := range *tgt {
			if !strconv.IsPrint(c) {
				self.numericReply(irc.ERR_ERRONEUSNICKNAME, *tgt)
				return
			}
		}
		if !self.server.registerNickname(*tgt, self) {
			self.numericReply(irc.ERR_NICKNAMEINUSE, *tgt)
			self.behavesBad()
			return
		}
		if self.registered {
			self.broadcastToChannel(self.makeMessage(":%s NICK %s", oldnick, self.nickname))
		} else {
			if len(self.username) > 0 && len(self.realname) > 0 {
				self.onRegistered()
			}
		}
	case "USER":
		if self.registered {
			self.numericReply(irc.ERR_ALREADYREGISTRED)
			return
		}
		if msg.NumParameters() != 4 { //user mode unused realname
			self.numericReply(irc.ERR_NEEDMOREPARAMS, *msg.Command())
			return
		}
		self.username = *msg.First()
		//hostname and servername ignored XXX
		self.realname = *msg.Last()
		if len(self.nickname) > 0 {
			self.onRegistered()
		}
	case "PASS":
		if msg.NumParameters() != 1 {
			self.numericReply(irc.ERR_NEEDMOREPARAMS, *msg.Command())
			return
		}
		self.password = *msg.First()
		self.trace("PASS=%v", *msg.First())
	case "PONG":
		param := msg.First()
		if param == nil {
			self.log("PONG without parameter received!")
			return
		}
		//check returned parameter
		tmp := fmt.Sprintf("%d", self.lastPing)
		if tmp != *param {
			self.log("PONG mismatch: lastping=%s received=%s", tmp, *param)
			return
		}
		self.lastPing = -1
		self.lastActivity = time.Now().Unix()
	case "PING":
		self.send(":%s PONG %s", self.server.servername, *msg.Last())
		return
	case "MODE":
		if msg.NumParameters() == 1 {
			self.numericReply(irc.RPL_UMODEIS, self.mode)
			return
		}
		tgt := msg.First()
		if tgt == nil || (*tgt != self.nickname && !irc.IsChannelName(*tgt)) {
			self.numericReply(irc.ERR_USERSDONTMATCH)
			return
		}
		if irc.IsChannelName(*tgt) {
			self.handleChannelMode(msg)
		} else {
			self.handleUserMode(msg)
		}
		return
	case "AWAY":
		if msg.NumParameters() == 0 {
			self.clearMode('a')
			self.numericReply(irc.RPL_UNAWAY)
		} else {
			self.setMode('a')
			self.awayMessage = *msg.Last()
			self.numericReply(irc.RPL_NOWAWAY)
		}
	case "USERHOST":
		if msg.NumParameters() < 1 || msg.NumParameters() > 5 {
			self.numericReply(irc.ERR_NEEDMOREPARAMS, *msg.Command())
			return
		}
		rv := strings.Builder{}
		for _, p := range msg.Parameters() {
			cl := self.server.findClientByNick(p)
			if cl == nil {
				continue
			}
			//TODO operator status "*"
			//output is nickname=+hostname
			rv.WriteString(cl.nickname)
			rv.WriteString("=")
			if cl.IsAway() {
				rv.WriteString("-")
			} else {
				rv.WriteString("+")
			}
			rv.WriteString(cl.hashedname[0:32])
			rv.WriteString(" ")
		}
		self.numericReply(irc.RPL_USERHOST, rv.String())
	case "JOIN":
		if msg.NumParameters() < 1 {
			self.numericReply(irc.ERR_NEEDMOREPARAMS, *msg.Command())
			return
		}
		tgts := strings.Split(msg.Parameters()[0], ",")
		var keys []string
		if msg.NumParameters() == 2 {
			keys = strings.Split(msg.Parameters()[1], ",")
		}
		for i := range tgts {
			var k string
			if i < len(keys) {
				k = keys[i]
			}
			self.server.joinChannel(tgts[i], k, self)
		}

	case "PART":
		if msg.NumParameters() < 1 {
			self.numericReply(irc.ERR_NEEDMOREPARAMS, *msg.Command())
			return
		}
		tgts := strings.Split(msg.Parameters()[0], ",")
		for _, tgt := range tgts {
			ch := self.server.getChannel(tgt)
			if ch == nil {
				self.numericReply(irc.ERR_NOSUCHCHANNEL, tgt)
				return
			}
			if !ch.IsMember(self) {
				self.numericReply(irc.ERR_NOTONCHANNEL, tgt)
				return
			}
			self.server.deliver(self.makeMessage(":%s PART %s :%s", self.getIdent(), tgt, msg.Last()))
			if !self.server.partChannel(tgt, self) {
				self.log("ERROR cannot part channel %s", tgt)
			}
		}
	case "PRIVMSG", "NOTICE":
		self.server.deliver(msg)
	case "QUIT":
		if msg.Prefix() != nil && len(*msg.Prefix()) > 0 {
			//check if client owns prefix TODO
			if *msg.Prefix() != self.getIdent() || *msg.Prefix() != self.nickname {
				self.trace("QUIT invalid prefix: %v", msg)
				return
			}
		}
		self.doneMessage = msg.ParameterString()
		self.send("ERROR :Good bye!")
		self.server.onDisconnect(self)
		self.Kill("quit %s", strconv.QuoteToASCII(msg.ParameterString()))
	case "WHO":
		if msg.NumParameters() < 1 {
			self.log("who without parameter received")
			return
		}
		mask := msg.First()
		if mask == nil {
			self.numericReply(irc.ERR_NEEDMOREPARAMS, "WHO")
			return
		}
		// TODO mask might be a glob, second parameter might be "o" flag
		if irc.IsChannelName(*mask) {
			ch := self.server.getChannel(*mask)
			if ch == nil {
				self.log("WHO on non existing channel: %v", msg)
				self.numericReply(irc.RPL_ENDOFWHO, *mask)
			} else {
				for _, cl := range ch.members {
					if cl == self {
						continue
					}
					mode := "H"
					if ch.IsOperator(cl) {
						mode += "@"
					}
					/*
					   fmt.Printf("%s\n", fmt.Sprintf(NumericMap[RPL_WHOREPLY], ch.name, cl.username,
					       cl.hashedname, self.servername, mode, cl.nickname, cl.realname))
					*/
					self.numericReply(irc.RPL_WHOREPLY, ch.name, cl.username,
						cl.hashedname, self.server.servername, cl.nickname, mode, cl.realname)
				}
			}
		} else {
			// TODO match against nick!user@host
			//cl := self.server.findClientByNick(*mask)
			//if cl != nil {
			//}
		}
		self.numericReply(irc.RPL_ENDOFWHO, *mask)
	case "WHOIS":
		if msg.NumParameters() > 2 {
			self.numericReply(irc.RPL_TRYAGAIN, "WHOIS")
			return
		}
		if msg.NumParameters() == 2 {
			self.numericReply(irc.ERR_NOSUCHSERVER, *msg.First())
			return
		}
		mask := msg.First()
		if mask == nil {
			self.numericReply(irc.ERR_NONICKNAMEGIVEN)
			return
		}
		//TODO -- for now only return a whois user and whoischannels
		cl := self.server.findClientByNick(*mask)
		if cl == nil {
			self.numericReply(irc.ERR_NOSUCHNICK, *mask)
			return
		}
		self.numericReply(irc.RPL_WHOISUSER, cl.nickname,
			cl.server.servername, cl.hashedname, cl.realname)
		var tmp strings.Builder
		for _, ch := range cl.channels {
			if ch.IsOperator(cl) {
				tmp.WriteString("@")
			} else if ch.IsVoice(cl) {
				tmp.WriteString("+")
			}
			tmp.WriteString(ch.name)
			tmp.WriteString(" ")
		}
		if len(tmp.String()) > 0 {
			self.numericReply(irc.RPL_WHOISCHANNELS, cl.nickname, tmp.String())
		}
		self.numericReply(irc.RPL_ENDOFWHOIS, cl.nickname)

	case "NAMES":
		tgt := msg.First()
		if tgt == nil {
			self.numericReply(irc.ERR_NEEDMOREPARAMS, "NAMES")
			return //no numeric given in RFC
		}
		if msg.NumParameters() == 2 {
			// channel+ target
		}
		for _, t := range strings.Split(*tgt, ",") {
			if len(t) > 0 {
				self.namReply(t)
			}
		}
	case "TOPIC":
		tgt := msg.First()
		if tgt == nil || !irc.IsChannelName(*tgt) || msg.NumParameters() < 1 {
			self.trace("TOPIC without enough parameters")
			self.numericReply(irc.ERR_NEEDMOREPARAMS, *msg.Command())
			return
		}
		ch := self.server.getChannel(*tgt)
		if ch == nil {
			self.trace("TOPIC cannot find channel %v", *tgt)
			self.numericReply(irc.RPL_NOTOPIC, *tgt)
			return
		}
		if !ch.IsMember(self) {
			self.trace("TOPIC not a member")
			self.numericReply(irc.ERR_NOTONCHANNEL, ch.name)
			return
		}
		hasTrailing := *msg.First() != *msg.Last()
		if !hasTrailing {
			self.numericReply(irc.RPL_TOPIC, ch.topicSetBy, ch.name, ch.topic)
			return
		}
		ch.topic = *msg.Last()
		ch.topicSetBy = self.nickname
		ch.topicSetOn = time.Now()
		tmp := fmt.Sprintf(irc.NumericMap[irc.RPL_TOPIC], ch.name, ch.topic)
		self.server.deliver(self.makeMessage(":%s %s %s %s", self.getIdent(),
			irc.RPL_TOPIC.String(), self.nickname, tmp))
		tmp = fmt.Sprintf(irc.NumericMap[irc.RPL_TOPICWHOTIME], ch.name,
			self.nickname, ch.topicSetOn.Unix())
		self.server.deliver(self.makeMessage(":%s %s %s %s", self.getIdent(),
			irc.RPL_TOPICWHOTIME.String(), self.nickname, tmp))

	default:
		self.log("unknown msg <- %v", msg)
	}
}
func (self *ircclient) makeMessage(tmpl string, args ...interface{}) *clientMessage {
	msg, _ := irc.NewMessage(fmt.Sprintf(tmpl, args...))
	if msg == nil {
		return nil
	}
	return &clientMessage{msg, self}
}
func (self *ircclient) namReply(channel string) {
	ch := self.server.getChannel(channel)
	if ch == nil {
		return
	}
	// =, *, @ are prefixes for public, private, secret channels
	var users string
	needspc := false
	tmp := ch.GetMembers()
	self.trace("members=%v", tmp)
	for _, cl := range ch.GetMembers() {
		u := cl.nickname
		if len(u) > 0 {
			if needspc {
				users += " "
			}
			user_flags := ""
			if ch.IsOperator(cl) {
				user_flags = "@"
			} else if ch.IsVoice(cl) {
				user_flags = "+"
			}
			users += fmt.Sprintf("%s%s", user_flags, u)
			needspc = true
		}
	}
	self.numericReply(irc.RPL_NAMREPLY, "=", channel, users)
	self.numericReply(irc.RPL_ENDOFNAMES, channel)
}
func (self *ircclient) onJoin(channel string) {
	ch := self.server.getChannel(channel)
	self.trace("onJoin %v: %s (%s)", ch, self.id, self.nickname)
	if ch == nil {
		self.Kill("join on non-existing channel %s", channel)
		return
	}
	//self.send(":%s JOIN %s", self.getIdent(), channel)
	self.server.deliver(self.makeMessage(":%s JOIN %s ", self.getIdent(), channel))
	self.namReply(channel)
	if len(ch.topic) < 1 {
		self.numericReply(irc.RPL_NOTOPIC, channel)
	} else {
		self.numericReply(irc.RPL_TOPIC, channel, ch.topic)
	}
	if ch.IsOperator(self) {
		self.server.deliverToChannel(&ch.name,
			self.makeMessage(":%s MODE %s +o %s", self.server.servername, ch.name,
				self.nickname))
	}
}
func (self *ircclient) numericReply(num irc.NumericReply, args ...interface{}) {
	msg := ""
	if tmp, ok := irc.NumericMap[num]; ok {
		msg = tmp
		if len(args) > 0 {
			msg = fmt.Sprintf(msg, args...)
		}
	} else {
		self.log("numeric not in map: %d", num)
	}
	nick := self.nickname
	if !self.registered && num == irc.ERR_NICKNAMEINUSE {
		//nickname might be undefined
		nick = args[0].(string)
	}
	self.send(":%s %s %s %s", self.server.servername, num.String(), nick, msg)
}
func (self *ircclient) send(tmpl string, args ...interface{}) {
	if self.done {
		return
	}
	self.trace(tmpl, args...)
	self.outQueue <- fmt.Sprintf(tmpl, args...)
}
func (self *ircclient) Start() {
	go self.writeIO()
	go self.readIO()
}

func (self *ircclient) writeIO() {
	for self.done == false {
		select {
		case msg := <-self.outQueue:
			self.trace("writeIO: buffered %d available %d", self.connwriter.Buffered(), self.connwriter.Available())
			if msg == "" {
				continue
			}
			if !strings.HasSuffix(msg, "\r\n") {
				msg += "\r\n"
			}
			n, err := self.connwriter.WriteString(msg)
			if err != nil {
				self.Kill("write error: %v", err)
			}
			if n != len(msg) {
				self.Kill("short write %d != %d", n, len(msg))
			}
			if err = self.connwriter.Flush(); err != nil {
				self.Kill("flush failed: %s", err)
			}
			//TODO this might contain PRIVMSG: self.trace("Sent %s %s %s ...", *tmp.Prefix(), *tmp.Command(), *tmp.First())
			self.lastActivity = time.Now().Unix()
		}
	}
	self.server.cleanup(false)
}
func (self *ircclient) readIO() {
	scanner := bufio.NewScanner(self.conn)
	self.connwriter = bufio.NewWriter(self.conn)
	crlnSplit := func(data []byte, atEOF bool) (advance int, token []byte, err error) {
		//tested with pidgin, irssi and konversation -- konversation is broken, sends LN without CR
		const sep = byte('\n')
		idx := bytes.IndexByte(data, sep)
		if len(data) == 0 {
			return 0, nil, nil
		}
		if idx == -1 {
			return len(data),
				nil,
				errors.New(fmt.Sprintf("no LN separator in data: %s", strconv.QuoteToASCII(string(data))))
		}
		advance = idx + 1
		if idx > 0 && data[idx-1] == byte('\r') {
			idx = idx - 1 //skip \r
		} else {
			self.isBroken = true
		}
		token = data[0:idx]
		err = nil
		//fmt.Printf("idx = %d\n", idx)
		return advance, token, err
	}
	scanner.Split(crlnSplit)
	for !self.done {
		self.log("connect from %s [%s]", self.id, self.hostname)
		for scanner.Scan() {
			msg, err := irc.NewMessage(scanner.Text())
			if err != nil {
				self.Kill("invalid irc-message: %v", err)
				break
			}
			self.handleMessage(&clientMessage{msg, self})
		}
		if scanner.Err() != nil {
			self.log("got error while reading from client: %v", scanner.Err())
		}
		//read done
		if !self.done {
			self.Kill("readIO done")
		}
	}
}
