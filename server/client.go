// Copyright (c) Marius Börschig. All rights reserved.
// Licensed under the BSD-3-Clause License.
package server
import (
    . "github.com/mboersch/gosch/irc"
    "fmt"
    "net"
    "bufio"
    "time"
    "crypto/sha256"
    "strconv"
    "strings"
    "bytes"
)
type ircclient struct {
    server *ircd
    channels map[string]*ircchannel
    // IO
    conn net.Conn
    connwriter *bufio.Writer
    outQueue chan string
    // state
    registered bool
    done bool
    doneMessage string
    nickname, username, realname string
    id string //for logging/handling
    lastActivity int64
    lastPing int64
    pingTimer *time.Timer
    permissions string
    password string
    hostname string
    hashedname string
    mode string
    isBroken bool
    badBehavior int
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
    rv.outQueue = make(chan string)
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
func (self *ircclient) Kill(errormsg string) {
    self.done = true
    self.doneMessage = errormsg
    self.registered = false
    if self.pingTimer != nil {
        self.pingTimer.Stop()
    }
    self.conn.Close()
    self.log("%s killed with %s", self.getIdent(), strconv.QuoteToASCII(errormsg))
    self.outQueue <- "" //make sure writeIO wakes up
}
func (self *ircclient) getIdent() string {
    return fmt.Sprintf("%s!%s@%s", self.nickname, self.username, self.hashedname[0:32])
}
func (self *ircclient) behavesBad() {
    const badLimit = 4
    self.badBehavior ++
    if self.badBehavior > badLimit {
        self.Kill("misbehaving client")
    }
}
func (self *ircclient) onRegistered() {
    if self.registered == true {
        return
    }
    if len(self.server.config.password) > 0 {
        if self.password != self.server.config.password {
            self.numericReply(ERR_ALREADYREGISTRED)
            self.log("invalid password: %v", self.password)
            self.Kill("invalid password")
            return
        }
    }
    self.registered = true
    self.log("registered user %s", self.getIdent())
    self.numericReply(RPL_WELCOME, self.nickname)
    self.numericReply(RPL_YOURHOST, self.server.servername,
            fmt.Sprintf("gosch %s", self.server.version))
    self.numericReply(RPL_CREATED, self.server.created.Format(time.RFC3339))
    self.numericReply(RPL_MYINFO, self.server.servername, self.server.version, "i", "i")
    //LUSER response  (pidgin needs this)
    self.numericReply(RPL_LUSERCLIENT, len(self.server.clients), 0)
    self.numericReply(RPL_LUSEROP, 0)
    self.numericReply(RPL_LUSERUNKOWN, 0)
    self.numericReply(RPL_LUSERCHANNELS,len(self.server.channels))
    self.numericReply(RPL_LUSERME, len(self.server.clients))
    go self.onTimeout()
}

func (self *ircclient) onTimeout() {
    // keep client alive
    for ! self.done {
        self.pingTimer = time.NewTimer(time.Second)
        select {
        case now := <-self.pingTimer.C:
            dp := now.Unix() - self.lastPing
            if self.lastPing > 0  && dp >= int64(self.server.config.timeout) {
                self.log("Ping timeout t=%d", dp)
                self.Kill("Ping timeout")
            }
            da := now.Unix() - self.lastActivity
            if da >= int64(self.server.config.timeout) {
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
    if self.server.debugLevel > 2 {
        self.server.trace("[%s] %s", self.id, fmt.Sprintf(msg, args...))
    }
}
func (self *ircclient) handleMessage(msg *ircmessage) {
    //only handle NICK, PASS, USER, CAP for registration
    if msg == nil {
        return
    }
    defer func() {
        if r:= recover(); r != nil {
            self.log("handleMessage: recovered from panic: msg=%v", msg)
        }
        return
    }()
    self.trace2("msg=%v",msg)
    msg.source = self
    if ! self.registered {
        switch msg.command {
        case "CAP","NICK","USER","PASS":
            //nop
        default:
            self.debug("[unregistered] received command %s", msg.command)
            return
        }
    }
    switch msg.command {
    case "CAP":
        //self.log("TODO implement capability negotiation")
    case "NICK":
        tgt := msg.FirstParameter()
        if tgt == nil {
            self.numericReply(ERR_ERRONEUSNICKNAME)
            return
        }
        for _,c := range *tgt {
            if ! strconv.IsPrint(c) {
                self.numericReply(ERR_ERRONEUSNICKNAME, *tgt)
                return
            }
        }
        if !self.server.registerNickname(*tgt, self) {
            self.numericReply(ERR_NICKNAMEINUSE, *tgt)
            self.behavesBad()
            return
        }
        if len(self.username)  >0 && len(self.realname) > 0 {
            self.onRegistered()
        }
    case "USER":
        if self.registered {
            self.numericReply(ERR_ALREADYREGISTRED)
            return
        }
        if msg.NumParameters() != 4  { //user mode unused realname
            self.numericReply(ERR_NEEDMOREPARAMS, msg.command)
            return
        }
        self.username = *msg.FirstParameter()
        //hostname and servername ignored XXX
        self.realname = msg.trailing
        if len(self.nickname) > 0 {
            self.onRegistered()
        }
    case "PASS":
        if msg.NumParameters() !=  1 {
            self.numericReply(ERR_NEEDMOREPARAMS, msg.command)
            return
        }
        self.password = *msg.FirstParameter()
        self.trace("PASS=%v", *msg.FirstParameter())
    case "PONG":
        param := msg.FirstParameter()
        if param == nil {
            self.log("PONG without parameter received!")
            return
        }
        //check returned parameter
        tmp := fmt.Sprintf("%d", self.lastPing)
        if tmp != *param{
            self.log("PONG mismatch: lastping=%s received=%s", tmp, *param)
            return
        }
        self.lastPing = -1
        self.lastActivity = time.Now().Unix()
    case "PING":
        self.send(":%s PONG %s", self.server.servername, msg.trailing)
        return
    case "MODE":
        if msg.NumParameters() == 1 {
            self.numericReply(RPL_UMODEIS, self.mode)
            return
        }
        tgt := msg.FirstParameter()
        if tgt == nil || (*tgt != self.nickname && !IsChannelName(*tgt)) {
            self.numericReply(ERR_USERSDONTMATCH)
            return
        }
        for _, c := range msg.parameters[1:]{
            if IsChannelName(*tgt) {
                if len(c) > 1 && ! IsValidChannelMode(c[1]) {
                    self.numericReply(ERR_UNKNOWNMODE, string(c[1]), *tgt)
                    return
                }
                self.numericReply(ERR_NOCHANMODES, *tgt) //TODO implement modes
            } else {
                // User modes
                if len(c)  < 2 || ! IsValidUserMode(c[1]) {
                    self.numericReply(ERR_UMODEUNKNOWNFLAG)
                    return
                }
                if len(c) == 2 {
                    if c[0] == '+' {
                        //XXX not implemented modes
                        if IsValidUserMode(c[1]){
                            self.mode += string(c[1])
                        }
                    } else if c[0] ==  '-' {
                        var tmp string
                        for _, t := range self.mode {
                            if t != rune(c[1]) {
                                tmp += string(t)
                            }
                        }
                        self.mode = tmp
                    } else {
                        self.numericReply(ERR_UMODEUNKNOWNFLAG)
                        return
                    }
                }
            }
        }
        self.numericReply(RPL_UMODEIS, self.mode)
    case "USERHOST":
        if msg.NumParameters() < 1 || msg.NumParameters() > 5 {
            self.numericReply(ERR_NEEDMOREPARAMS, msg.command)
            return
        }
        rv := strings.Builder{}
        for _, p := range msg.parameters {
            cl := self.server.findClientByNick(p)
            if cl == nil { continue }
            //TODO operator status "*"
            //output is nickname=+hostname
            rv.WriteString(cl.nickname)
            rv.WriteString("=")
            if cl.isAway() { rv.WriteString("-") } else { rv.WriteString("+") }
            rv.WriteString(cl.hashedname[0:32])
            rv.WriteString(" ")
        }
        self.numericReply(RPL_USERHOST, rv.String())
    case "JOIN":
        if msg.NumParameters() < 1 {
            self.numericReply(ERR_NEEDMOREPARAMS, msg.command)
            return
        }
        tgts := strings.Split(msg.parameters[0], ",")
        var keys []string
        if msg.NumParameters() == 2 {
            keys = strings.Split(msg.parameters[1], ",")
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
            self.numericReply(ERR_NEEDMOREPARAMS, msg.command)
            return
        }
        tgts := strings.Split(msg.parameters[0], ",")
        for _, tgt := range tgts {
            if len(tgt) < 1  {
                self.numericReply(ERR_NOSUCHCHANNEL, tgt)
                return
            }
            ch := self.server.getChannel(tgt)
            if ch == nil {
                self.numericReply(ERR_NOSUCHCHANNEL, tgt)
                return
            }
            if ! ch.isMember(self.nickname) {
                self.numericReply(ERR_NOTONCHANNEL, tgt)
                return
            }
            self.server.deliver(self.makeMessage(":%s PART %s :%s", self.getIdent(), tgt, msg.trailing))
            if !self.server.partChannel(tgt, self) {
                self.log("ERROR cannot part channel %s", tgt)
            }
        }
    case "PRIVMSG", "NOTICE":
        self.server.deliver(msg)
    case "QUIT":
        if len(msg.prefix) > 0 {
            //check if client owns prefix TODO
            if msg.prefix != self.getIdent() || msg.prefix  != self.nickname {
                self.trace("QUIT invalid prefix: %v", msg)
                return
            }
        }
        self.doneMessage=msg.trailing
        self.server.onDisconnect(self)
        self.Kill(fmt.Sprintf("quit %s", strconv.QuoteToASCII(msg.trailing)))
    case "WHO":
        if msg.NumParameters() < 1 {
            self.log("who without parameter received")
            return
        }
        mask := msg.FirstParameter()
        if mask == nil {
            self.numericReply(ERR_NEEDMOREPARAMS, "WHO")
            return
        }
        // TODO mask might be a glob, second parameter might be "o" flag
        if IsChannelName(*mask) {
            ch := self.server.getChannel(*mask)
            if ch == nil {
                self.log("WHO on non existing channel: %v", msg)
                self.numericReply(RPL_ENDOFWHO, *mask)
            } else {
                for _, cl := range ch.members {
                    if cl == self{
                        continue
                    }
                    mode := "H"
                    if ch.isOperator(cl.nickname) {
                        mode += "@"
                    }
                    /*
                    fmt.Printf("%s\n", fmt.Sprintf(NumericMap[RPL_WHOREPLY], ch.name, cl.username,
                        cl.hashedname, self.servername, mode, cl.nickname, cl.realname))
                    */
                    self.numericReply(RPL_WHOREPLY, ch.name, cl.username,
                        cl.hashedname, self.server.servername, cl.nickname, mode, cl.realname)
                }
            }
        } else {
            // TODO match against nick!user@host
            //cl := self.server.findClientByNick(*mask)
            //if cl != nil {
            //}
        }
        self.numericReply(RPL_ENDOFWHO, *mask)
    case "WHOIS":
        if msg.NumParameters() > 2 {
            self.numericReply(RPL_TRYAGAIN,"WHOIS")
            return
        }
        if msg.NumParameters() == 2 {
            self.numericReply(ERR_NOSUCHSERVER, *msg.FirstParameter())
            return
        }
        mask := msg.FirstParameter()
        if mask == nil {
            self.numericReply(ERR_NONICKNAMEGIVEN)
            return
        }
        //TODO -- for now only return a whois user and whoischannels
        cl := self.server.findClientByNick(*mask)
        if cl == nil {
            self.numericReply(ERR_NOSUCHNICK, *mask)
            return
        }
        self.numericReply(RPL_WHOISUSER, cl.nickname,
            cl.server.servername, cl.hashedname, cl.realname)
        var tmp strings.Builder
        for _, ch := range cl.channels {
            //TODO + and @
            tmp.WriteString(ch.name)
            tmp.WriteString(" ")
        }
        if len(tmp.String()) > 0 {
            self.numericReply(RPL_WHOISCHANNELS, cl.nickname, tmp.String())
        }
        self.numericReply(RPL_ENDOFWHOIS, cl.nickname)

    case "NAMES":
        tgt := msg.FirstParameter()
        if tgt == nil {
            self.numericReply(ERR_NEEDMOREPARAMS,"NAMES")
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
        tgt := msg.FirstParameter()
        if tgt == nil || !IsChannelName(*tgt) || msg.NumParameters() < 1 {
            self.trace("TOPIC without enough parameters")
            self.numericReply(ERR_NEEDMOREPARAMS, msg.command)
            return
        }
        ch := self.server.getChannel(*tgt)
        if ch == nil {
            self.trace("TOPIC cannot find channel %v", *tgt)
            self.numericReply(RPL_NOTOPIC, *tgt)
            return
        }
        if ! ch.isMember(self.nickname) {
            self.trace("TOPIC not a member")
            self.numericReply(ERR_NOTONCHANNEL, ch.name)
            return
        }
        if ! msg.hasTrailing {
            self.numericReply(RPL_TOPIC, ch.topicSetBy, ch.name, ch.topic)
            return
        }
        ch.topic = msg.trailing
        ch.topicSetBy = self.nickname
        ch.topicSetOn = time.Now()
        tmp := fmt.Sprintf(NumericMap[RPL_TOPIC], ch.name, ch.topic)
        self.server.deliver(self.makeMessage(":%s %s %s %s", self.getIdent(),
                RPL_TOPIC.String(), self.nickname, tmp))
        tmp = fmt.Sprintf(NumericMap[RPL_TOPICWHOTIME], ch.name,
            self.nickname, ch.topicSetOn.Unix())
        self.server.deliver(self.makeMessage(":%s %s %s %s", self.getIdent(),
            RPL_TOPICWHOTIME.String(), self.nickname, tmp))

    default:
        self.log("unknown msg <- %v", msg)
    }
}
func (self *ircclient) isAway() bool {
    return false //TODO implement me
}
func (self *ircclient) makeMessage(tmpl string, args ...interface{}) (*ircmessage) {
    msg, _ := ircParseMessage(fmt.Sprintf(tmpl, args...))
    if msg == nil {
        return nil
    }
    msg.source = self
    return msg
}
func (self *ircclient) namReply(channel string) {
    ch := self.server.getChannel(channel)
    if ch == nil {
        return
    }
    // =, *, @ are prefixes for public, private, secret channels
    var users string
    needspc := false
    for _,u := range ch.getNicks() {
        if len(u) > 0 {
            if needspc{
                users +=" "
            }
            user_flags := ch.getUserFlags(u)
            users += fmt.Sprintf("%s%s", user_flags, u)
            needspc = true
        }
    }
    self.numericReply(RPL_NAMREPLY, "=", channel, users)
    self.numericReply(RPL_ENDOFNAMES, channel)
}
func (self *ircclient) onJoin(channel string) {
    ch := self.server.getChannel(channel)
    self.trace("onJoin %v: %s (%s)", ch, self.id, self.nickname)
    if ch == nil {
        self.log("cannot get channel %s", channel)
        self.Kill("join on non-existing channel")
        return
    }
    //self.send(":%s JOIN %s", self.getIdent(), channel)
    self.server.deliver(self.makeMessage(":%s JOIN %s ", self.getIdent(), channel))
    self.namReply(channel)
    if len(ch.topic) < 1 {
        self.numericReply(RPL_NOTOPIC, channel)
    } else {
        self.numericReply(RPL_TOPIC, channel, ch.topic)
    }
}
func (self *ircclient) numericReply(num NumericReply, args ...interface{}) {
    //TODO XXX
    // should look like :localhost 001 marius :Welcom fooba ?
    msg := ""
    if tmp, ok := NumericMap[num]; ok {
        msg = tmp
        if len(args) > 0  {
            msg = fmt.Sprintf(msg, args...)
        }
    } else {
        self.log("numeric not in map: %d", num)
    }
    self.send(":%s %s %s %s", self.server.servername, num.String(), self.nickname, msg)
}
func (self *ircclient) send(tmpl string, args ...interface{}) {
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
            if msg == "" {
                continue
            }
            if !strings.HasSuffix(msg, "\r\n") {
                msg += "\r\n"
            }
            n, err := self.connwriter.WriteString(msg)
            if err != nil {
                self.log("error writing: %s",msg)
                self.Kill(fmt.Sprintf("write error: %v", err))
            }
            if n != len(msg) {
                self.log("short write %d != %d", n, len(msg))
                self.Kill("short write")
            }
            if err = self.connwriter.Flush(); err != nil {
                self.log("send flush failed: %s", err)
                return
            }
            self.trace("Sent %s", strconv.QuoteToASCII(msg))
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
        const sep =  byte('\n')
        idx := bytes.IndexByte(data, sep)
        if len(data) == 0 {
            return 0, nil, nil
        }
        if idx == -1 {
            return len(data), nil, ircError{-1,
                    fmt.Sprintf("no LN separator in data: %s",
                            strconv.QuoteToASCII(string(data))) }
        }
        advance = idx+1
        if idx > 0  && data[idx-1] == byte('\r') {
            idx = idx -1  //skip \r
        } else {
            self.isBroken = true
        }
        token = data[0:idx]
        err = nil
        //fmt.Printf("idx = %d\n", idx)
        return advance,token, err
    }
    scanner.Split(crlnSplit)
    for ! self.done {
        self.log("connect from %s [%s]", self.id, self.hostname)
        for scanner.Scan() {
            msg, err := ircParseMessage(scanner.Text())
            if err != nil {
                self.log("<- cannot parse message: %v", err)
                self.Kill("invalid irc-message")
                break
            }
            self.handleMessage(msg)
        }
        if scanner.Err() != nil {
            self.log("got error while reading from client: %v", scanner.Err())
        }
        //read done
        if ! self.done {
            self.Kill("IO done")
        }
    }
}
