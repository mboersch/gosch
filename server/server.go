//Copyright (C) 2019  Marius Boerschig <code (at) boerschig (dot) net>
package server
import (
    . "gosch/irc"
    "gosch/util"
    "crypto/tls"
    "fmt"
    "flag"
    "log"
    "os"
    "net"
    "strconv"
    "time"
    "sync"
)
type config struct {
    //config
    address  string
    port     string
    certfile string
    doSelfsigned bool
    password string
    maxChannels uint
}
type ircError struct {
    code int
    msg string
}
func (err ircError) Error() string {
    return fmt.Sprintf("IRC-ERROR: %d: %s", err.code, err.msg)
}
func isNumeric (reply string) bool {
    if _, err := strconv.Atoi(reply); err == nil {
        return true
    }
    return false
}

/////////////////////////////////////////////
// ircd
type ircd struct {
    config config
    logger    *log.Logger
    channels map[string]*ircchannel
    clients map[string]*ircclient
    mutex sync.Mutex
    created time.Time
    version string
    debugLevel int
    servername string
}

func (self *ircd) trace(msg string, args ...interface{}) {
    if self.debugLevel > 2 {
        self.log(fmt.Sprintf("[TRACE] %s", fmt.Sprintf(msg, args...)))
    }
}
func (self *ircd) debug(msg string, args ...interface{}) {
    if self.debugLevel > 0 {
        self.log(fmt.Sprintf("[DEBUG] %s", fmt.Sprintf(msg, args...)))
    }
}
func (self *ircd) log(msg string, args ...interface{}) {
    if self.logger == nil {
        fmt.Printf(msg, args...)
        return
    }
    self.logger.Printf("%s", fmt.Sprintf(msg, args...))
}

func (self *ircd) usage(msg string ) {
    flag.PrintDefaults()
    os.Stderr.WriteString(fmt.Sprintf("ERROR: %s\n", msg))
}
func (self *ircd) parseArgs() error {
    flag.StringVar(&self.config.port, "port", "6697", "specify the port number to listen on")
    flag.StringVar(&self.config.address, "address", "localhost", "specify the internet address to listen on")
    flag.StringVar(&self.config.certfile, "certfile", "", "specify the ssl PEM certificate to use for TLS server")
    flag.StringVar(&self.config.password, "pass", "", "specify the connection password")
    flag.UintVar(&self.config.maxChannels, "maxchannels", 16, "maximum number of channels a user can join")
    flag.BoolVar(&self.config.doSelfsigned, "selfsigned", false, "use openssl commands to generate a selfsigned certificate use (development use only)")
    var dbg, trace bool
    flag.BoolVar(&dbg, "d", false, "set debug level")
    flag.BoolVar(&trace, "t",  false,"should be -ddd but flags package sucks badly (TODO getopt)")
	flag.Parse()
    tmp, err := strconv.Atoi(self.config.port)
    if err != nil  || tmp > int(^uint16(0)) {
        self.usage("the specified port is invalid")
        return ircError{-1, "invalid port"}
    }
    if len(self.config.certfile) < 1 {
        self.usage("please specify a certificate file. Or use '-selfsigned' to generate one")
        return  ircError{-2, "invalid cert file"}
    }
    _ , err = os.Stat(self.config.certfile)
    if os.IsNotExist(err) {
        if self.config.doSelfsigned {
            if err := util.MakeSelfSignedPemFile(self.config.address,
                        self.config.certfile); err != nil {
                self.log("cannot make self signed cert: %s\n", err)
                return ircError{-3, "create self signed cert"}
            }
        } else {
            self.usage("the certfificate file does not exist")
            return ircError{-4, "cert does not exist"}
        }
    }
    if dbg {
        self.debugLevel  = 1
    }
    if trace {
        self.debugLevel = 3
    }
    return nil
}
func (self *ircd) getChannel(name string) (*ircchannel) {
    if ch, ok := self.channels[name]; ok {
        return ch
    }
    return nil
}
func (self *ircd) deliverToChannel(tgt *string, msg *ircmessage) {
    self.debug("delivering to %s: %v", *tgt , msg)
    ch := self.getChannel(*tgt)
    if ch == nil {
        self.debug("deliver: ignoring msg on non-existing channel %s", *tgt)
        return
    }
    if ! ch.isMember(msg.source.nickname) {
        self.debug("deliver: %s is not a member of %s", msg.source.nickname, *tgt)
        msg.source.numericReply(ERR_CANNOTSENDTOCHAN, ch.name)
        return
    }
    self.trace("deliver ch=%v, members=%v", ch, ch.members)
    for _, client := range ch.members {
        if client == msg.source {
            if msg.command == "PRIVMSG" || msg.command == "NOTICE"  {
                continue
            }
            if msg.command =="QUIT" {
                self.log("skipping client=%v msg=%v", client.id, msg)
                continue
            }
        }
        self.log("XXX Sending %s %v", client.id, msg)
        client.outQueue <- msg.GetRaw()
    }
    return
}
func (self *ircd) deliver(msg *ircmessage) {
    //disseminate the client message, e.g. from client to channel etc
    //channels multiplex: JOIN, MODE, KICK, PART, QUIT, PRIVMSG/NOTICE
    //TODO NOTICE must not send any error replies
    self.trace("enter msg=%v", msg)
    msg.prefix = msg.source.getIdent()
    switch msg.command {
    case "JOIN", "PART", "KICK", "MODE", "QUIT", "PRIVMSG", "NOTICE":
        // XXX locking channels/members ?
        if msg.NumParameters()> 0 {
            tgt := msg.FirstParameter()
            // :prefix CMD #target
            //self.log("tgt=%v, validChannelName=%v", tgt, IsChannelName(tgt))
            if IsChannelName(*tgt) {
                self.deliverToChannel(tgt, msg)
            } else {
                // :prefix CMD nick/ident
                //must be client/user
                //TODO <msgtarget> might be a hostmask ("*.foobar") for OP
                if msg.command != "PRIVMSG" &&  msg.command != "NOTICE" {
                    self.log("ERROR: got directed message that is not privmsg/notice!: %v", msg)
                    return
                }
                if len(msg.trailing) < 1 {
                    msg.source.numericReply(ERR_NOTEXTTOSEND)
                    return
                }
                cl := self.findClientByNick(*tgt)
                if cl == nil {
                    msg.source.numericReply(ERR_NOSUCHNICK, *tgt)
                    return
                }
                cl.outQueue <- msg.GetRaw()
            }
        } else {
            // :prefix CMD :trailing, only interesting for the current client?
            msg.source.outQueue <- msg.GetRaw()
        }
    case string(RPL_TOPIC), string(RPL_TOPICWHOTIME):
        if len(msg.parameters) >= 2 {
            if IsChannelName(msg.parameters[1]) {
                self.deliverToChannel(&msg.parameters[1], msg)
            } else if cl := self.findClientByNick(msg.parameters[1]); cl != nil {
                cl.outQueue <- msg.GetRaw()
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
func NewServer() *ircd {
    rv := new(ircd)
    rv.version = "Gosch IRC 19.6"
    rv.created = time.Now()
    rv.logger  = log.New(os.Stdout, "ircd ", log.LstdFlags)
    if err := rv.parseArgs(); err != nil {
        rv.log("ERROR: %s", err)
        return nil
    }
    rv.clients = make(map[string]*ircclient)
    rv.channels = make(map[string]*ircchannel)
    return rv
}
func (self *ircd) addClient(client *ircclient) {
    self.mutex.Lock()
    defer self.mutex.Unlock()
    self.clients[client.id] = client
}
func (self *ircd) onDisconnect(client *ircclient) error {
    // send quit message to all channels
    for _, ch := range client.channels {
        self.trace("onDisconnect: removing from %v members=%v", ch.name, ch.members)
        if len(ch.members) > 0 {
            self.deliverToChannel(&ch.name,
                client.makeMessage(":%s QUIT %s :%s", client.getIdent(), ch.name, client.doneMessage))
        }
        ch.RemoveClient(client)
    }
    return nil
}
func (self *ircd) cleanup() {
    self.mutex.Lock()
    defer self.mutex.Unlock()

    for _, cl := range self.clients {
        if cl.done {
            self.log("[%s] disconnected", cl.id)
            self.onDisconnect(cl)
        }
    }
}
func (self *ircd) Run() {
    crt, err := tls.LoadX509KeyPair(self.config.certfile, self.config.certfile)
    if err != nil {
        self.log("Cannot load cert/key pair: %s", err)
        return
    }
    cfg := &tls.Config{Certificates: []tls.Certificate{crt}}



    host := self.config.address
    myhost, err := os.Hostname()
    if err != nil  {
        self.log("cannot get hostname: %s", err)
        myhost = self.config.address //back to default
    }
    self.log("hostname: %s", myhost)
    if  host == myhost {
        host = "" //listen to all
    }
    addr := fmt.Sprintf("%s:%s", host, self.config.port)
    l, err := net.Listen("tcp", addr)
    if err != nil {
        self.log("Cannot create listening socket on  %s", addr)
        return
    }
    defer l.Close()
    self.log("Listening on %s", l.Addr())

    self.servername = myhost
    hostnames, err := net.LookupHost(myhost)
    if err != nil {
        self.servername = hostnames[0]
    }

    for {
        cl, err :=  l.Accept()
        if err != nil {
            self.log("ERROR: cannot accept client %v", err)
            continue
        }
        tlsconn := tls.Server(cl, cfg)
        client := NewClient(tlsconn, self)
        client.Start()
        self.addClient(client)
    }
}

func (self *ircd) joinChannel(channel, key string, client *ircclient){
    //TODO key/password checks
    self.mutex.Lock()
    defer self.mutex.Unlock()
    ch := self.getChannel(channel)
    if ch ==  nil {
        //does not exist yet
        ch = NewChannel(channel)
        self.channels[ch.name] = ch
    }
    ch.AddClient(client)
    client.onJoin(channel)
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
    cl := self.findClientByNick(nick)
    if cl != nil {
        if cl != client {
            //some other client has the nick
            self.trace("%v wants %s which is taken by %v", client.id, nick, cl.id)
            return false
        }
    }
    client.nickname = nick
    return true
}
