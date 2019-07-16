// Copyright (c) Marius Börschig. All rights reserved.
// Licensed under the BSD-3-Clause License.
package server
import (
    . "github.com/mboersch/gosch/irc"
    "github.com/mboersch/gosch/util"
    "crypto/tls"
    "fmt"
    "flag"
    "os"
    "os/signal"
    "net"
    "strconv"
    "time"
    "sync"
    "errors"
)
type config struct {
    //config
    address  string
    port     string
    certfile string
    doSelfsigned bool
    password string
    maxChannels uint
    timeout uint
    logfile string
    sysuser, sysgroup string
    pidfile string
    isDaemon bool
}
const (
    SERVER_VERSION string = "0.0.1"
)
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
    logger    util.Logger
    channels map[string]*ircchannel
    clients map[string]*ircclient
    mutex sync.Mutex
    created time.Time
    version string
    debugLevel int
    servername string
    listenSock  net.Listener
    isRunning bool
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
func (self *ircd) fatal(msg string, args ...interface{}){
    if self.logger == nil {
        fmt.Printf(msg, args...)
        return
    }
    self.logger.Error(msg, args...)
}
func (self *ircd) usage(msg string ) {
    flag.PrintDefaults()
    os.Stderr.WriteString(fmt.Sprintf("ERROR: %s\n", msg))
}
func (self *ircd) parseArgs(args []string) error {
    DebugFlagLoop:
    for k, arg := range args {
        if len(arg)>= 2 && arg[0] == '-' && arg[1] == 'd' {
            c := 1
            for i:= 2; i< len(arg); i++ {
                if arg[i] != 'd' {
                    break DebugFlagLoop
                }
                c ++
            }
            self.debugLevel = c
            //remove -d+ from args
            args = append(args[:k], args[k+1:]...)
            self.logger.SetLogLevel(util.LogLevel(self.debugLevel))
            break
        }
    }
    cmd := flag.NewFlagSet("gosch", flag.ContinueOnError)
    cmd.Usage = func()  {
        fmt.Printf("gosch version %v -- Usage:\n", self.version)
        cmd.PrintDefaults()
    }
    cmd.StringVar(&self.config.port, "port", "6697", "specify the port number to listen on")
    cmd.StringVar(&self.config.address, "address", "localhost", "specify the internet address or hostname to listen on")
    cmd.StringVar(&self.config.certfile, "certfile", "",
            "specify the ssl PEM certificate/key to use for TLS server")
    cmd.StringVar(&self.config.password, "password", "", "specify the connection password")
    cmd.UintVar(&self.config.maxChannels, "maxchannels", 8, "maximum number of channels a user can join")
    cmd.UintVar(&self.config.timeout, "clienttimeout", 60, "idle client timeout in seconds")
    cmd.BoolVar(&self.config.doSelfsigned, "selfsigned", false, "create a selfsigned certificate use (development use only)")
    cmd.StringVar(&self.config.logfile, "logfile", "", "log to specified file")
    cmd.StringVar(&self.config.sysgroup, "group", "", "change to this OS group before serving requests")
    cmd.StringVar(&self.config.sysuser, "user", "", "change to this OS user before serving requests")
    cmd.StringVar(&self.config.pidfile, "pidfile", "", "write the process ID to this file")
    cmd.BoolVar(&self.config.isDaemon, "daemon", false, "give up controlling terminal and serve in background")
    //dummy
    cmd.Bool("d", false, "set verbosity level (use -dd.. to increase debug level)")
    err := cmd.Parse(args)
    if err != nil {
        return err
    }
    if cmd.NArg() > 0 {
        cmd.PrintDefaults()
        fmt.Printf("ERROR: additional unknown arguments: %v\n", cmd.Args())
        return errors.New("unkown arguments")
    }
    if self.config.isDaemon {
        //Experimental: forkexec does not work and C.daemon() does something bad
        //remove --daemon from flags, and forkexec ourselves
        cmdargs := make([]string, cmd.NFlag()+ cmd.NArg() + 1)
        cmdargs[0] = os.Args[0]
        cmd.Visit(func(flg *flag.Flag) {
            if flg.Name != "daemon" {
                cmdargs = append(cmdargs, fmt.Sprintf("--%s %v", flg.Name, flg.Value))
            }
        })
        if cmd.NArg() > 0 {
            cmdargs = append(cmdargs, cmd.Args()...)
        }
        self.log("going to background")
        err = util.CDaemonize()
        if err != nil {
            self.log("error going to background: %s", err)
            os.Exit(-1)
        }
    }
    if len(self.config.logfile) > 0 {
        fd, err := os.OpenFile(self.config.logfile, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0600)
        if err != nil {
            panic(err)
        }
        self.logger.AddSink(fd)
    }
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
            self.log("creating self signed tls certificate")
            if err := util.MakeSelfSignedPemFile(self.config.certfile); err != nil {
                self.log("cannot make self signed cert: %s\n", err)
                return ircError{-3, "create self signed cert"}
            }
        } else {
            self.usage("the certfificate file does not exist")
            return ircError{-4, "cert does not exist"}
        }
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
    if ! ch.isMember(msg.source) {
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
                self.trace("skipping client=%v msg=%v", client.id, msg)
                continue
            }
        }
        self.trace("Sending %s %v", client.id, msg)
        client.outQueue <- msg.GetRaw()
    }
    return
}
func (self *ircd) deliver(msg *ircmessage) {
    //disseminate the client message, e.g. from client to channel etc
    //channels multiplex: JOIN, MODE, KICK, PART, QUIT, PRIVMSG/NOTICE
    //TODO NOTICE must not send any error replies
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
                if msg.NumParameters() < 2 {
                    msg.source.numericReply(ERR_NOTEXTTOSEND)
                    return
                }
                cl := self.findClientByNick(*tgt)
                if cl == nil {
                    msg.source.numericReply(ERR_NOSUCHNICK, *tgt)
                    return
                }
                if cl.isAway() {
                    msg.source.numericReply(RPL_AWAY, cl.nickname, cl.awayMessage)
                }
                cl.outQueue <- msg.GetRaw()
            }
        } else {
            // :prefix CMD :trailing, only interesting for the current client?
            msg.source.outQueue <- msg.GetRaw()
        }
    case RPL_TOPIC.String(), RPL_TOPICWHOTIME.String():
        if msg.NumParameters() >= 2 {
            if IsChannelName(msg.parameters[1]) {
                self.deliverToChannel(&msg.parameters[1], msg)
            } else if cl := self.findClientByNick(msg.parameters[1]); cl != nil {
                cl.outQueue <- msg.GetRaw()
            }
        }
    }
}
func (self *ircd) findClientByNick(nick string) *ircclient {
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
    rv.logger  = util.NewLogger("ircd")
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
        if ! ch.isMember(client) {
            self.fatal("sanity check failed: client %v is not a member of %v",
                client, ch)
        }
        self.trace("onDisconnect: removing from %v members=%v", ch.name, ch.members)
        if len(ch.members) > 0 {
            self.deliverToChannel(&ch.name,
                client.makeMessage(":%s QUIT :%s", client.getIdent(), client.doneMessage))
        }
        ch.RemoveClient(client)
    }
    return nil
}
func (self *ircd) cleanup(force bool) {
    self.mutex.Lock()
    defer self.mutex.Unlock()
    for _, cl := range self.clients {
        if force || cl.done {
            if force {
                cl.done = true
            }
            self.log("[%s] disconnected", cl.id)
            self.onDisconnect(cl)
        }
    }
}
func (self *ircd) handleSignals() {
    sigs := make(chan os.Signal, 1)
    signal.Notify(sigs, os.Interrupt, os.Kill)
    var nint int = 0
    go func() {
        for sig := range sigs {
            switch sig {
            case os.Interrupt, os.Kill:
                self.fatal("received signal %v. shutting down.", sig)
                self.Stop()
                nint ++
                if(nint > 1) {
                    os.Exit(1)
                }
            }
        }
    }()
}
func (self *ircd) Stop(){
    if ! self.isRunning {
        return
    }
    self.log("Stopping I/O")
    self.isRunning = false
    if self.listenSock != nil{
        _ = self.listenSock.Close()
    }
}
func (self *ircd) Run() {
    self.isRunning = true
    // setup ssl socket
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
    self.log("hostname: %s pid %v", myhost, os.Getpid())
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
    self.listenSock = l //saved for Stop() 
    self.log("Listening on %s", l.Addr())

    self.servername = myhost
    hostnames, err := net.LookupHost(myhost)
    if err != nil {
        self.servername = hostnames[0]
    }
    // handle network requests
    for {
        cl, err :=  l.Accept()
        if ! self.isRunning {
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
    self.cleanup(true)
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
    self.mutex.Lock()
    defer self.mutex.Unlock()
    self.debug("server: register nick %s for %v", nick, client.getIdent())
    cl := self.findClientByNick(nick)
    if cl != nil {
        if cl != client {
            //some other client has the nick
            self.trace("%v wants %s which is taken by %v", client.id, nick, cl.getIdent())
            return false
        }
    }
    client.nickname = nick
    return true
}
