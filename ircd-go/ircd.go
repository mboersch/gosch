package main
//author: Marius Boerschig <code (at) boerschig (dot) net>
//
import (
    "crypto/tls"
    "crypto/sha256"
    "strings"
    "fmt"
    "flag"
    "log"
    "os"
    "os/exec"
    "io/ioutil"
    "bufio"
    "bytes"
    "net"
    "strconv"
    "time"
    "sync"
)
const ( 
    irc_ping_timeout int64  = 5
    irc_valid_modes string = "iwoOrs" //obsolte: "s"
    irc_valid_channel_prefix string = "&#"
)
func isChannelName(in string) bool {
    for _, p := range irc_valid_channel_prefix {
        if strings.HasPrefix(in, string(p)) {
            return true
        }
    }
    return false
}
//Numeric Reply 
const (
    // registration / new client
    RPL_WELCOME = 001
    RPL_YOURHOST = 002
    RPL_CREATED = 003
    RPL_MYINFO = 004
    //RFC 2813 sys we SHALL send LUSERS on connect
    RPL_LUSERCLIENT = 251
    RPL_LUSEROP = 252
    RPL_LUSERUNKOWN = 253
    RPL_LUSERCHANNELS = 254
    RPL_LUSERME = 255
    // WHO
    RPL_WHOREPLY = 352
    RPL_ENDOFWHO = 315
    //Numeric Replies
    // NICK
    ERR_NONICKNAMEGIVEN = 431
    ERR_ERRONEUSNICKNAME = 432
    ERR_NICKNAMEINUSE = 433
    ERR_NICKCOLLISION = 436
    // USER
    ERR_NEEDMOREPARAMS = 461
    ERR_ALREADYREGISTRED = 462
    //MODE
    ERR_UMODEUNKNOWNFLAG = 501
    ERR_USERSDONTMATCH = 502
    RPL_UMODEIS = 221
    //JOIN
    ERR_CHANNELISFULL = 471
    ERR_INVITEONLYCHAN = 473
    ERR_BANNEDFROMCHAN = 474
    ERR_BADCHANNELKEY = 475
    ERR_BADCHANMASK = 476
    ERR_NOSUCHCHANNEL = 403
    ERR_TOOMANYCHANNELS = 405
    ERR_TOOMANYTARGETS = 407
    ERR_UNAVAILRESOURCE = 437
    RPL_NOTOPIC = 331
    RPL_TOPIC = 332
    RPL_NAMREPLY = 353
    // PART
    ERR_NOTONCHANNEL = 443
    // PRIVMSG
    ERR_CANNOTSENDTOCHAN = 404
    ERR_NORECIPIENT = 411
    ERR_NOTEXTTOSEND = 412
    ERR_NOTOPLEVEL = 413
    ERR_WILDTOPLEVEL=414
    ERR_NOSUCHNICK =  401
    ERR_NOSUCHSERVER =  402

)
var numericMap  = map[int]string{
    // registration
    RPL_WELCOME: ":Welcome to the Internet Relay Network %s", // nick!user@host
    RPL_YOURHOST: ":Your host is %s, running version %s", //servername, version
    RPL_CREATED: ":This server was created %s", //date
    RPL_MYINFO: ":%s %s %s %s", //servername version user_modes channel_modes
    RPL_LUSERCLIENT: ": There are %d users and %d services on 1 servers", //num(users), num(services)
    RPL_LUSEROP: "%d :operator(s) online",//num(operators)
    RPL_LUSERUNKOWN: "%d :unknown connection(s)", //num(unknown)
    RPL_LUSERCHANNELS: "%d :channels formed", // num(channels)
    RPL_LUSERME: ":I have %d clients and 1 servers", //num(clients)
    //NICK
    ERR_NONICKNAMEGIVEN: ":No nickname given",
    ERR_ERRONEUSNICKNAME: "%s :Erroneus nickname", //nick
    ERR_NICKNAMEINUSE: "%s :Nickname is already in use", //nick
    ERR_NICKCOLLISION: "%s :Nickname collision KILL", //nick
    // USER
    ERR_NEEDMOREPARAMS: "%s :Not enough parameters",
    ERR_ALREADYREGISTRED: ":You may not reregister",
    //MODE
    ERR_UMODEUNKNOWNFLAG : "Unknown MODE flag",
    ERR_USERSDONTMATCH : "Cannot change mode for other users",
    RPL_UMODEIS : "%s",
    //JOIN
    ERR_CHANNELISFULL: "%s :Cannot join channel (+l)", //channel
    ERR_INVITEONLYCHAN: "%s :Cannot join channel (+i)", //channel
    ERR_BANNEDFROMCHAN: "%s :Cannot join channel (+b)", //channel
    ERR_BADCHANNELKEY: "%s :Cannot join channel (+k)", //channel
    ERR_BADCHANMASK: "%s :Bad channel mask", //channel
    ERR_NOSUCHCHANNEL: "%s :No such channel", //channel
    ERR_TOOMANYCHANNELS: "%s :You have joined too many channels", //channel
    ERR_TOOMANYTARGETS: "%s :%d recipients. %s", //target, error_code, abort_message
    ERR_UNAVAILRESOURCE: "%s :Nick/channel is temporarily unvavailable", //nick/channel
    RPL_NOTOPIC: "%s :No topic set", //channel
    RPL_TOPIC: "%s :%s", //channel, topic
    RPL_NAMREPLY:  "%s %s :%s",  //symbol(=*@), (symboL)nick ...
    //PART
    ERR_NOTONCHANNEL: "%s :You're not on that channel", //channel
    //PRIVMSG
    ERR_CANNOTSENDTOCHAN: "%s :Cannot send to channel", //channel
    ERR_NORECIPIENT: ":No recipient given (%s)", //command
    ERR_NOTEXTTOSEND : "No text to send",
    ERR_NOTOPLEVEL: "%s :No toplevel domain specified", //mask
    ERR_WILDTOPLEVEL: "%s :Wildcard in toplevel domain", //mask
    ERR_NOSUCHNICK: "%s :No such nick/channel", //nick
    ERR_NOSUCHSERVER: "%s :No such server", //servername
    //WHO
    RPL_ENDOFWHO: "%s :End of WHO list", //name
    RPL_WHOREPLY: "%s %s %s %s %s :0 %s", //channel user host server nick realname
}
type config struct {
    //config
    address  string
    port     string
    certfile string
    doSelfsigned bool
    password string
    maxChannels uint
}
type ircmessage struct {
    raw string
    prefix string
    command string
    trailing string
    parameters []string
    source *ircclient
}
type ircchannel struct {
    name string
    members map[string]*ircclient
    topic string
    mode string
    maxUsers uint
}
type ircd struct {
    config config
    logger    *log.Logger
    channels []*ircchannel
    clients []*ircclient
    mutex sync.Mutex
    created time.Time
    version string
}
type ircclient struct {
    server *ircd
    channels []*ircchannel
    // IO
    conn net.Conn
    connwriter *bufio.Writer
    outQueue chan string
    registered bool
    done bool 
    nickname, username, realname string
    ident string
    id string //for logging/handling
    lastActivity int64
    lastPing int64
    pingTimer *time.Timer
    permissions string
    password string
    servername string
    hashedname string
    mode string
}
type ircError struct {
    code int
    msg string
}
func (err ircError) Error() string {
    return fmt.Sprintf("IRC-ERROR: %d: %s", err.code, err.msg)
}
func (self *ircchannel) getNicks() []string {
    rv := make([]string, len(self.members))
    for n:= range self.members {
        rv = append(rv, n)
    }
    return rv
}
func (self *ircchannel) isMember(nick string) bool {
    for user :=  range self.members {
        if  nick == user {
            return true
        }
    }
    return false
}
func (ircc ircchannel) String() string {
    return ircc.name
}
func makeCert(ircd *ircd) error {
    //TODO this is trivally easy with the crypt/tls pkg, without shellout
    const cmd_selfsign string = "openssl req -x509 -newkey rsa:4096 -keyout -" +
        " -out - -days 3650 -nodes -subj /C=DE/ST=BW/L=BW/O=Faul/OU=Org/CN=%s"
    myaddr := ircd.config.address
    filename := ircd.config.certfile
    if strings.Index(myaddr, " ")  != -1 {
        return ircError{-1, "invalid user input as certificate hostname"}
    }
    //expand template and pipe output into file
    tmp := fmt.Sprintf(cmd_selfsign, myaddr)
    args := strings.Fields(tmp)
    var out, cerr bytes.Buffer
    ircd.log("calling %v\n", args)
    cmd := exec.Command(args[0], args[1:]...)
    cmd.Stdout = &out
    cmd.Stderr = &cerr
    err := cmd.Run()
    if err != nil {
        fmt.Printf("ERROR openssl: %s\n", cerr.String())
        return err
    }
    ircd.log("openssl returned %d bytes\n", len(out.String()))
    return ioutil.WriteFile(filename, out.Bytes(), 0600)
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
            if err := makeCert(self); err != nil {
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
func (self *ircd) getChannel(name string) (*ircchannel, error) {
    for _,c := range self.channels {
        if c.name == name {
            return c, nil
        }
    }
    return nil, ircError{-1, "channel not found"}
}
func (self *ircd) deliver(msg *ircmessage) {
    //disseminate the client message, e.g. from client to channel etc
    //channels multiplex: JOIN, MODE, KICK, PART, QUIT, PRIVMSG/NOTICE
    //TODO NOTICE must not send any error replies
    self.log("enter msg=%v", msg.command)
    switch msg.command {
    case "JOIN", "PART", "KICK", "MODE", "QUIT", "PRIVMSG", "NOTICE":
        // XXX locking channels/members ?
        msg.prefix = msg.source.ident
        if len(msg.parameters)> 0 {
            // :prefix CMD #target
            tgt := msg.parameters[0]
            self.log("tgt=%v, validChannelName=%v", tgt, isChannelName(tgt))
            if isChannelName(tgt) {
                ch, err := self.getChannel(tgt)
                if err != nil {
                    self.log("deliver: ignoring msg on non-existing channel %s", tgt)
                    return
                }
                self.log("ch=%v, members=%v", ch, ch.members)
                for _, client := range ch.members {
                    if client == msg.source && (msg.command == "PRIVMSG" || msg.command == "NOTICE")  {
                        continue
                    }
                    client.outQueue <- msg.GetRaw()
                }
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
                cl := self.findClientByNick(tgt)
                if cl == nil {
                    msg.source.numericReply(ERR_NOSUCHNICK, tgt)
                    return
                }
                cl.outQueue <- msg.GetRaw()
            }
        } else {
            // :prefix CMD :trailing, only interesting for the current client?
            msg.source.outQueue <- msg.GetRaw()
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
    return rv
}
func (self *ircd) addClient(client *ircclient) {
    self.mutex.Lock()
    defer self.mutex.Unlock()
    self.clients = append(self.clients, client)
}
func (self *ircd) cleanup() {
    self.mutex.Lock()
    defer self.mutex.Unlock()

    for i, cl := range self.clients {
        if cl.done {
            self.log("%s disconnected", cl.id)
            self.clients = append(self.clients[0:i], self.clients[i+1:]...)
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

    addr := fmt.Sprintf("%s:%s", self.config.address, self.config.port)
    self.log("Listening on %s", addr)
    l, err := net.Listen("tcp", addr)
    if err != nil {
        self.log("Cannot create listening socket on  %s", addr)
        return
    }
    defer l.Close()

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

func NewChannel(name string) *ircchannel {
    nuch := new(ircchannel)
    nuch.name = name
    nuch.members = make(map[string]*ircclient)
    return nuch
}
func (self *ircd) joinChannel(channel, key string, client *ircclient) bool {
    self.mutex.Lock()
    defer self.mutex.Unlock()
    //TODO key/password checks
    for _, c := range self.channels {
        //TODO check modes
        if c.name == channel {
            c.members[client.nickname] = client
            return true
        }
    }
    //does not exist yet
    nuch := NewChannel(channel)
    nuch.members[client.nickname] = client
    self.channels = append(self.channels, nuch)
    return true
}
func (self *ircd) partChannel(channel string, client *ircclient) bool {
    self.mutex.Lock()
    defer self.mutex.Unlock()
    ch, err := self.getChannel(channel)
    if err != nil {
        return false
    }
    delete(ch.members, client.nickname)
    return true
}
func (self *ircd) registerNickname(nick string, client *ircclient) bool {
    self.mutex.Lock()
    defer self.mutex.Unlock()
    for _, d := range self.clients {
        if nick == d.nickname {
            return false
        }
    }
    client.nickname = nick
    return true
}
func NewClient(conn net.Conn, server *ircd) *ircclient {
    rv := new(ircclient)
    rv.conn = conn
    rv.server = server
    rv.id = conn.RemoteAddr().String()
    rv.lastPing = -1
    localname := strings.Split(conn.LocalAddr().String(), ":")
    rv.servername = localname[0] //default to IP
    hostnames, err := net.LookupHost(localname[0])
    if err != nil {
        rv.servername = hostnames[0]
    }
    h := sha256.Sum256([]byte(rv.id))
    rv.hashedname = fmt.Sprintf("%x", h)
    rv.outQueue = make(chan string)
    return rv
}
func (m *ircmessage) String() string {
    var param strings.Builder
    for _, b := range m.parameters {
        param.WriteString(b)
        param.WriteString("; ")
    }
    return fmt.Sprintf("Msg<pref=\"%s\",cmd=\"%s\",param=\"%s\",trail=\"%s\">",
            m.prefix, m.command, param.String(), m.trailing)
}

func (msg *ircmessage) FirstParameter() *string {
    if len(msg.parameters) > 0 {
        return &msg.parameters[0]
    }
    if len(msg.trailing) > 0 {
        return &msg.trailing
    }
    return nil
}
func (m *ircmessage) GetRaw() string {
    // return updated raw string
    var raw strings.Builder
    if len(m.prefix) > 0 {
        raw.WriteString(fmt.Sprintf(":%s ", m.prefix))
    }
    raw.WriteString(m.command)
    raw.WriteString(" ")
    for _, b := range m.parameters {
        raw.WriteString(b)
        raw.WriteString(" ")
    }
    if len(m.trailing) > 0 {
        raw.WriteString(":")
        raw.WriteString(m.trailing)
    }
    return raw.String()
}
func ircParseMessage( raw string) (msg *ircmessage, err error) {
    fmt.Printf("msg = %s\n", raw)
    if len(raw) < 3  {
        return nil, nil
    }
    var idx int = -1
    rv := new(ircmessage)
    rv.raw = raw
    //colon starts the prefix, up to whitespace
    raw = strings.TrimLeft(raw, " ")
    if raw[0] == ':' {
        idx = strings.Index(raw, " ")
        if idx == -1  {
            return nil, ircError{-1, "prefix started but no end"}
        }
        rv.prefix=raw[0:idx]
        raw=raw[idx:]
        //fmt.Printf("raw1=%s\n", raw)
    }
    //purge whitespace
    raw = strings.TrimLeft(raw, " ")
    if idx = strings.Index(raw, " "); idx == -1 {
            return nil, ircError{-1, "command has no end"}
    }
    //command up to whitespace
    rv.command = raw[0:idx]
    //fmt.Printf("raw2=%s\n", raw)
    raw = raw[idx:]
    //params, muliple whitespace separated, trailer might be ":" separated
    idx = strings.Index(raw, ":")
    if idx != -1 {
        rv.trailing = raw[idx+1:]
        raw = raw[0:idx]
        //fmt.Printf("raw3=%s\n", raw)
    }
    tmp := strings.Split(raw, " ")
    for _, t := range tmp {
        if len(t) > 0 {
            rv.parameters = append(rv.parameters, t)
        }
    }
    return rv, nil
}
func (self *ircclient) Kill() {
    self.done = true
    self.registered = false
    if self.pingTimer != nil {
        self.pingTimer.Stop()
    }
    self.conn.Close()
    self.log("killed")
    self.outQueue <- "" //make sure writeIO wakes up
}
func (self *ircclient) onRegistered() {
    self.registered = true
    if len(self.server.config.password) > 0 {
        if self.password != self.server.config.password {
            self.log("invalid password")
            self.Kill()
            return
        }
    }
    self.log("registered user %s", self.nickname)
    self.ident = fmt.Sprintf("%s!%s@%s", self.nickname, self.username, self.hashedname[0:32])
    self.numericReply(RPL_WELCOME, self.nickname)
    self.numericReply(RPL_YOURHOST, self.servername, self.server.version)
    self.numericReply(RPL_CREATED, self.server.created.Format(time.RFC3339))
    self.numericReply(RPL_MYINFO, self.servername, self.server.version, "i", "i")
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
            if self.lastPing > 0  && dp >= irc_ping_timeout {
                self.log("Ping timeout t=%d", dp)
                self.Kill()
            }
            da := now.Unix() - self.lastActivity
            if da >= irc_ping_timeout {
                self.lastPing = time.Now().Unix()
                self.send("PING %d", self.lastPing)
            }
        }
    }
}
func (self *ircd) log(msg string, args ...interface{}) {
    if self.logger == nil {
        fmt.Printf(msg, args...)
        return
    }
    self.logger.Printf("%s", fmt.Sprintf(msg, args...))
}
func (self *ircclient) log(msg string, args ...interface{}) {
    self.server.log("[%s] %s", self.id, fmt.Sprintf(msg, args...))
}
func (self *ircclient) handleMessage(msg *ircmessage) {
    //only handle NICK, PASS, USER, CAP for registration
    if msg == nil {
        return
    }
    msg.source = self
    switch msg.command {
    case "NICK":
        tgt := msg.FirstParameter()
        if tgt == nil {
            self.numericReply(ERR_ERRONEUSNICKNAME)
            return
        }
        for _,c := range *tgt {
            if ! strconv.IsPrint(c) {
                self.numericReply(ERR_ERRONEUSNICKNAME)
                return
            }
        }
        if !self.server.registerNickname(*tgt, self) {
            self.numericReply(ERR_NICKNAMEINUSE, *tgt)
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
        if len(msg.parameters) != 3  {
            self.numericReply(ERR_NEEDMOREPARAMS, msg.command)
            return
        }
        self.username = msg.parameters[0]
        //hostname and servername ignored XXX
        self.realname = msg.trailing
        if len(self.nickname) > 0 {
            self.onRegistered()
        }
    case "PASS":
        if len(msg.parameters) != 1 {
            self.numericReply(ERR_NEEDMOREPARAMS, msg.command)
            return
        }
        self.password = msg.parameters[0]
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
        self.send(":%s PONG %s", self.servername, msg.trailing)
        return
    case "MODE":
        if len(msg.parameters) < 2 {
            self.numericReply(ERR_NEEDMOREPARAMS)
            return
        }
        if msg.parameters[0]  != self.nickname {
            self.numericReply(ERR_USERSDONTMATCH)
            return
        }
        for _, c := range msg.parameters[1:]{
            if len(c) != 2 || strings.Index(irc_valid_modes, string(c[1])) == -1 {
                self.numericReply(ERR_UMODEUNKNOWNFLAG)
                return
            }
            if len(c) == 2 {
                if c[0] == '+' {
                    //XXX not implemented modes
                    if idx := strings.Index(self.mode, string(c[1])); idx == -1 {
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

        self.numericReply(RPL_UMODEIS, self.mode)
    case "JOIN":
        if len(msg.parameters) < 1 {
            self.numericReply(ERR_NEEDMOREPARAMS, msg.command)
            return
        }
        tgts := strings.Split(msg.parameters[0], ",")
        var keys []string
        if len(msg.parameters) == 2 {
            keys = strings.Split(msg.parameters[1], ",")
        }
        for i := range tgts {
            var k string
            if i < len(keys) {
                k = keys[i]
            }
            if self.server.joinChannel(tgts[i], k, self){
                self.onJoin(tgts[i])
            } else {
                self.numericReply(ERR_UNAVAILRESOURCE, tgts[i])
            }
        }

    case "PART":
        if len(msg.parameters) < 1 {
            self.numericReply(ERR_NEEDMOREPARAMS, msg.command)
            return
        }
        tgts := strings.Split(msg.parameters[0], ",")
        for _, tgt := range tgts {
            if len(tgt) < 1  {
                self.numericReply(ERR_NOSUCHCHANNEL, tgt)
                return
            }
            ch, err := self.server.getChannel(tgt)
            if err != nil {
                self.numericReply(ERR_NOSUCHCHANNEL, tgt)
                return
            }
            if ! ch.isMember(self.nickname) {
                self.numericReply(ERR_NOTONCHANNEL, tgt)
                return
            }
            if !self.server.partChannel(tgt, self) {
                self.log("ERROR cannot part channel %s", tgt)
            }
            self.server.deliver(self.makeMessage(":%s PART %s :%s", self.ident, tgt, msg.trailing))
        }
    case "PRIVMSG", "NOTICE":
        self.server.deliver(msg)
    case "QUIT":
        if len(msg.prefix) > 0 {
            //check if client owns prefix TODO
            if msg.prefix != self.ident || msg.prefix  != self.nickname {
                return
            }
        }
        self.server.deliver(self.makeMessage(":%s QUIT :%s", self.ident, msg.trailing))
        self.Kill()
    case "WHO":
        if len(msg.parameters) < 1 {
            self.log("who without parameter received")
            return
        }
        mask := &msg.parameters[0]
        // TODO mask might be a glob, second parameter might be mode/flag
        if isChannelName(*mask) {
            ch, err := self.server.getChannel(*mask)
            if err != nil {
                self.numericReply(RPL_ENDOFWHO, *mask)
            } else {
                for _, cl := range ch.members {
                    self.numericReply(RPL_WHOREPLY, ch.name, cl.username,
                        cl.hashedname, self.servername, cl.nickname, cl.realname)
                }
            }
        }

    default:
        self.log("unknown msg <- %v", msg)
    }
}

func (self *ircclient) makeMessage(tmpl string, args ...interface{}) (*ircmessage) {
    msg, err := ircParseMessage(fmt.Sprintf(tmpl, args...))
    if err != nil {
        return nil
    }
    if msg != nil {
        msg.source = self
    }
    return msg
}
func (self *ircclient) onJoin(channel string) {
    ch, err := self.server.getChannel(channel)
    if err != nil {
        self.log("cannot get channel %s", channel)
        self.Kill()
        return
    }
    if len(ch.topic) > 0 {
        self.numericReply(RPL_TOPIC, ch.topic)
    }
    // =, *, @ are prefixes for public, private, secret channels
    var users string
    for _,u := range ch.getNicks() {
        if len(u) > 0 {
            users += fmt.Sprintf("=%s ", u)
        }
    }
    self.numericReply(RPL_NAMREPLY, "=", channel, users)
    self.server.deliver(self.makeMessage(":%s JOIN %s", self.ident, channel))
}
func (self *ircclient) numericReply(num int, args ...interface{}) {
    //TODO XXX
    // should look like :localhost 001 marius :Welcom fooba ?
    msg := ""
    if tmp, ok := numericMap[num]; ok {
        msg = tmp
        if len(args) > 0  {
            msg = fmt.Sprintf(msg, args...)
        }
    }
    self.send(":%s %03d %s %s", self.servername, num, self.nickname, msg)
}
func (self *ircclient) send(tmpl string, args ...interface{}) {
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
                self.Kill()
            }
            if n != len(msg) {
                self.log("short write %d != %d", n, len(msg))
                self.Kill()
            }
            if err = self.connwriter.Flush(); err != nil {
                self.log("send flush failed: %s", err)
                return
            }
            self.log("Sent '%s'", msg[0:len(msg)-2])
            self.lastActivity = time.Now().Unix()
        }
    }
    self.server.cleanup()
}
func (self *ircclient) readIO() {
    scanner := bufio.NewScanner(self.conn)
    self.connwriter = bufio.NewWriter(self.conn)
    crlnSplit := func(data []byte, atEOF bool) (advance int, token []byte, err error) {
        idx := bytes.Index(data, []byte("\r\n"))
        if len(data) == 0 {
            return 0, nil, nil
        }
        if idx == -1 {
            return 0, nil, ircError{-1, fmt.Sprintf("no line separator in data: \"%s\"", string(data))}
        }
        advance = idx+2
        token = data[0:idx]
        err = nil
        //fmt.Printf("idx = %d\n", idx)
        return advance,token, err
    }
    scanner.Split(crlnSplit)
    for self.done == false{
        self.log("main loop")
        for scanner.Scan() {
            msg, err := ircParseMessage(scanner.Text())
            if err != nil {
                self.log("<- cannot parse message: %v", err)
                self.Kill()
                break
            }
            self.handleMessage(msg)
        }
        if scanner.Err() != nil {
            self.log("got error while reading from client: %v", scanner.Err())
        }
        //read done
        if ! self.done {
            self.Kill()
        }
    }
}
func main() {
    server :=  NewServer()
	server.Run()
}
