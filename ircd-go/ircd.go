package main
//author: Marius Boerschig <code (at) boerschig (dot) net>
// TODO:
// - usermodes: +m on channels, +v, +o for users,
// - make sure BAN works with hashed client addr/hostnames
// - the nick roster in pidgin is broken, works fine in konversation and irssi
// - refactor and clean up
// - remove ssl-shellout, can be done in native go code
// - implement POSIX getopt, flags sucks 
// - daemonize, log to folder

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
    irc_valid_user_modes string = "iwoOra" //obsolete: "s"
    irc_valid_channel_modes string = "opsitnbv" //obsolete: "s"
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
func isValidUserMode(mod byte) bool {
    return strings.Index(irc_valid_user_modes, string(mod)) != -1
}
func isValidChannelMode(mod byte) bool {
    return strings.Index(irc_valid_channel_modes, string(mod)) != -1
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
    ERR_UNKNOWNMODE = 472
    // INFO
    RPL_INFO = 371
    RPL_ENDOFINFO = 374
    //MODE channel
    RPL_BANLIST = 367
    RPL_ENDOFBANLIST = 368
    RPL_EXCEPTLIST = 348
    RPL_ENDOFEXCEPTLIST = 349
    RPL_INVITELIST = 346
    RPL_ENDOFINVITELIST =347
    RPL_UNIQOPIS = 325
    RPL_CHANNELMODEIS = 324
    ERR_USERNOTINCHANNEL = 441
    ERR_NOCHANMODES = 477
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
    RPL_TOPICWHOTIME = 333
    RPL_NAMREPLY = 353
    RPL_ENDOFNAMES = 366
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
    // USERHOST
    RPL_USERHOST = 302

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
    ERR_NEEDMOREPARAMS: "%s :Not enough parameters", //command
    ERR_ALREADYREGISTRED: ":You may not reregister",
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
    RPL_TOPIC: "%s :%s", //channel topic
    RPL_TOPICWHOTIME: "%s %s %d", //channel, nick, setat_unix_timestamp
    RPL_NAMREPLY:  "%s %s :%s",  //symbol(=*@), channel, (symboL)nick ...
    RPL_ENDOFNAMES: "%s :End of NAMES list", //channel
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
    RPL_WHOREPLY: "%s %s %s %s %s %s :0 %s", //channel user host server nick mode realname
    //USERHOST
    RPL_USERHOST: ":%s", //space separated encoded replies: (nickname[*]=[+|-]hostname)
    // INFO
    RPL_INFO: ":%s", //string
    RPL_ENDOFINFO: ":End of INFO list",
    //MODE channel
    RPL_BANLIST: "%s %s", //channel banmask
    RPL_ENDOFBANLIST: "%s :End of channel ban list", //channel
    RPL_EXCEPTLIST: "%s %s", //channel exception mask
    RPL_ENDOFEXCEPTLIST: "%s :End of channel exception list",
    RPL_INVITELIST: "%s %s", //channel invitemask
    RPL_ENDOFINVITELIST: "%s :End of channel invite list", //channel
    RPL_UNIQOPIS: "%s %s", //channel, nickname
    RPL_CHANNELMODEIS: "%s %s %s", //channel, mode, modeparams
    ERR_USERNOTINCHANNEL: "%s %s: They aren't on that channel", //nick channel
    ERR_NOCHANMODES: "%s :Channel doesn't support modes", //channel
    //MODE
    ERR_UMODEUNKNOWNFLAG : "Unknown MODE flag",
    ERR_USERSDONTMATCH : "Cannot change mode for other users",
    RPL_UMODEIS : "%s",
    ERR_UNKNOWNMODE: "%s :is unknown mode char to me for %s", // char, channel
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
    userFlags map[string]string
    topic string
    topicSetBy string
    topicSetOn time.Time
    mode string
    maxUsers uint
    created time.Time
}
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
    hashedname string
    mode string
    isBroken bool
}
type ircError struct {
    code int
    msg string
}
func (err ircError) Error() string {
    return fmt.Sprintf("IRC-ERROR: %d: %s", err.code, err.msg)
}

func (self *ircchannel) getUserFlags(nick string) string {
    if flag, ok := self.userFlags[nick]; ok {
        return flag
    }
    return ""
}
func (self *ircchannel) getNicks() []string {
    rv := make([]string, len(self.members))
    for n:= range self.members {
        rv = append(rv, n)
    }
    return rv
}

func (self *ircchannel) isOperator(nick string) bool {
    return false
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
            if err := makeCert(self); err != nil {
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
func rS( code int) string {
    //reply code as string
    return fmt.Sprintf("%03d", code)
}
func isNumeric (reply string) bool {
    if _, err := strconv.Atoi(reply); err == nil {
        return true
    }
    return false
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
        }
        if msg.command == "JOIN" && client == msg.source {
            continue
        }
        if msg.command == "QUIT" && client == msg.source {
            continue
        }
        client.outQueue <- msg.GetRaw()
    }
    return
}
func (self *ircd) deliver(msg *ircmessage) {
    //disseminate the client message, e.g. from client to channel etc
    //channels multiplex: JOIN, MODE, KICK, PART, QUIT, PRIVMSG/NOTICE
    //TODO NOTICE must not send any error replies
    self.trace("enter msg=%v", msg)
    switch msg.command {
    case "JOIN", "PART", "KICK", "MODE", "QUIT", "PRIVMSG", "NOTICE":
        msg.prefix = msg.source.getIdent()
        // XXX locking channels/members ?
        if len(msg.parameters)> 0 {
            tgt := msg.FirstParameter()
            // :prefix CMD #target
            //self.log("tgt=%v, validChannelName=%v", tgt, isChannelName(tgt))
            if isChannelName(*tgt) {
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
    case rS(RPL_TOPIC), rS(RPL_TOPICWHOTIME):
        if len(msg.parameters) >= 2 {
            if isChannelName(msg.parameters[1]) {
                self.deliverToChannel(&msg.parameters[1], msg)
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


    addr := fmt.Sprintf("%s:%s", self.config.address, self.config.port)
    self.log("Listening on %s", addr)


    l, err := net.Listen("tcp", addr)
    if err != nil {
        self.log("Cannot create listening socket on  %s", addr)
        return
    }
    defer l.Close()

    localname := strings.Split(l.Addr().String(), ":")
    self.servername = localname[0] //default to IP
    hostnames, err := net.LookupHost(localname[0])
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

func NewChannel(name string) *ircchannel {
    nuch := new(ircchannel)
    nuch.name = name
    nuch.members = make(map[string]*ircclient)
    nuch.userFlags = make(map[string]string)
    nuch.created = time.Now()
    return nuch
}
func (self *ircchannel) RemoveClient(client *ircclient) {
    delete(self.members, client.nickname)
    delete(self.userFlags, client.nickname)
}
func (self *ircd) joinChannel(channel, key string, client *ircclient){
    //TODO key/password checks
    self.mutex.Lock()
    defer self.mutex.Unlock()
    ch := self.getChannel(channel)
    if ch ==  nil {
        //does not exist yet
        nuch := NewChannel(channel)
        nuch.members[client.nickname] = client
        nuch.userFlags[client.nickname] = ""
        self.channels[nuch.name]= nuch
        self.trace("[%s] %s created %s", client.id, client.nickname, channel)
    } else {
        ch.members[client.nickname] = client
        ch.userFlags[client.nickname] = ""
        self.trace("[%s] %s joined %s", client.id, client.nickname, channel)
    }
    client.onJoin(channel)
}
func (self *ircd) partChannel(channel string, client *ircclient) bool {
    //TODO should be destroyed when last user leaves
    self.mutex.Lock()
    defer self.mutex.Unlock()
    ch := self.getChannel(channel)
    if ch == nil {
        return false
    }
    ch.RemoveClient(client)
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
    h := sha256.Sum256([]byte(rv.id))
    rv.hashedname = fmt.Sprintf("%x", h)
    rv.outQueue = make(chan string)
    rv.channels = make(map[string]*ircchannel)
    return rv
}
func (m *ircmessage) NumParameters() int {
    r := len(m.parameters)
    if len(m.trailing) > 0 {
        r ++
    }
    return r
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
    //fmt.Printf("msg = %s\n", raw)
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
        rv.prefix=raw[1:idx]
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
func (self *ircclient) onRegistered() {
    if self.registered == true {
        return
    }
    self.registered = true
    if len(self.server.config.password) > 0 {
        if self.password != self.server.config.password {
            self.log("invalid password")
            self.Kill("invalid password")
            return
        }
    }
    self.log("registered user %s", self.nickname)
    self.numericReply(RPL_WELCOME, self.nickname)
    self.numericReply(RPL_YOURHOST, self.server.servername, self.server.version)
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
            if self.lastPing > 0  && dp >= irc_ping_timeout {
                self.log("Ping timeout t=%d", dp)
                self.Kill("Ping timeout")
            }
            da := now.Unix() - self.lastActivity
            if da >= irc_ping_timeout {
                self.lastPing = time.Now().Unix()
                self.send("PING %d", self.lastPing)
            }
        }
    }
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
func (self *ircclient) log(msg string, args ...interface{}) {
    self.server.log("[%s] %s", self.id, fmt.Sprintf(msg, args...))
}
func (self *ircclient) debug(msg string, args ...interface{}) {
    self.server.debug("[%s] %s", self.id, fmt.Sprintf(msg, args...))
}
func (self *ircclient) trace(msg string, args ...interface{}) {
    self.server.trace("[%s] %s", self.id, fmt.Sprintf(msg, args...))
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
    msg.source = self
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
        self.send(":%s PONG %s", self.server.servername, msg.trailing)
        return
    case "MODE":
        if msg.NumParameters() == 1 {
            self.numericReply(RPL_UMODEIS, self.mode)
            return
        }
        tgt := msg.FirstParameter()
        if tgt == nil || (*tgt != self.nickname && !isChannelName(*tgt)) {
            self.numericReply(ERR_USERSDONTMATCH)
            return
        }
        for _, c := range msg.parameters[1:]{
            if isChannelName(*tgt) {
                if len(c) > 1 && ! isValidChannelMode(c[1]) {
                    self.numericReply(ERR_UNKNOWNMODE, string(c[1]), *tgt)
                    return
                }
                self.numericReply(ERR_NOCHANMODES, *tgt) //TODO implement modes
            } else {
                // User modes
                if len(c)  < 2 || ! isValidUserMode(c[1]) {
                    self.numericReply(ERR_UMODEUNKNOWNFLAG)
                    return
                }
                if len(c) == 2 {
                    if c[0] == '+' {
                        //XXX not implemented modes
                        if isValidUserMode(c[1]){
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
                return
            }
        }
        self.doneMessage=msg.trailing
        self.server.onDisconnect(self)
        self.Kill(fmt.Sprintf("quit %s", strconv.QuoteToASCII(msg.trailing)))
    case "WHO":
        if len(msg.parameters) < 1 {
            self.log("who without parameter received")
            return
        }
        mask := msg.FirstParameter()
        // TODO mask might be a glob, second parameter might be "o" flag
        if isChannelName(*mask) {
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
                    fmt.Printf("%s\n", fmt.Sprintf(numericMap[RPL_WHOREPLY], ch.name, cl.username,
                        cl.hashedname, self.servername, mode, cl.nickname, cl.realname))
                    */
                    self.numericReply(RPL_WHOREPLY, ch.name, cl.username,
                        cl.hashedname, self.server.servername, cl.nickname, mode, cl.realname)
                }
            }
        } else {
            // TODO match against nick!user@host

        }
        self.numericReply(RPL_ENDOFWHO)
    case "NAMES":
        tgt := msg.FirstParameter()
        if tgt == nil {
            return //no numeric given in RFC
        }
        if len(msg.parameters) == 2 {
            // channel+ target
        }
        for _, t := range strings.Split(*tgt, ",") {
            if len(t) > 0 {
                self.namReply(t)
            }
        }
    case "TOPIC":
        tgt := msg.FirstParameter()
        if tgt == nil || !isChannelName(*tgt) || len(msg.parameters) < 1 {
            self.numericReply(ERR_NEEDMOREPARAMS, msg.command)
            return
        }
        ch := self.server.getChannel(*tgt)
        if ch == nil {
            self.numericReply(RPL_NOTOPIC, *tgt)
            return
        }
        //TODO cannot distinguish between missing trailing parameter or empty string (delete current topic)
        if len(msg.trailing) < 1 {
            self.log("HIER")
            self.numericReply(RPL_TOPIC, ch.topicSetBy, ch.name, ch.topic)
            return
        }
        if ! ch.isMember(self.nickname) {
            self.log("not a member")
            self.numericReply(ERR_NOTONCHANNEL, ch.name)
            return
        }
        ch.topic = msg.trailing
        ch.topicSetBy = self.nickname
        ch.topicSetOn = time.Now()
        tmp := fmt.Sprintf(numericMap[RPL_TOPIC], ch.name, ch.topic)
        self.server.deliver(self.makeMessage(":%s %s %s %s", self.getIdent(),
                rS(RPL_TOPIC), self.nickname, tmp))
        tmp = fmt.Sprintf(numericMap[RPL_TOPICWHOTIME], ch.name,
            self.nickname, ch.topicSetOn.Unix())
        self.server.deliver(self.makeMessage(":%s %s %s %s", self.getIdent(),
            rS(RPL_TOPICWHOTIME), self.nickname, tmp))

    default:
        self.log("unknown msg <- %v", msg)
    }
}
func (self *ircclient) isAway() bool {
    return false //TODO implement me
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
func (self *ircclient) namReply(channel string) {
    ch := self.server.getChannel(channel)
    if ch == nil {
        return
    }
    // =, *, @ are prefixes for public, private, secret channels
    var users string
    for _,u := range ch.getNicks() {
        if len(u) > 0 {
            user_flags := ch.getUserFlags(u)
            users += fmt.Sprintf("%s%s ", user_flags, u)
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
    self.channels[ch.name] = ch
    self.send(":%s JOIN %s", self.getIdent(), channel)
    self.server.deliver(self.makeMessage(":%s JOIN %s", self.getIdent(), channel))
    self.namReply(channel)
    self.numericReply(RPL_TOPIC, channel, ch.topic)
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
    self.send(":%s %03d %s %s", self.server.servername, num, self.nickname, msg)
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
            //self.log("Sent '%s'", msg[0:len(msg)-2])
            self.lastActivity = time.Now().Unix()
        }
    }
    self.server.cleanup()
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
    for self.done == false{
        self.log("client connected")
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
func main() {
    server :=  NewServer()
	server.Run()
}
