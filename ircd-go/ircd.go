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
)
//Numeric Reply 
const (
    RPL_WELCOME = 001
    RPL_YOURHOST = 002
    RPL_CREATED = 003
    RPL_MYINFO = 004
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


)
var numericMap  = map[int]string{
    RPL_WELCOME: ":Welcome to the Internet Relay Network %s", // nick!user@host
    RPL_YOURHOST: ":Your host is %s, running version %s", //servername, version
    RPL_CREATED: ":This server was created %s", //date
    RPL_MYINFO: ":%s %s %s %s", //servername version user_modes channel_modes
    //NICK
    ERR_NONICKNAMEGIVEN: ":No nickname given",
    ERR_ERRONEUSNICKNAME: ":Erroneus nickname",
    ERR_NICKNAMEINUSE: ":Nickname is already in use",
    ERR_NICKCOLLISION: ":Nickname collision KILL",
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
    log    *log.Logger
    channels []*ircchannel
    clients []*ircclient
    mutex sync.Mutex
    created time.Time
}
type ircclient struct {
    server *ircd
    channels []*ircchannel
    conn net.Conn
    connwriter *bufio.Writer
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
    ircd.log.Printf("calling %v\n", args)
    cmd := exec.Command(args[0], args[1:]...)
    cmd.Stdout = &out
    cmd.Stderr = &cerr
    err := cmd.Run()
    if err != nil {
        fmt.Printf("ERROR openssl: %s\n", cerr.String())
        return err
    }
    ircd.log.Printf("openssl returned %d bytes\n", len(out.String()))
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
                self.log.Fatalf("cannot make self signed cert: %s\n", err)
                return ircError{-3, "create self signed cert"}
            }
        } else {
            self.usage("the certfificate file does not exist")
            return ircError{-4, "cert does not exist"}
        }
    }
    return nil
}
func NewServer() *ircd {
    rv := new(ircd)
    rv.log  = log.New(os.Stdout, "ircd ", log.LstdFlags)
    if err := rv.parseArgs(); err != nil {
        rv.log.Printf("ERROR: %s", err)
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
            self.log.Printf("%s disconnected", cl.id)
            self.clients = append(self.clients[0:i], self.clients[i+1:]...)
        }
    }
}
func (self *ircd) Run() {
    crt, err := tls.LoadX509KeyPair(self.config.certfile, self.config.certfile)
    if err != nil {
        self.log.Fatalf("Cannot load cert/key pair: %s", err)
        return
    }
    cfg := &tls.Config{Certificates: []tls.Certificate{crt}}

    addr := fmt.Sprintf("%s:%s", self.config.address, self.config.port)
    self.log.Printf("Listening on %s", addr)
    l, err := net.Listen("tcp", addr)
    if err != nil {
        self.log.Fatalf("Cannot create listening socket on  %s", addr)
        return
    }
    defer l.Close()

    for {
        cl, err :=  l.Accept()
        if err != nil {
            self.log.Printf("ERROR: cannot accept client %v", err)
            continue
        }
        tlsconn := tls.Server(cl, cfg)
        client := NewClient(tlsconn, self)
        go client.Run()
        self.addClient(client)
    }
}

func (self *ircd) enterChannel(channel string, client *ircclient) bool {
    self.mutex.Lock()
    defer self.mutex.Unlock()
    for _, c := range self.channels {
        //TODO check modes
        if c.name == channel {
            c.members[client.nickname] = client
            return true
        }
    }
    //does not exist yet
    nuch := new(ircchannel)
    nuch.name = channel
    self.channels = append(self.channels, nuch)
    return false
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
func ircParseMessage( raw string) (msg *ircmessage, err error) {
    fmt.Printf("msg = %s\n", raw)
    if len(raw) < 3  {
        return nil, nil
    }
    var idx int = -1
    rv := new(ircmessage)
    rv.raw = raw
    //fmt.Printf("raw=%s\n", raw)
    //colon starts the prefix, up to whitespace
    if raw[0] == ':' {
        idx = strings.Index(raw, " ")
        if idx == -1  {
            return nil, ircError{-1, "prefix started but no end"}
        }
        rv.prefix=raw[0:idx]
        raw=raw[idx:]
        //fmt.Printf("raw1=%s\n", raw)
    }
    if idx = strings.Index(raw, " "); idx == -1 {
            return nil, ircError{-1, "command has no end"}
    }
    //purge whitespace
    raw = strings.TrimLeft(raw, " ")
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
    self.numericReply(RPL_WELCOME, self.ident)
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
                self.Send("PING %d", self.lastPing)
            }
        }
    }
}
func (self *ircclient) log(msg string, args ...interface{}) {
    if self.server == nil {
        return
    }
    self.server.log.Printf("[%s] %s", self.id, fmt.Sprintf(msg, args...))
}
func (self *ircclient) handleMessage(msg *ircmessage) {
    //only handle NICK, PASS, USER, CAP for registration
    if msg == nil {
        return
    }
    switch msg.command {
    case "NICK":
        if len(msg.parameters) != 1 {
            self.numericReply(ERR_ERRONEUSNICKNAME)
            return
        }
        for _,c := range msg.parameters[0] {
            if ! strconv.IsPrint(c) {
                self.numericReply(ERR_ERRONEUSNICKNAME)
                return
            }
        }
        if !self.server.registerNickname(msg.parameters[0], self) {
            self.numericReply(ERR_NICKNAMEINUSE)
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
    case "CAP":
        self.log("ignoring CAP msg")
    case "PONG":
        if len(msg.trailing) < 1 {
            self.log("PONG without trailing received!")
            return
        }
        tmp := fmt.Sprintf("%d", self.lastPing)
        if tmp != msg.trailing {
            self.log("PONG mismatch: lastping=%s received=%s", tmp, msg.trailing)
            return
        }
        self.lastPing = -1
        self.lastActivity = time.Now().Unix()
    case "PING":
        self.Send(":%s PONG %s", self.servername, msg.trailing)
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
        //TODO might be chan,chan,chan key,key,key or "0"
        if self.server.enterChannel(msg.parameters[0], self) {
            self.numericReply(RPL_NOTOPIC, msg.parameters[0])
            return
        }

    case "PRIVMSG":

    default:
        self.log("unknown msg <- %v", msg)
    }
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
    self.Send(":%s %03d %s %s", self.servername, num, self.nickname, msg)
}
func (self *ircclient) Send(tmpl string, args ...interface{}) {
    msg := fmt.Sprintf("%s\r\n", fmt.Sprintf(tmpl, args...))
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
func (self *ircclient) Run() {
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
        self.server.cleanup()
    }
}
func main() {
    server :=  NewServer()
	server.Run()
}
