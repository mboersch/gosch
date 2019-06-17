package main

import (
    //"crypto/tls"
    "strings"
    "fmt"
    "flag"
    "log"
    "os"
    "os/exec"
    "io/ioutil"
    "bytes"
)
type config struct {
    //config
    address  string
    port     uint
    certfile string
    doSelfsigned bool
}
type ircd struct {
    config config
    log    *log.Logger
}

type ircError struct {
    code int
    msg string
}
func (err ircError) Error() string {
    return fmt.Sprintf("IRC-ERROR: %d: %s", err.code, err.msg)
}
const cmd_selfsign string = "openssl req -x509 -newkey rsa:4096 -keyout - -out - -days 3650 -nodes -subj /C=DE/ST=BW/L=BW/O=Faul/OU=Org/CN=%s"
func makeCert(ircd *ircd) error {
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
    flag.UintVar(&self.config.port, "port", 6697, "specify the port number to listen on")
    flag.StringVar(&self.config.address, "address", "localhost", "specify the internet address to listen on")
    flag.StringVar(&self.config.certfile, "certfile", "", "specify the ssl PEM certificate to use for TLS server")
    flag.BoolVar(&self.config.doSelfsigned, "selfsigned", false, "use openssl commands to generate a selfsigned certificate use (development use only)")
	flag.Parse()
    if self.config.port > uint(^uint16(0)) {
        self.usage("the specified port is invalid")
        return ircError{-1, "invalid port"}
    }
    if len(self.config.certfile) < 1 {
        self.usage("please specify a certificate file. Or use '-selfsigned' to generate one")
        return  ircError{-2, "invalid cert file"}
    }
     _, err := os.Stat(self.config.certfile)
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
func New() *ircd {
    rv := new(ircd)
    rv.log  = log.New(os.Stdout, "ircd ", log.LstdFlags)
    rv.parseArgs()
    return rv
}
func (self *ircd) run() {
}
func main() {
    server :=  New()
	server.run()
}
