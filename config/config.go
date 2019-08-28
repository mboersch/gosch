// Copyright (c) Marius Börschig. All rights reserved.
// Licensed under the BSD 3-Clause License. See the LICENSE file.

package config

import (
	"bufio"
	"flag"
	"fmt"
	"os"
	"regexp"
	"strconv"
	"strings"
)

type Config struct {
	Version      string
	Appname      string
	Flags        *flag.FlagSet
	DebugLevel   int
	configLoaded bool
}

func NewConfig(appname, version string) *Config {
	cfg := Config{}
	cfg.Appname = appname
	cfg.Version = version
	cfg.Flags = flag.NewFlagSet(appname, flag.ContinueOnError)
	cmd := cfg.Flags
	cmd.Usage = func() {
		fmt.Printf("gosch version %v -- Usage:\n", version)
		cmd.PrintDefaults()
	}
	cmd.String("config", "", "load settings from the file path given here (can be overriden from command line)")
	cmd.Uint("port", 6697, "specify the port number to listen on")
	cmd.String("address", "localhost",
		"specify the internet address or hostname to listen on")
	cmd.String("certfile", "",
		"specify the ssl PEM certificate/key to use for TLS server")
	cmd.String("password", "", "specify the connection password")
	cmd.Uint("max-channels", 8, "maximum number of channels a user can join")
	cmd.Uint("client-timeout", 60, "idle client timeout in seconds")
	cmd.Uint("debug", 0, "set debug level (higher means more infos)")
	cmd.Bool("selfsigned", false, "create a selfsigned certificate use (development use only)")
	cmd.String("logfile", "", "log to specified file")
	cmd.String("group", "", "change to this OS group before serving requests")
	cmd.String("user", "", "change to this OS user before serving requests")
	cmd.String("pidfile", "", "write the process ID to this file")
	cmd.Bool("daemon", false, "give up controlling terminal and serve in background")
	cmd.Bool("show-config", false, "print a default config file and exit")
	return &cfg
}

// LoadFile implements primitive config file support:
// each command line flag can be given on a line with "=" as a separator to its arguments
func (self *Config) LoadFile(filename string) error {
	fd, err := os.Open(filename)
	if err != nil {
		return err
	}
	rcom := regexp.MustCompile(`^\s*#.*`)
	rline := regexp.MustCompile(`^\s*(\S+)\s*=\s*(\S+).*`)
	rtrue := regexp.MustCompile(`^(true|TRUE|on|ON|yes|YES|y|Y|1)$`)
	rfalse := regexp.MustCompile(`^(false|FALSE|OFF|off|no|NO|n|N|0)$`)
	scanner := bufio.NewScanner(fd)
	scanner.Split(bufio.ScanLines)
	cfg := make([]string, 0)
	numig := 0
	ignored := strings.Builder{}
	for scanner.Scan() {
		ln := scanner.Text()
		// drop comments
		if m := rcom.FindAllStringSubmatch(ln, -1); m != nil {
			continue
		}
		//fetch key=value
		if m := rline.FindAllStringSubmatch(ln, -1); m != nil {
			arg := m[0][1]
			val := m[0][2]
			if self.IsSet(arg) {
				numig++
				ignored.WriteString(" ")
				ignored.WriteString(arg)
				continue
			}
			if flg := self.Flags.Lookup(arg); flg == nil {
				fmt.Printf("WARNING: ignoring unknown configuration key: %s: %s\n",
					arg, val)
			} else {
				if rtrue.MatchString(val) {
					//boolean takes no argument
					cfg = append(cfg, fmt.Sprintf("--%s", arg))
				} else if rfalse.MatchString(val) {
					//disabled booleans are skipped
					continue
				} else {
					cfg = append(cfg, fmt.Sprintf("--%s", arg), val)
				}
			}
		}
	}
	fmt.Printf("loaded config file: %s\n", cfg)
	if numig > 0 {
		fmt.Printf("  Overriden on command line: %d entries ignored: %s\n",
			numig, ignored.String())
	}
	self.configLoaded = true
	return self.Parse(cfg)
}

// Get returns the value or default value of flag named flagname.
func (self *Config) Get(flagname string) flag.Value {
	flg := self.Flags.Lookup(flagname)
	if flg == nil {
		return nil
	} else {
		return flg.Value
	}
}

// GetInt returns the flag parsed as an integer or -1 on failure
func (self *Config) GetInt(flagname string) int64 {
	flg := self.Get(flagname)
	if flg == nil {
		return -1
	}
	rv, err := strconv.Atoi(flg.String())
	if err != nil {
		return -1
	}
	return int64(rv)
}

// IsSet returns true if the named flag was seen during Parse() time
func (self *Config) IsSet(name string) bool {
	is_set := false
	self.Flags.Visit(func(flg *flag.Flag) {
		if flg != nil && name == flg.Name {
			is_set = true
			return
		}
	})
	return is_set
}
func (self *Config) Parse(args []string) error {
	err := self.Flags.Parse(args)
	if err != nil {
		return err
	}

	self.DebugLevel = int(self.GetInt("debug"))
	if cfgfile := self.Get("config"); self.IsSet("config") && !self.configLoaded {
		fmt.Printf("loading configuration from \"%s\"\n", cfgfile.String())
		return self.LoadFile(cfgfile.String())
	}
	return err
}
