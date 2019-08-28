// Copyright (c) Marius Börschig. All rights reserved.
// Licensed under the BSD-3-Clause License.
package server

import (
	"fmt"
	"github.com/mboersch/gosch/irc"
	"strconv"
	"strings"
)

type ircmessage struct {
	raw         string
	prefix      string
	command     string
	trailing    string //should be just another parameter
	hasTrailing bool
	parameters  []string
	source      *ircclient
}

// ircmessage
func (m *ircmessage) NumParameters() int {
	r := len(m.parameters)
	if len(m.trailing) > 0 {
		r++
	}
	return r
}
func (m *ircmessage) GetParameterString() string {
	var rv strings.Builder
	for _, b := range m.parameters {
		rv.WriteString(b)
		rv.WriteString(" ")
	}
	if m.hasTrailing {
		rv.WriteString(m.trailing)
	}
	return rv.String()
}
func (m *ircmessage) String() string {
	var rv strings.Builder
	rv.WriteString("Msg<prefix=")
	rv.WriteString(m.prefix)
	rv.WriteString(",cmd=")
	rv.WriteString(m.command)
	rv.WriteString(",params<")
	for _, b := range m.parameters {
		rv.WriteString(b)
		rv.WriteString(";")
	}
	rv.WriteString(">")
	if m.hasTrailing {
		rv.WriteString(",trail=")
		if m.command == "NOTICE" || m.command == "PRIVMSG" {
			rv.WriteString(fmt.Sprintf("%d bytes", len(m.trailing)))
		} else {
			rv.WriteString(strconv.QuoteToASCII(m.trailing))
		}
	}
	rv.WriteString(">")
	return rv.String()
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
	needspc := false
	for _, b := range m.parameters {
		if needspc {
			raw.WriteString(" ")
		}
		raw.WriteString(b)
		needspc = true
	}
	if len(m.trailing) > 0 {
		raw.WriteString(" :")
		raw.WriteString(m.trailing)
	}
	return raw.String()
}
func ircParseMessage(raw string) (msg *ircmessage, err error) {
	//TODO FFS rewrite this in regexp
	const space = " "
	if len(raw) < 3 {
		return nil, nil
	}
	if len(raw) > irc.IRC_max_message_length {
		return nil, ircError{-5, "message too long"}
	}
	if strings.Index(raw, "\r\n") != -1 {
		return nil, ircError{-4, "raw message contains CR LN!"}
	}
	var idx int = -1
	rv := new(ircmessage)
	rv.raw = raw
	//colon starts the prefix, up to whitespace
	raw = strings.Trim(raw, space)
	if raw[0] == ':' {
		idx = strings.Index(raw, " ")
		if idx == -1 {
			return nil, ircError{-1, "prefix started but no end"}
		}
		rv.prefix = raw[1:idx]
		raw = raw[idx:]
		//fmt.Printf("raw1=%s\n", raw)
	}
	//purge whitespace
	raw = strings.TrimLeft(raw, space)
	if idx = strings.Index(raw, " "); idx == -1 {
		if len(raw) > 0 {
			rv.command = raw
			return rv, nil
		} else {
			return nil, ircError{-2, "no command given"}
		}
	}
	//command up to whitespace
	rv.command = strings.ToUpper(raw[0:idx])
	raw = raw[idx:]
	raw = strings.TrimLeft(raw, space)
	//params, muliple whitespace separated, trailer might be ":" separated
	idx = strings.Index(raw, ":")
	if idx != -1 {
		rv.hasTrailing = true
		rv.trailing = raw[idx+1:]
		raw = raw[0:idx]
		//fmt.Printf("raw3=%s\n", raw)
	}
	tmp := strings.Split(raw, " ")
	for _, t := range tmp {
		t = strings.Trim(t, space)
		if len(t) > 0 {
			rv.parameters = append(rv.parameters, t)
		}
	}
	return rv, nil
}
