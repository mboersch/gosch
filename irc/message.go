// Copyright (c) Marius Börschig. All rights reserved.
// Licensed under the BSD-3-Clause License.
package irc

import (
	"fmt"
	"strconv"
	"strings"
	"errors"
)

type ircmessage struct {
	raw         string
	prefix      string
	command     string
	parameters  []string
	valid		bool
	//source      *ircclient
}

// ctor
func NewMessage(raw string) (Message, error) {
	return parseMessage(raw)
}
func (m *ircmessage) Valid() bool {
	return true
}
func (m *ircmessage) NumParameters() int {
	return len(m.parameters)
}
func (m *ircmessage) Parameters() []string {
	return m.parameters
}
func (m *ircmessage) ParameterString() string {
	var rv strings.Builder
	for _, b := range m.parameters {
		rv.WriteString(b)
		rv.WriteString(" ")
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
	if m.command == "NOTICE" || m.command == "PRIVMSG" {
		rv.WriteString(fmt.Sprintf("%d params", len(m.parameters)))
	} else {
		rv.WriteString(strconv.QuoteToASCII(m.ParameterString()))
	}
	rv.WriteString(">")
	return rv.String()
}
func (msg *ircmessage) SetPrefix(newPrefix string) {
	msg.prefix = newPrefix
}
func (msg *ircmessage) Prefix() *string {
	if len(msg.prefix) > 0 {
		return &msg.prefix
	}
	return nil
}
func (msg *ircmessage) Command() *string {
	if len(msg.command) > 0 {
		return &msg.command
	}
	return nil
}
func (msg *ircmessage) First() *string {
	if len(msg.parameters) > 0 {
		return &msg.parameters[0]
	}
	return nil
}
func (m *ircmessage) Raw() string {
	// return updated raw string
	var raw strings.Builder
	if len(m.prefix) > 0 {
		raw.WriteString(fmt.Sprintf(":%s ", m.prefix))
	}
	raw.WriteString(m.command)
	raw.WriteString(" ")
	needspc := false
	isTrail := func(parm string) bool {
		return strings.Index(parm, " ") != -1
	}
	for _, b := range m.parameters {
		if needspc {
			raw.WriteString(" ")
		}
		if isTrail(b) {
			raw.WriteString(":")
		}
		raw.WriteString(b)
		needspc = true
	}
	return raw.String()
}
func (m *ircmessage) Last() *string {
	if len(m.parameters) < 1 { return nil }
	return &m.parameters[len(m.parameters)-1]
}
func parseMessage(raw string) (msg *ircmessage, err error) {
	//TODO FFS rewrite this in regexp
	const space = " "
	if len(raw) < 3 {
		return nil, nil
	}
	if len(raw) > IRC_max_message_length {
		return nil, errors.New( "message too long")
	}
	if strings.Index(raw, "\r\n") != -1 {
		return nil, errors.New( "raw message contains CR LN!")
	}
	var idx int = -1
	rv := new(ircmessage)
	rv.raw = raw
	rv.valid = false
	//colon starts the prefix, up to whitespace
	raw = strings.Trim(raw, space)
	if raw[0] == ':' {
		idx = strings.Index(raw, " ")
		if idx == -1 {
			return nil, errors.New( "prefix started but no end")
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
			return nil, errors.New( "no command given")
		}
	}
	//command up to whitespace
	rv.command = strings.ToUpper(raw[0:idx])
	raw = raw[idx:]
	raw = strings.TrimLeft(raw, space)
	//params, muliple whitespace separated, trailer might be ":" separated
	var trailing string
	idx = strings.Index(raw, ":")
	if idx != -1 {
		trailing = raw[idx+1:]
		raw = raw[0:idx]
	}
	tmp := strings.Split(raw, " ")
	for _, t := range tmp {
		t = strings.Trim(t, space)
		if len(t) > 0 {
			rv.parameters = append(rv.parameters, t)
		}
	}
	if len(trailing) > 0 {
		rv.parameters = append(rv.parameters, trailing)
	}
	rv.valid = true
	return rv, nil
}
