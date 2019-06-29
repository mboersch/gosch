//Copyright (C) 2019  Marius Boerschig <code (at) boerschig (dot) net>
package server
import (
    "fmt"
    "strconv"
    "strings"
)
type ircmessage struct {
    raw string
    prefix string
    command string
    trailing string //should be just another parameter
    parameters []string
    source *ircclient
}

// ircmessage
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
        param.WriteString(";")
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
func ircParseMessage( raw string) (msg *ircmessage, err error) {
    //TODO FFS rewrite this in regexp
    const space = " "
    fmt.Printf("msg = %s\n", strconv.QuoteToASCII(raw))
    if len(raw) < 3  {
        return nil, nil
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
        if idx == -1  {
            return nil, ircError{-1, "prefix started but no end"}
        }
        rv.prefix=raw[1:idx]
        raw=raw[idx:]
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
    rv.command = raw[0:idx]
    raw = raw[idx:]
    raw = strings.TrimLeft(raw, space)
    //params, muliple whitespace separated, trailer might be ":" separated
    idx = strings.Index(raw, ":")
    if idx != -1 {
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
