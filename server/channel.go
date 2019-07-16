// Copyright (c) Marius Börschig. All rights reserved.
// Licensed under the BSD-3-Clause License.
package server
import (
    "github.com/mboersch/gosch/irc"
    "time"
    "strings"
)
//ircchannel 
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

func NewChannel(name string) *ircchannel {
    nuch := new(ircchannel)
    nuch.name = name
    nuch.members = make(map[string]*ircclient)
    nuch.userFlags = make(map[string]string)
    nuch.created = time.Now()
    return nuch
}
func (self *ircchannel) RemoveClient(client *ircclient) {
    delete(client.channels, self.name)
    delete(self.members, client.nickname)
    delete(self.userFlags, client.nickname)
}
func (self *ircchannel) AddClient(client *ircclient) {
    self.members[client.nickname] = client
    self.userFlags[client.nickname] = ""
    client.trace("[%s] %s joined %s", client.id, client.nickname, self.name)
    client.channels[self.name] = self
}

func (self *ircchannel) getUserFlags(nick string) string {
    if flag, ok := self.userFlags[nick]; ok {
        return flag
    }
    return ""
}

func (self *ircchannel) isOperator(nick string) bool {
    for mod := range self.getUserFlags(nick) {
        if mod == 'o' { return true}
    }
    return false
}
func (self *ircchannel) isVoice(nick string) bool {
    for mod := range self.getUserFlags(nick) {
        if mod == 'v' { return true}
    }
    return false
}
func (self *ircchannel) getNicks() []string {
    rv := make([]string, len(self.members))
    for n:= range self.members {
        rv = append(rv, n)
    }
    return rv
}

func (self *ircchannel) isMember(nick *ircclient) bool {
    for _, user :=  range self.members {
        if  nick == user {
            return true
        }
    }
    return false
}
func (ircc ircchannel) String() string {
    return ircc.name
}
func IsValidChannelName(nameToTest string) bool {
    if len(nameToTest) > irc.IRC_max_channel_name_length {
        return false
    }
    if ! irc.IsChannelName(nameToTest) {
        return false
    }
    if strings.IndexByte(nameToTest, ' ') != -1 { return false }
    if strings.IndexByte(nameToTest, ',') != -1 { return false }
    if strings.IndexByte(nameToTest, '\x07') != -1 { return false } //Ctrl-G
    return true
}
