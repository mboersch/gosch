// Copyright (c) Marius Börschig. All rights reserved.
// Licensed under the BSD-3-Clause License.
package server
import (
    "time"
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
