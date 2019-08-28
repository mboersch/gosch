// Copyright (c) Marius Börschig. All rights reserved.
// Licensed under the BSD 3-Clause License. See the LICENSE file.
package server

import (
	"github.com/mboersch/gosch/irc"
	"strings"
	"time"
)

//ircchannel
type ircchannel struct {
	name       string
	members    map[string]*ircclient
	userFlags  map[*ircclient]string
	topic      string
	topicSetBy string
	topicSetOn time.Time
	mode       string
	maxUsers   uint
	secretKey  string
	created    time.Time
	creator    *ircclient
	//TODO exception masks
}

func NewChannel(name string) *ircchannel {
	nuch := new(ircchannel)
	nuch.name = name
	nuch.members = make(map[string]*ircclient)
	nuch.userFlags = make(map[*ircclient]string)
	nuch.created = time.Now()
	return nuch
}
func (self *ircchannel) RemoveClient(client *ircclient) {
	delete(client.channels, self.name)
	delete(self.members, client.nickname)
	delete(self.userFlags, client)
}
func (self *ircchannel) AddClient(client *ircclient) {
	self.members[client.nickname] = client
	self.userFlags[client] = ""
	client.trace("[%s] %s joined %s", client.id, client.nickname, self.name)
	client.channels[self.name] = self
}

// user flags
func (self *ircchannel) GetUserFlags(nick *ircclient) string {
	if flag, ok := self.userFlags[nick]; ok {
		return flag
	}
	return ""
}
func (self *ircchannel) SetUserFlag(client *ircclient, mod rune) {
	if self.creator == nil && mod == 'O' {
		self.creator = client
	}
	self.userFlags[client] += string(mod)
}

func (self *ircchannel) IsOperator(client *ircclient) bool {
	for _, mod := range self.GetUserFlags(client) {
		if mod == 'o' {
			return true
		}
	}
	return false
}
func (self *ircchannel) IsVoice(client *ircclient) bool {
	for _, mod := range self.GetUserFlags(client) {
		if mod == 'v' {
			return true
		}
	}
	return false
}

// channel flags

func (self *ircchannel) isModerated() bool {
	for _, m := range self.mode {
		if m == 'm' {
			return true
		}
	}
	return false
}
func (self *ircchannel) setMode(mod rune) bool {
	if !irc.IsValidChannelMode(mod) {
		return false
	}
	self.mode += string(mod)
	return true
}
func (self *ircchannel) clearMode(mod rune) {
	var tmp string
	for _, t := range self.mode {
		if t != mod {
			tmp += string(t)
		}
	}
	self.mode = tmp
}

func (self *ircchannel) GetMembers() []*ircclient {
	rv := make([]*ircclient, len(self.members))
	i := 0
	for _, mem := range self.members {
		rv[i] = mem
		i += 1
	}
	return rv
}
func (self *ircchannel) GetMode() string {
	return self.mode
}

func (self *ircchannel) IsMember(nick *ircclient) bool {
	for _, user := range self.members {
		if nick == user {
			return true
		}
	}
	return false
}
func (self *ircchannel) GetCreator() *ircclient {
	return self.creator
}
func (ircc ircchannel) String() string {
	return ircc.name
}
func IsValidChannelName(nameToTest string) bool {
	if len(nameToTest) > irc.IRC_max_channel_name_length {
		return false
	}
	if !irc.IsChannelName(nameToTest) {
		return false
	}
	if strings.IndexByte(nameToTest, ' ') != -1 {
		return false
	}
	if strings.IndexByte(nameToTest, ',') != -1 {
		return false
	}
	if strings.IndexByte(nameToTest, '\x07') != -1 {
		return false
	} //Ctrl-G
	return true
}
