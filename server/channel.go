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
	updater    chan func() //async update calls

	//TODO exception masks
}

func NewChannel(name string) *ircchannel {
	nuch := new(ircchannel)
	nuch.name = name
	nuch.members = make(map[string]*ircclient)
	nuch.userFlags = make(map[*ircclient]string)
	nuch.created = time.Now()
	nuch.updater = make(chan func())
	go func() {
		for {
			//centrally dispatch/udpate values
			select  {
			case cb := <-nuch.updater:
				cb()
			}
		}
	}()
	return nuch
}
func (self *ircchannel) asyncUpdate(thunk func()) {
	rv := make(chan bool)
	self.updater <- func() {
		thunk()
		rv <- true
	}
	<-rv
}
func (self *ircchannel) RemoveClient(client *ircclient) {
	self.asyncUpdate(func() {
		delete(client.channels, self.name)
		delete(self.members, client.nickname)
		delete(self.userFlags, client)
	})
}
func (self *ircchannel) AddClient(client *ircclient) {
	self.asyncUpdate(func() {
		self.members[client.nickname] = client
		self.userFlags[client] = ""
		client.trace("[%s] %s joined %s", client.id, client.nickname, self.name)
		client.channels[self.name] = self
	})
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
	rv := make([]*ircclient, 0)
	self.asyncUpdate(func() {
		for _, mem := range self.members {
			rv = append(rv, mem)
		}
	})
	return rv
}
func (self *ircchannel) GetMode() string {
	return self.mode
}

func (self *ircchannel) IsMember(nick *ircclient) bool {
	rv := false
	self.asyncUpdate(func() {
		for _, user := range self.members {
			if nick == user {
				rv = true
				break
			}
		}
	})
	return rv
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
func (ch *ircchannel) SendMessage(msg *clientMessage) {
	if !ch.IsMember(msg.source) {
		msg.source.debug("deliver: %s is not a member of %s", msg.source.nickname, ch.name)
		msg.source.numericReply(irc.ERR_CANNOTSENDTOCHAN, ch.name)
		return
	}
	ch.asyncUpdate(func() {
		for _, client := range ch.members {
			if client == msg.source {
				if *msg.Command() == "PRIVMSG" || *msg.Command() == "NOTICE" {
					continue
				}
				if *msg.Command() == "QUIT" {
					continue
				}
			}
			if !client.IsDone() {
				client.send( msg.Raw())
			}
		}
	})
}
