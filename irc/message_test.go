// Copyright (c) Marius Börschig. All rights reserved.
// Licensed under the BSD-3-Clause License.
package irc

import "testing"
var messageTestsOk  =[]struct {
	in string
	out *ircmessage
}{
	{
		":hello!world@foobar NICK hello",
		&ircmessage{prefix: "hello!world@foobar", command: "NICK", parameters:[]string{"hello"}},
	},
	{
		":hello!world@foobar PRIVMSG #foobar hello :whats up?",
		&ircmessage{prefix: "hello!world@foobar", command: "PRIVMSG", parameters:[]string{"#foobar", "hello", "whats up?"}},
	},
}
func TestMessage(t *testing.T) {
	for _, mt := range messageTestsOk {
		// optional string helper
		derefStr := func (context string, str *string) string {
			if str == nil {
				t.Errorf("%s: Method %s  returned nil!", mt.in, context)
				return ""
			}
			return *str
		}
		tmp, err := NewMessage(mt.in)
		if err != nil {
			t.Errorf("TestMessage: cannot parse message input %s: %s", mt.in, err)
		}
		if derefStr("Prefix", tmp.Prefix()) != mt.out.prefix {
			t.Errorf("TestMessage: input %s: prefix %v != %s",
				mt.in, tmp.Prefix(), mt.out.prefix)
		}
		if derefStr("Command", tmp.Command()) != mt.out.command {
			t.Errorf("TestMessage: input %s: command %v != %s",
				mt.in, tmp.Command(), mt.out.command)
		}
		if tmp.NumParameters() != len(mt.out.parameters) {
			t.Errorf("TestMessage: input %s: parameters %v != %v",
				mt.in, tmp.Parameters(), mt.out.parameters)
		}
		if ! tmp.Valid() {
			t.Errorf("TestMessage: input %s: is invalid: %v", mt.in, tmp)
		}
	}
}
