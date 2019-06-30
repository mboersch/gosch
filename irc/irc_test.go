//Copyright (C) 2019  Marius Boerschig <code (at) boerschig (dot) net>
package irc
import (
    "testing"
)

func TestIRCDefs(t *testing.T) {
    if RPL_TOPIC.String() != "332" {
        t.Fatalf("numericReply type for RPL_TOPIC does not convert to string \"332\": result %v",
            RPL_TOPIC.String())
    }
}
