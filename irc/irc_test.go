// Copyright (c) Marius Börschig. All rights reserved.
// Licensed under the BSD-3-Clause License.
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
