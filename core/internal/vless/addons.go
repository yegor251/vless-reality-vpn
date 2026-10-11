package vless

import "encoding/binary"

// XRV is the flow name negotiated through the Addons protobuf message.
const XRV = "xtls-rprx-vision"

// ParseFlow extracts the flow name from a raw Addons protobuf message
// (message Addons { string Flow = 1; bytes Seed = 2; }).
func ParseFlow(addons []byte) string {
	if len(addons) == 0 || addons[0] != 0x0a { // field 1, wire type 2
		return ""
	}
	n, skip := binary.Uvarint(addons[1:])
	if skip <= 0 || 1+skip+int(n) > len(addons) {
		return ""
	}
	return string(addons[1+skip : 1+skip+int(n)])
}
