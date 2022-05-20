// Copyright (C) 2019-2022 Antoine Tenart <antoine.tenart@ack.tf>
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License
// along with this program. If not, see <https://www.gnu.org/licenses/>.

package sniproxy

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"net"
)

// Handles sending an HAProxy PROXY header to a backend.
func proxyHeader(version uint, client, upstream net.Conn) error {
	var header bytes.Buffer

	// Retrieve the PROXY header to be sent.
	switch (version) {
	case ProxyV1:
		header = proxyHeaderV1(client)
		break
	case ProxyV2:
		header = proxyHeaderV2(client)
		break
	default:
		return fmt.Errorf("PROXY protocol version not supported (%d)", version)
	}

	// Send the PROXY header to the backend.
	if _, err := header.WriteTo(upstream); err != nil {
		return fmt.Errorf("Could not send the PROXY header (%s)", err)
	}

	return nil
}

// Returns an HAProxy PROXY header (protocol v1).
func proxyHeaderV1(conn net.Conn) bytes.Buffer {
	client := conn.RemoteAddr().(*net.TCPAddr)
	local := conn.LocalAddr().(*net.TCPAddr)

	inetProto := "TCP6"
	if local.IP.To4() != nil {
		inetProto = "TCP4"
	}

	var buf bytes.Buffer
	buf.WriteString(fmt.Sprintf("PROXY %s %s %s %d %d\r\n", inetProto,
				    client.IP.String(), local.IP.String(),
				    client.Port, local.Port))
	return buf
}

// Returns an HAProxy PROXY header (protocol v2).
// See https://www.haproxy.org/download/2.0/doc/proxy-protocol.txt
func proxyHeaderV2(conn net.Conn) bytes.Buffer {
	client := conn.RemoteAddr().(*net.TCPAddr)
	local := conn.LocalAddr().(*net.TCPAddr)
	ipv4 := local.IP.To4() != nil

	var buf bytes.Buffer

	// Protocol signature.
	buf.Write([]byte{0x0d, 0x0a, 0x0d, 0x0a, 0x00, 0x0d, 0x0a, 0x51, 0x55, 0x49, 0x54, 0x0a})

	// Command. Must be \x2 followed by \x0 for 'local' or \x1 for 'proxy'.
	buf.WriteByte(0x21)

	// Transport protocol and address family. The highest 4 bits represent
	// the address family (0x1: AF_INET, 0x2: AF_INET6) and the lowest 4
	// bits the protocol (0x1: SOCK_STREAM).
	// The address family part is set at the begining of the function.
	if ipv4 {
		buf.WriteByte(0x11)
	} else {
		buf.WriteByte(0x21)
	}

	tmp := make([]byte, 2)

	// Address length.
	if ipv4 {
		binary.BigEndian.PutUint16(tmp, 12)
	} else {
		binary.BigEndian.PutUint16(tmp, 36)
	}
	buf.Write(tmp)

	// Addresses (client, local).
	if ipv4 {
		buf.Write(client.IP.To4())
		buf.Write(local.IP.To4())
	} else {
		buf.Write(client.IP.To16())
		buf.Write(local.IP.To16())
	}

	// TCP ports (client, local).
	binary.BigEndian.PutUint16(tmp, uint16(client.Port))
	buf.Write(tmp)
	binary.BigEndian.PutUint16(tmp, uint16(local.Port))
	buf.Write(tmp)

	return buf
}
