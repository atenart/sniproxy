// Copyright (C) 2019-2021 Antoine Tenart <antoine.tenart@ack.tf>
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

package main

import (
	"bytes"
	"testing"
)

func craft(bs ...[]byte) []byte {
	var packet []byte
	for _, b := range(bs) {
		packet = append(packet, b...)
	}
	return packet
}

func TestParseRecord(t *testing.T) {
	tests := []struct {
		desc    string
		in      []byte
		success bool
	}{
		{
			"Empty message",
			[]byte{},
			false,
		},
		{
			"Truncated message #0",
			[]byte{22},
			false,
		},
		{
			"Truncated message #2",
			[]byte{22, 3},
			false,
		},
		{
			"Truncated message #3",
			[]byte{22, 3, 2},
			false,
		},
		{
			"Truncated message #4",
			[]byte{22, 3, 2, 0},
			false,
		},
		{
			"SSL 3.0",
			[]byte{22, 3, 0, 0, 0},
			false,
		},
		{
			"TLS 1.0, empty payload",
			[]byte{22, 3, 1, 0, 0},
			true,
		},
		{
			"TLS 1.1, empty payload",
			[]byte{22, 3, 2, 0, 0},
			true,
		},
		{
			"TLS 1.2 or later, empty payload",
			[]byte{22, 3, 3, 0, 0},
			true,
		},
		{
			"TLS 1.2 or later, 1b payload",
			[]byte{22, 3, 3, 0, 1, 0},
			true,
		},
		{
			"TLS 1.2 or later, max message length payload",
			[]byte{22, 3, 3, 64, 0},
			true,
		},
		{
			"TLS 1.2 or later, (max message length + 1) payload",
			[]byte{22, 3, 3, 64, 1},
			false,
		},
		{
			"Wrong TLS content type",
			[]byte{99, 3, 2, 0, 0},
			false,
		},
		{
			"Wrong TLS major version",
			[]byte{22, 4, 2, 0, 0},
			false,
		},
		{
			"Wrong TLS minor version",
			[]byte{22, 3, 99, 0, 0},
			false,
		},
	}

	for _, test := range(tests) {
		err := parseRecord(bytes.NewBuffer(test.in))
		if (test.success && (err != nil)) || (!test.success && (err == nil)) {
			t.Errorf(test.desc)
		}
	}
}

func TestParseHandshake(t *testing.T) {
	tests := []struct {
		desc    string
		in      []byte
		success bool
	}{
		{
			"Empty handshake",
			[]byte{},
			false,
		},
		{
			"Truncated handshake #0",
			[]byte{1, 0},
			false,
		},
		{
			"Truncated handshake #1",
			[]byte{1, 0, 0},
			false,
		},
		{
			"Wrong message type",
			[]byte{99, 0, 0, 0},
			false,
		},
		{
			"ClientHello handshake, no payload",
			[]byte{1, 0, 0, 0},
			true,
		},
		{
			"ClientHello handshake, 34b payload",
			[]byte{1, 0, 0, 34},
			true,
		},
	}

	for _, test := range(tests) {
		err := parseHandshake(bytes.NewBuffer(test.in))
		if (test.success && (err != nil)) || (!test.success && (err == nil)) {
			t.Errorf(test.desc)
		}
	}
}

func TestParseClientHello(t *testing.T) {
	tests := []struct {
		desc    string
		in      []byte
		success bool
	}{
		{
			"Empty message",
			[]byte{},
			false,
		},
		{
			"ClientHello TLS 1.2 or later, no payload",
			craft([]byte{3, 3}, make([]byte, 32)),
			false,
		},
		{
			"ClientHello TLS 1.2 or later, 0'ed payload",
			craft([]byte{3, 3}, make([]byte, 32), []byte{0, 0, 0, 0}),
			false,
		},
		{
			"ClientHello TLS1.0, valid payload",
			craft([]byte{3, 1}, make([]byte, 32), []byte{0, 0, 2, 0, 0, 1, 0}),
			true,
		},
		{
			"ClientHello TLS1.1, valid payload",
			craft([]byte{3, 2}, make([]byte, 32), []byte{0, 0, 2, 0, 0, 1, 0}),
			true,
		},
		{
			"ClientHello TLS 1.2 or later, valid payload",
			craft([]byte{3, 3}, make([]byte, 32), []byte{0, 0, 2, 0, 0, 1, 0}),
			true,
		},
		{
			"ClientHello wrong TLS major version",
			craft([]byte{4, 2}, make([]byte, 32), []byte{0, 0, 2, 0, 0, 1, 0}),
			false,
		},
		{
			"ClientHello wrong TLS minor version",
			craft([]byte{3, 99}, make([]byte, 32), []byte{0, 0, 2, 0, 0, 1, 0}),
			false,
		},
		{
			"ClientHello TLS 1.2 or later, max session ID length",
			craft([]byte{3, 3}, make([]byte, 32), []byte{32}, make([]byte, 32),
			      []byte{0, 2, 0, 0, 1, 0}),
			true,
		},
		{
			"ClientHello TLS 1.2 or later, (max + 1) session ID length",
			craft([]byte{3, 3}, make([]byte, 32), []byte{33}, make([]byte, 33),
			      []byte{0, 2, 0, 0, 1, 0}),
			false,
		},
		{
			"ClientHello TLS 1.2 or later, invalid cipher suites length #0",
			craft([]byte{3, 3}, make([]byte, 32), []byte{0, 0, 1, 0, 1, 0}),
			false,
		},
		{
			"ClientHello TLS 1.2 or later, invalid cipher suites length #1",
			craft([]byte{3, 3}, make([]byte, 32), []byte{0, 0, 33}, make([]byte, 33),
			      []byte{0, 1, 0}),
			false,
		},
		{
			"ClientHello TLS 1.2 or later, invalid compression methods length",
			craft([]byte{3, 3}, make([]byte, 32), []byte{0, 0, 1, 0, 0}),
			false,
		},
		{
			"ClientHello TLS 1.2 or later, valid payload, max size",
			craft([]byte{3, 3}, make([]byte, 32), []byte{32}, make([]byte, 32),
			      []byte{0xff, 0xfe}, make([]byte, 0xfffe),
			      []byte{0xff}, make([]byte, 0xff)),
			true,
		},
	}

	for _, test := range(tests) {
		err := parseClientHello(bytes.NewBuffer(test.in))
		if (test.success && (err != nil)) || (!test.success && (err == nil)) {
			t.Errorf(test.desc)
		}
	}
}

func TestParseSNI(t *testing.T) {
	tests := []struct{
		desc    string
		in      []byte
		out     string
		success bool
	}{
		{
			"Empty SNI extension",
			[]byte{},
			"",
			false,
		},
		{
			"Invalid SNI extension vector",
			[]byte{0},
			"",
			false,
		},
		{
			"Empty SNI extension",
			[]byte{0, 0},
			"",
			true,
		},
		{
			"Invalid SNI vector",
			[]byte{0, 2, 0, 0},
			"",
			true,
		},
		{
			"Empty SNI vector",
			[]byte{0, 3, 0, 0, 0},
			"",
			true,
		},
		{
			"Invalid name type",
			[]byte{0, 6, 1, 0, 3, 1, 2, 3},
			"",
			true,
		},
		{
			"Valid SNI",
			craft([]byte{0, 14, 0, 0, 11}, []byte("example.net")),
			"example.net",
			true,
		},
		{
			"Multiple SNI vectors",
			craft([]byte{0, 28, 0, 0, 11}, []byte("example.net"),
			      []byte{0, 0, 11}, []byte("example.org")),
			"example.net",
			true,
		},
		{
			"SNI in second vector",
			craft([]byte{0, 22, 1, 0, 5, 1, 2, 3, 4, 5},
			      []byte{0, 0, 11}, []byte("example.net")),
			"example.net",
			true,
		},
	}

	for _, test := range(tests) {
		sni, err := parseSNI(test.in)
		if (test.success && (err != nil)) || (!test.success && (err == nil)) {
			t.Errorf(test.desc)
		}
		if sni != test.out {
			t.Errorf("%s: wrong SNI: got '%s', wanted '%s'", test.desc, sni, test.out)
		}
	}
}
