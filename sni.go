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
	"encoding/binary"
	"fmt"
	"io"
)

// Extracts required information from a TLS handshake.
// Returns the SNI and checks for acme-tls.
func extractInfo(r io.Reader) (string, bool, error) {
	if err := parseRecord(r); err != nil {
		return "", false, err
	}

	if err := parseHandshake(r); err != nil {
		return "", false, err
	}

	if err := parseClientHello(r); err != nil {
		return "", false, err
	}

	// Parse the TLS extension, looking for a server name indication.
	b, err := parseVector(r, 2)
	if err != nil {
		// No extension (not an error).
		if err == io.EOF {
			err = nil
		}
		return "", false, err
	}

	sni := ""
	acme := false

	// Loop over the TLS extensions.
	for len(b) >= 4 {
		extType := binary.BigEndian.Uint16(b[:2])
		length := binary.BigEndian.Uint16(b[2:4])
		b = b[4:]

		switch(extType) {
		// SNI.
		case 0:
			sni, err = parseSNI(b[:length])
			if err != nil {
				break
			}
		// ALPN.
		case 16:
			acme, err = parseACME(b[:length])
			if err != nil {
				break
			}
		}

		b = b[length:]
	}

	return sni, acme, err
}

// Parse a TLS Plaintext record.
func parseRecord(r io.Reader) error {
	var record struct {
		Type          uint8
		Major, Minor  uint8
		Length        uint16
	}
	if err := binary.Read(r, binary.BigEndian, &record); err != nil {
		return fmt.Errorf("Could not read TLS handshake (%s)", err)
	}

	// Check if record type is 22, aka handshake.
	if record.Type != 22 {
		return fmt.Errorf("Record is not a TLS handshake")
	}

	// Checks the TLS version is supported:
	// 3.1: TLS 1.0, 3.2: TLS 1.1, 3.3: TLS 1.2 & TLS 1.3
	if record.Major != 3 {
		return fmt.Errorf("TLS version not supported (%d.%d)", record.Major, record.Minor)
	}
	switch (record.Minor) {
	default:
		return fmt.Errorf("TLS version not supported (%d.%d)", record.Major, record.Minor)
	case 1,2,3:
	}

	// Check the handshake does not exceed the max authorized.
	if record.Length > (16 * 1024) {
		return fmt.Errorf("TLS record length exceed maximum (%d > 2^14)", record.Length)
	}

	return nil
}

// Parse a TLS handshake message.
func parseHandshake(r io.Reader) error {
	var handshake struct {
		MessageType   uint8
		MessageLength [3]byte
	}
	if err := binary.Read(r, binary.BigEndian, &handshake); err != nil {
		return fmt.Errorf("Could not read TLS message header (%s)", err)
	}

	// Check if the message type is ClientHello.
	if handshake.MessageType != 1 {
		return fmt.Errorf("TLS handshake is not a ClientHello message (%d)", handshake.MessageType)
	}

	// We do not check the handshake length as we'll try to read it fully anyway.

	return nil
}

// Parse a TLS ClientHello message.
func parseClientHello(r io.Reader) error {
	var hello struct {
		Version uint16
		Random  [32]byte
	}
	if err := binary.Read(r, binary.BigEndian, &hello); err != nil {
		return fmt.Errorf("Could not read TLS ClientHello message (%s)", err)
	}

	// Checks the version:
	// 0x301: TLS 1.0, 0x302: TLS 1.1, 0x303 after TLS 1.2.
	switch (hello.Version) {
	default:
		return fmt.Errorf("ClientHello version is not 0x303 (%#x)", hello.Version)
	case 0x301, 0x302, 0x303:
	}

	// We do not check other fields strictly, but reading them ensure they
	// are present (ie. the message seems to be a valid ClientHello).

	// SessionID.
	b, err := parseVector(r, 1)
	if err != nil {
		return fmt.Errorf("Could not read ClientHello session ID (%s)", err)
	}
	if len(b) > 32 {
		return fmt.Errorf("ClientHello SessionID has an invalid length (%d)", len(b))
	}

	// Cipher Suites.
	b, err = parseVector(r, 2)
	if err != nil {
		return fmt.Errorf("Could not read ClientHello cipher suites (%s)", err)
	}
	if len(b) < 2 || len(b) % 2 != 0 {
		return fmt.Errorf("ClientHello cipher suites has an invalid length (%d)", len(b))
	}

	// Compression methods.
	b, err = parseVector(r, 1)
	if err != nil {
		return fmt.Errorf("Could not read ClientHello compression methods (%s)", err)
	}
	if len(b) < 1 {
		return fmt.Errorf("ClientHello compression methods has an invalid length (%d)", len(b))
	}

	// We reached the extensions (or none, which is valid).
	return nil
}

// Parse the SNI from an SNI extension.
func parseSNI(b []byte) (string, error) {
	if len(b) < 2 {
		return "", fmt.Errorf("SNI extension is empty.")
	}

	length := binary.BigEndian.Uint16(b[:2])
	if int(length) > len(b[2:]) {
		return "", fmt.Errorf("SNI extension is too short.")
	}

	b = b[2:2+length]

	for len(b) >= 3 {
		nameType := b[0]
		vectLength := binary.BigEndian.Uint16(b[1:3])
		if int(vectLength) > len(b[3:]) {
			return "", fmt.Errorf("SNI vector is too short.")
		}

		if nameType != 0 {
			b = b[3+vectLength:]
			continue
		}

		return string(b[3 : 3+vectLength]), nil
	}

	// No DNS-based SNI.
	return "", nil
}

// Parse a vector and returns a byte array. Takes the length of the len field as
// an argument.
func parseVector(r io.Reader, l uint) ([]byte, error) {
	rawLen := make([]byte, l)
	if err := binary.Read(r, binary.BigEndian, &rawLen); err != nil {
		// No data to read. This can be valid.
		if err == io.EOF {
			return nil, err
		}
		return nil, fmt.Errorf("Could not read the vector length (%s)", err)
	}

	var length uint = 0
	for _, b := range rawLen {
		length = (length << 8) + uint(b)
	}

	if length == 0 {
		return nil, nil
	}

	data := make([]byte, length)
	if err := binary.Read(r, binary.BigEndian, &data); err != nil {
		return nil, fmt.Errorf("Could not read the vector data (%s)", err)
	}

	return data, nil
}

// Parse an ALPN extension looking for acme-tls/1.
func parseACME(b []byte) (bool, error) {
	if len(b) < 2 {
		return false, fmt.Errorf("ALPN extension is empty.")
	}

	length := binary.BigEndian.Uint16(b[:2])
	if int(length) > len(b[2:]) {
		return false, fmt.Errorf("ALPN extension is too short.")
	}

	b = b[2:2+length]

	for len(b) > 2 {
		stringLen := int(b[0])

		b = b[1:]
		if stringLen == 0 || stringLen > len(b) {
			return false, fmt.Errorf("ALPN string length overflowed")
		}

		if string(b[:stringLen]) == "acme-tls/1" {
			return true, nil
		}

		b = b[stringLen:]
	}

	return false, nil
}
