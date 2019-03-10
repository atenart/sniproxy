// Copyright (C) 2019 Antoine Tenart <antoine.tenart@ack.tf>
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
	"fmt"
	"io"
	"log"
	"net"

	"github.com/atenart/sniproxy/config"
)

// Represents the proxy itself.
type Proxy struct {
	Config config.Config
}

// Listen and serve the connexions.
func (p *Proxy) ListenAndServe(bind string) error {
	l, err := net.Listen("tcp", bind)
	if err != nil {
		return err
	}
	defer l.Close()

	// Accept connexions and handle them to a go routine.
	for {
		conn, err := l.Accept()
		if err != nil {
			return err
		}

		go p.dispatchConn(conn)
	}

	return nil
}

// Dispatch a net.Conn. This cannot fail.
func (p *Proxy) dispatchConn(conn net.Conn) {
	defer conn.Close()

	var buf bytes.Buffer
	sni, err := extractSNI(io.TeeReader(conn, &buf))
	if err != nil {
		log.Println(err)
		return
	}

	backend, err := p.Match(sni)
	if err != nil {
		log.Println(err)
		return
	}

	upstream, err := net.Dial("tcp", backend)
	if err != nil {
		log.Println(err)
		return
	}
	defer upstream.Close()

	// Replay the handshake we read.
	if _, err := io.Copy(upstream, &buf); err != nil {
		log.Println("Failed to replay handshake to %s", backend)
		return
	}

	go io.Copy(upstream, conn)
	io.Copy(conn, upstream)
}

// Matches a connexion to a backend.
func (p *Proxy) Match(sni string) (string, error) {
	// Loop over each route described in the configuration.
	for _, route := range p.Config.Routes {
		// Loop over each domain of a given route.
		for _, domain := range route.Domains {
			if domain.MatchString(sni) {
				return route.Backend, nil
			}
		}
	}

	return "", fmt.Errorf("No route matching the requested domain (%s)", sni)
}
