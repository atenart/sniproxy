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
	"sync"

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

	route, err := p.Match(sni)
	if err != nil {
		log.Println(err)
		return
	}

	// Check if the client has the right to connect to a given backend.
	ip, _, err := net.SplitHostPort(conn.RemoteAddr().String())
	if err != nil {
		log.Print(err)
		return
	}
	if !clientAllowed(route, ip) {
		log.Printf("Denied %s / %s access to %s", ip, sni, route.Backend)
		return
	}

	upstream, err := net.Dial("tcp", route.Backend)
	if err != nil {
		log.Println(err)
		return
	}
	defer upstream.Close()

	// Replay the handshake we read.
	if _, err := io.Copy(upstream, &buf); err != nil {
		log.Printf("Failed to replay handshake to %s", route.Backend)
		return
	}

	log.Printf("Routing %s / %s to %s", conn.RemoteAddr(), sni, route.Backend)

	var wg sync.WaitGroup
	wg.Add(2)
	go func () {
		defer wg.Done()
		io.Copy(upstream, conn)
	}()
	go func () {
		defer wg.Done()
		io.Copy(conn, upstream)
	}()
	wg.Wait()
}

// Matches a connexion to a backend.
func (p *Proxy) Match(sni string) (*config.Route, error) {
	// Loop over each route described in the configuration.
	for _, route := range p.Config.Routes {
		// Loop over each domain of a given route.
		for _, domain := range route.Domains {
			if domain.MatchString(sni) {
				return route, nil
			}
		}
	}

	return nil, fmt.Errorf("No route matching the requested domain (%s)", sni)
}

// Check an IP against a route deny/allow rules.
// The more specific subnet takes precedence, and Deny wins over Allow in case
// none is more specific.
func clientAllowed(route *config.Route, ip string) bool {
	// Check if filtering is enabled for the route.
	if len(route.Allow) == 0 && len(route.Deny) == 0 {
		return true
	}

	client := net.ParseIP(ip)
	if client == nil {
		log.Printf("Could not parse client IP (%s), dennying access", ip)
		return false
	}

	var cidr int = 0
	for _, subnet := range(route.Allow) {
		if subnet.Contains(client) {
			sz, _ := subnet.Mask.Size()
			if sz > cidr {
				cidr = sz
			}
		}
	}
	for _, subnet := range(route.Deny) {
		if subnet.Contains(client) {
			sz, _ := subnet.Mask.Size()
			if sz >= cidr {
				return false
			}
		}
	}
	return true
}
