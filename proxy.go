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
	"time"

	"github.com/atenart/sniproxy/config"
)

// Represents the proxy itself.
type Proxy struct {
	Config config.Config
}

// Represents a connection being routed.
type Conn struct {
	*net.TCPConn
	Config *config.Config
}

// Listen and serve the connections.
func (p *Proxy) ListenAndServe(bind string) error {
	l, err := net.Listen("tcp", bind)
	if err != nil {
		return err
	}
	defer l.Close()

	// Accept connections and handle them to a go routine.
	for {
		c, err := l.Accept()
		if err != nil {
			return err
		}

		conn := &Conn{
			TCPConn: c.(*net.TCPConn),
			Config: &p.Config,
		}

		go conn.dispatch()
	}

	return nil
}

// Dispatch a net.Conn. This cannot fail.
func (conn *Conn) dispatch() {
	defer conn.Close()

	// Set a deadline for reading the TLS handshake.
	if err := conn.SetReadDeadline(time.Now().Add(3*time.Second)); err != nil {
		conn.alert(tlsInternalError)
		conn.logf("Could not set a read deadline (%s)", err)
		return
	}

	var buf bytes.Buffer
	sni, err := extractSNI(io.TeeReader(conn, &buf))
	if err != nil {
		conn.alert(tlsInternalError)
		conn.log(err)
		return
	}

	// We found an SNI, reset the read deadline.
	if err := conn.SetReadDeadline(time.Time{}); err != nil {
		conn.alert(tlsInternalError)
		conn.logf("Could not clear the read deadline (%s)", err)
		return
	}

	route, err := conn.Match(sni)
	if err != nil {
		conn.alert(tlsUnrecognizedName)
		conn.log(err)
		return
	}

	// Check if the client has the right to connect to a given backend.
	client := conn.RemoteAddr().(*net.TCPAddr).IP
	if !clientAllowed(route, client) {
		conn.alert(tlsAccessDenied)
		conn.logf("Denied %s / %s access to %s", client.String(), sni, route.Backend)
		return
	}

	upstream := func() *net.TCPConn {
		up, err := net.DialTimeout("tcp", route.Backend, 3*time.Second)
		if err != nil {
			conn.alert(tlsInternalError)
			conn.log(err)
			return nil
		}
		return up.(*net.TCPConn)
	}()
	if upstream == nil {
		return
	}
	defer upstream.Close()

	// Check if the HAProxy PROXY protocol header has to be sent.
	if route.SendProxy != config.ProxyNone {
		if err := proxyHeader(route, conn, upstream); err != nil {
			conn.alert(tlsInternalError)
			log.Print(err)
			return
		}
	}

	// Replay the handshake we read.
	if _, err := io.Copy(upstream, &buf); err != nil {
		conn.alert(tlsInternalError)
		conn.logf("Failed to replay handshake to %s", route.Backend)
		return
	}

	done := make(chan int, 1)
	go func () {
		io.Copy(upstream, conn.TCPConn)
		done<- 1
	}()
	go func () {
		io.Copy(conn.TCPConn, upstream)
		done<- 1
	}()

	// Send keep alive messages to both the client and the backend.
	conn.SetKeepAlive(true)
	conn.SetKeepAlivePeriod(time.Minute)
	upstream.SetKeepAlive(true)
	upstream.SetKeepAlivePeriod(time.Minute)

	conn.logf("Routing %s to %s", sni, route.Backend)
	<-done
}

// TLS alert message descriptions.
const (
       tlsAccessDenied     = 49
       tlsInternalError    = 80
       tlsUnrecognizedName = 112
)

// Sends an alert message with a fatal level to the remote.
func (conn *Conn) alert(desc byte) {
	// Craft an alert message (content type 21, TLS version 3.x, level: 2).
	message := bytes.NewBuffer([]byte{21, 3, 0, 0, 2, 2})

	// Set the alert description.
	message.WriteByte(desc)

	// Set a write timeout before sending the alert.
	if err := conn.SetWriteDeadline(time.Now().Add(3*time.Second)); err != nil {
		conn.logf("Could not set a write deadline for the alert message (%s)", err)
		return
	}

	if _, err := message.WriteTo(conn); err != nil {
		conn.logf("Failed to send an alert message (%s)", err)
	}
}

// Matches a connection to a backend.
func (conn *Conn) Match(sni string) (*config.Route, error) {
	// Loop over each route described in the configuration.
	for _, route := range conn.Config.Routes {
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
func clientAllowed(route *config.Route, ip net.IP) bool {
	// Check if filtering is enabled for the route.
	if len(route.Allow) == 0 && len(route.Deny) == 0 {
		return true
	}

	var cidr int = 0
	for _, subnet := range(route.Allow) {
		if subnet.Contains(ip) {
			sz, _ := subnet.Mask.Size()
			if sz > cidr {
				cidr = sz
			}
		}
	}
	for _, subnet := range(route.Deny) {
		if subnet.Contains(ip) {
			sz, _ := subnet.Mask.Size()
			if sz >= cidr {
				return false
			}
		}
	}
	return true
}
