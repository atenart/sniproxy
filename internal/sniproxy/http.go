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
	"bufio"
	"bytes"
	"fmt"
	"io"
	"net"
	"net/http"

	"github.com/atenart/sniproxy/internal/log"
)

// Handles HTTP requests by starting an HTTP server answering 308 redirects if
// the requested hostname is one we serve and if the redirection is allowed in
// the configuration for said hostname.
//
// Before calling this a check using Config.NeedHTTP() first can be made to
// ensure an HTTP server is needed, depending on the provided configuration.
func (p *Proxy)HandleRedirect(bind string) error {
	return http.ListenAndServe(bind, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		host := cleanHost(r.Host)
		redirHost, status, err := getRedirectHost(&p.Config, host, REDIRECT_FROM_HTTP)
		if err != nil {
			log.Printf(log.INFO, "%s (%s) - %s", r.RemoteAddr, host, err)
			http.Error(w, http.StatusText(status), status)
			return
		}

		url := fmt.Sprintf("https://%s%s", redirHost, r.RequestURI)
		http.Redirect(w, r, url, status)

		log.Printf(log.INFO, "%s (%s) - Redirecting request to HTTPS", r.RemoteAddr, host)
	}))
}

// Checks if the data in buf looks like an HTTP request. This does not guarantee
// the request is one, but should be enough to at least try handling it.
func isHTTP(buf *bytes.Buffer) bool {
	// The request is first parsed by parseRecord() which will try to read
	// a record header first. The record header is 5 bytes long.
	//
	// In case parseRecord() fails to read the record header, the buffer
	// won't contain the first 5 bytes. This is a request issue, we have no
	// reason to retry reading here.
	//
	// In all other cases at a minimum 5 bytes will be in the buffer, so
	// match on that. This is convenient as matching on more would require
	// some extra logic (method names do not all have the same length).
	// (We're only trying to loosely identify an HTTP request).
	if buf.Len() >= 5 {
		switch buf.String()[:5] {
		// From https://developer.mozilla.org/fr/docs/Web/HTTP/Methods
		case "GET /", "HEAD ", "POST ", "PUT /", "DELET", "CONNE", "OPTIO", "TRACE", "PATCH":
			return true
		}
	}
	return false
}

// Try redirecting what could be an HTTP request received on a TCP socket (in
// our case the TLS SNI server).
func redirectHTTP(conn *Conn, buf *bytes.Buffer) {
	req, err := http.ReadRequest(bufio.NewReader(io.MultiReader(buf, conn)))
	if err != nil {
		// Log as DEBUG, remember this is best effort and we're not sure
		// the request is genuine.
		conn.logf(log.DEBUG, "Could not parse the HTTP request: %s", err)
		return
	}

	host := cleanHost(req.Host)
	conn.sni = host
	redirHost, status, err := getRedirectHost(conn.Config, host, REDIRECT_FROM_TLS)
	if err != nil {
		conn.logf(log.INFO, "HTTP request on TLS port: %s", err)
	}

	hdr := make(http.Header)
	if status == http.StatusPermanentRedirect {
		hdr.Add("Location", fmt.Sprintf("https://%s%s", redirHost, req.RequestURI))
	}

	response := &http.Response{
		Proto: "HTTP/1.0",
		ProtoMajor: 1,
		ProtoMinor: 0,
		StatusCode: status,
		Status: http.StatusText(status),
		Header: hdr,
	}
	if err := response.Write(conn); err != nil {
		conn.logf(log.ERR, "Could not send the HTTP response: %s", err)
		return
	}

	if status == http.StatusPermanentRedirect {
		conn.logf(log.INFO, "Redirecting request to HTTPS")
	}
}

func getRedirectHost(c *Config, host string, redirectType uint32) (string, int, error) {
	route := c.MatchBackend(host)
	if route == nil {
		err := fmt.Errorf("No route to domain %s", host)
		return "", http.StatusForbidden, err
	} else if route.HTTPRedirect == REDIRECT_NONE || (route.HTTPRedirect & redirectType) == 0 {
		err := fmt.Errorf("Request to %s not being redirected", host)
		return "", http.StatusForbidden, err
	}

	if c.RedirectPort != 0 && c.RedirectPort != 443 {
		host = fmt.Sprintf("%s:%d", host, c.RedirectPort)
	}

	return host, http.StatusPermanentRedirect, nil
}

func cleanHost(from string) string {
	host, _, err := net.SplitHostPort(from)
	if err != nil {
		// No port in reqHost.
		host = from
	}

	return host
}
