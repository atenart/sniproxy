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

package main

import (
	"flag"
	"fmt"

	"github.com/atenart/sniproxy/internal/log"
	"github.com/atenart/sniproxy/internal/sniproxy"
)

var (
	conf = flag.String("conf", "", "Configuration file.")
	bind = flag.String("bind", ":443", "Address and port to bind to.")
	http = flag.String("http-bind", ":80", "Address and port to bind to, listening for HTTP traffic to redirect to its HTTPS counterpart.")
	redirectPort = flag.Int("http-redirect-port", 443, "Public port of the HTTPS server to redirect the HTTP traffic to.")
	logLevel = flag.String("log-level", "info", "Log level (debug, info, warn, err)")
)

func main() {
	flag.Parse()
	if *conf == "" {
		log.Fatalf("No config provided. Aborting.")
	}

	if err := setLogLevel(); err != nil {
		log.Fatal(err)
	}

	p := &sniproxy.Proxy{}

	if err := p.Config.ReadFile(*conf); err != nil {
		log.Fatalf("Could not read config %q (%s)", *conf, err)
	}
	p.Config.RedirectPort = *redirectPort

	if p.Config.NeedHTTP() {
		go func() {
			if err := p.HandleRedirect(*http); err != nil {
				log.Fatal(err)
			}
		}()
	}

	if err := p.ListenAndServe(*bind); err != nil {
		log.Fatal(err)
	}
}

func setLogLevel() error {
	switch *logLevel {
	case "debug":
		log.LogLevel = log.DEBUG
	case "info":
		log.LogLevel = log.INFO
	case "warn":
		log.LogLevel = log.WARN
	case "error":
		log.LogLevel = log.ERR
	default:
		return fmt.Errorf("Invalid log level '%s'", *logLevel)
	}
	return nil
}
