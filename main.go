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
	"flag"
	"log"
)

var (
	conf = flag.String("conf", "", "Configuration file.")
	bind = flag.String("bind", ":443", "Address and port to bind to.")
)

func main() {
	flag.Parse()
	if *conf == "" {
		log.Fatal("No config provided. Aborting.")
	}

	p := &Proxy{}
	if err := p.Config.ReadFile(*conf); err != nil {
		log.Fatalf("Could not read config %q (%s)", *conf, err)
	}

	if err := p.ListenAndServe(*bind); err != nil {
		log.Fatal(err)
	}
}
