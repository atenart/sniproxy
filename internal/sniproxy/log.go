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
	"fmt"

	"github.com/atenart/sniproxy/internal/log"
)

func (conn *Conn) logf(level int, format string, v ...any) {
	log.Printf(level, "%s %s", conn.logPrefix(), fmt.Sprintf(format, v...))
}

func (conn *Conn) log(level int, v ...any) {
	log.Printf(level, "%s %s", conn.logPrefix(), fmt.Sprint(v...))
}

func (conn *Conn) logPrefix() string {
	var sni, backend string

	if conn.backend != "" {
		backend = fmt.Sprintf("<>%s", conn.backend)
	}
	if conn.sni != "" {
		sni = fmt.Sprintf(" (%s)", conn.sni)
	}

	return fmt.Sprintf("%s%s%s -", conn.RemoteAddr(), backend, sni)
}
