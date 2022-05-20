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

package config

type Directive struct {
	Name       string
	Args       []string
	Directives []*Directive
}

func parseDirective(l *Lexer) *Directive {
	d := &Directive{ Name: l.Val() }

	// Quick hack, special case the first block.
	// Real default: false
	block := l.Val() == ""

	// Retrieve all the arguments on the current line.
	for l.Next() {
		// Start of a new block.
		if l.Val() == "{" {
			block = true
			break
		}

		// Directive's arguments.
		d.Args = append(d.Args, l.Val())
	}

	// Parse the directive's block.
	for block && l.NextLine() {
		// End of block, return to previous one.
		if l.Val() == "}" {
			break
		}

		// Parse new directives.
		d.Directives = append(d.Directives, parseDirective(l))
	}

	return d
}
