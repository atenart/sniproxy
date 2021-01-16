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

package config

// Represents a block within a configuration file. A block contains directives
// and other nested blocks, and starts with a label. The top level configuration
// is itself a block (with no label).
type Block struct {
	label      string
	directives []*Directive
	blocks     []*Block
}
type Directive struct {
	directive string
	args      []string
}

// Converts a configuration block into a Block, which is used later for the
// actual parsing of directives.
func newBlock(l *Lexer) *Block {
	b := &Block{ label: l.Val() }

	for l.NextLine() {
		// Start of a new block.
		if l.NextVal() == "{" {
			b.blocks = append(b.blocks, newBlock(l))
			continue
		}

		// End of block, return to previous one.
		if l.Val() == "}" {
			break
		}

		// Not a block, it's a directive. parse the current line.
		b.directives = append(b.directives, newDirective(l))
	}

	return b
}

// Parse a directive and store it into a Directive.
func newDirective(l *Lexer) *Directive {
	d := &Directive{ directive: l.Val() }

	// Retrieve all the arguments on the current line.
	for l.Next() {
		d.args = append(d.args, l.Val())
	}

	return d
}
