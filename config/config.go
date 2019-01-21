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

package config

import (
	"os"
	"strings"
)

type Config struct {
}

// Reads a configuration file and tranforms it into a Config struct.
func (c *Config) ReadFile(file string) error {
	f, err := os.Open(file)
	if err != nil {
		return err
	}
	defer f.Close()

	l := newLexer(f)
	block := parse(&l, 0)

	dump(block)

	return nil
}

// Debug function to dump a block, its directives and its sub-blocks.
func dump(b *Block) {
	prefix := strings.Repeat("\t", int(b.nest))

	println(prefix + b.label)
	for _, d := range(b.directives) {
		print(prefix + "\t" + d.directive)
		for _, a := range(d.args) {
			print(" " + a)
		}
		println()
	}
	for _, sub := range(b.blocks) {
		dump(sub)
	}
}
