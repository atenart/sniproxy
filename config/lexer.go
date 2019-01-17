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
	"bufio"
	"io"
	"unicode"
)

// Lexer gets values, token by token, from an io.Reader.
type Lexer struct {
	reader *bufio.Reader
	token string
}

// Loads an io.Reader and wraps it into a bufio.Reader to prepare the Lexer for
// scanning tokens.
func (l *Lexer) Load(input io.Reader) {
	l.reader = bufio.NewReader(input)
}

// Loads for the next token in Lexer.token. A token is delimited by whitespaces,
// unless it starts with a quote ("). The rest of a line is dropped if an hash
// (#) is read.
func (l *Lexer) Next() bool {
	var comment, quote bool
	var val []rune

	finalize := func() bool {
		l.token = string(val)
		return true
	}

	for {
		ch, _, err := l.reader.ReadRune()

		// Handle EOF and unexpected errors. If a token was being made
		// return it.
		if err != nil {
			if len(val) > 0 {
				return finalize()
			}
			return false
		}

		// End of quoted values.
		if quote && ch == '"' {
			return finalize()
		}

		// Handle spaces.
		if unicode.IsSpace(ch) {
			if ch == '\n' {
				if quote {
					return false
				}
				comment = false
			}
			if !quote && len(val) > 0 {
				return finalize()
			}
			continue
		}

		// Detect the start of a comment.
		if ch == '#' {
			comment = true
		}

		// Discard commented runes.
		if comment {
			continue
		}

		// Take care of quoted values.
		if len(val) == 0 && ch == '"' {
			quote = true
			continue
		}

		val = append(val, ch)
	}
}
