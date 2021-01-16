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

import (
	"bufio"
	"io"
	"unicode"
)

// Lexer gets values, token by token, from an io.Reader.
type Lexer struct {
	reader *bufio.Reader
	tokens []*Token
	cursor int
	line   uint
}

// Token stores a value, and metadata associated to it.
type Token struct {
	Val  string
	Line uint
}

// Loads an io.Reader and wraps it into a bufio.Reader to prepare the Lexer for
// scanning tokens.
func newLexer(input io.Reader) Lexer {
	l := Lexer{
		reader: bufio.NewReader(input),
		cursor: -1,
		line: 1,
	}

	// Parse all tokens and store them in l.tokens.
	for l.parseNext() {
	}

	return l
}

// Loads for the next token in Lexer.Token. A token is delimited by whitespaces,
// unless it starts with a quote ("). The rest of a line is dropped if an hash
// (#) is read. Values separated by a comma (,) are considered being members of
// a list and will end up in the same uniq token; it's up to the upper layer to
// split them. Commas (,) can be followed by spaces or new lines.
func (l *Lexer) parseNext() bool {
	var comment, quote, list bool
	var val []rune

	token := &Token{}

	finalize := func() bool {
		token.Val = string(val)
		l.tokens = append(l.tokens, token)
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
			// Carriage return is discarded.
			if ch == '\r' {
				continue
			}
			if ch == '\n' {
				if quote {
					// Unexpected EOL. We should handle this
					// with a real error being reported.
					return false
				}
				l.line++
				comment = false
			}
			if !quote && !list && len(val) > 0 {
				list = false
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

		// Understand lists
		if ch == ',' {
			list = true
		} else {
			// Next rune isn't a space, reset the list state.
			list = false
		}

		if len(val) == 0 {
			token.Line = l.line
			if ch == '"' {
				quote = true
				continue
			}
		}

		val = append(val, ch)
	}
}

// Loads a token only if on the same line. Returns true if a token is found,
// false otherwise.
func (l *Lexer) Next() bool {
	// No more token available
	if l.cursor + 1 == len(l.tokens) {
		return false
	}

	// We are not currently on a line.
	if l.cursor == -1 {
		return false
	}

	// Next token is on a new line.
	if l.tokens[l.cursor].Line != l.tokens[l.cursor + 1].Line {
		return false
	}

	l.cursor++
	return true
}

// Loads the first token of the next line. Returns true if a token is found,
// false otherwise.
func (l *Lexer) NextLine() bool {
	// Loop through all remaining tokens on the current line.
	for l.Next() {
	}

	// No more token available
	if l.cursor + 1 == len(l.tokens) {
		return false
	}

	l.cursor++
	return true
}

// Returns the current token value.
func (l *Lexer) Val() string {
	if l.cursor == -1 || l.cursor + 1 == len(l.tokens) {
		return ""
	}

	return l.tokens[l.cursor].Val
}

// Returns the next token value.
func (l *Lexer) NextVal() string {
	if l.cursor + 2 >= len(l.tokens) {
		return ""
	}

	return l.tokens[l.cursor + 1].Val
}
