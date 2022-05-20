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

package log

import (
	"fmt"
)

// Log levels.
const (
	DEBUG = iota
	INFO
	WARN
	ERR
)

// Default log level.
var LogLevel = INFO

func Printf(level int, format string, v ...any) {
	if level >= LogLevel {
		fmt.Printf(format, v...)
		fmt.Println()
	}
}

func Print(level int, v ...any) {
	Printf(level, fmt.Sprint(v...))
}

func Fatalf(format string, v ...any) {
	Printf(ERR, format, v...)
}

func Fatal(v ...any) {
	Print(ERR, v...)
}
