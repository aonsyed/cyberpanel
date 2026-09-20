//go:build linux

package database

import "io"

// Native dump arguments require --skip-extended-insert: each complete INSERT
// represents exactly one row. This counts statements, not line prefixes, so
// quoted data/identifiers and comments cannot manufacture extra rows. It is not
// an arbitrary uploaded-SQL row estimator, and buffers no row contents.
type transferDumpRows struct {
	destination                        io.Writer
	maximum, rows                      uint64
	quote, previous                    byte
	escaped, lineComment, blockComment bool
	token                              [6]byte
	tokenLength                        int
	firstDone, insert                  bool
}

func (counter *transferDumpRows) finishToken() {
	if counter.firstDone || counter.tokenLength == 0 {
		return
	}
	counter.insert = counter.tokenLength == 6 && string(counter.token[:]) == "INSERT"
	counter.firstDone = true
}

func (counter *transferDumpRows) Write(data []byte) (int, error) {
	for _, character := range data {
		if counter.lineComment {
			if character == '\n' {
				counter.lineComment = false
			}
			counter.previous = character
			continue
		}
		if counter.blockComment {
			if counter.previous == '*' && character == '/' {
				counter.blockComment = false
				counter.previous = 0
			} else {
				counter.previous = character
			}
			continue
		}
		if counter.quote != 0 {
			if counter.escaped {
				counter.escaped = false
			} else if character == '\\' {
				counter.escaped = true
			} else if character == counter.quote {
				counter.quote = 0
			}
			counter.previous = character
			continue
		}
		if counter.previous == '/' && character == '*' {
			counter.blockComment = true
			counter.previous = character
			continue
		}
		if counter.previous == '-' && character == '-' || character == '#' {
			counter.lineComment = true
			counter.previous = character
			continue
		}
		if character == '\'' || character == '"' || character == '`' {
			counter.finishToken()
			counter.quote = character
			counter.previous = character
			continue
		}
		if character == ';' {
			counter.finishToken()
			if counter.insert {
				if counter.rows == counter.maximum {
					return 0, ErrTransferLimit
				}
				counter.rows++
			}
			counter.tokenLength = 0
			counter.firstDone = false
			counter.insert = false
			counter.previous = 0
			continue
		}
		if !counter.firstDone {
			if character >= 'A' && character <= 'Z' || character >= 'a' && character <= 'z' {
				if counter.tokenLength < 6 {
					if character >= 'a' && character <= 'z' {
						character -= 32
					}
					counter.token[counter.tokenLength] = character
				}
				if counter.tokenLength < 7 {
					counter.tokenLength++
				}
			} else {
				counter.finishToken()
			}
		}
		counter.previous = character
	}
	return counter.destination.Write(data)
}

func (counter *transferDumpRows) finish() error {
	if counter.quote != 0 || counter.blockComment || counter.tokenLength != 0 || counter.firstDone {
		return ErrTransferInvalid
	}
	return nil
}
