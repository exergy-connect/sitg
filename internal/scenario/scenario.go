// Package scenario parses traffic scripts without executing shell commands.
package scenario

import (
	"bufio"
	"fmt"
	"io"
	"strings"
	"unicode"

	"github.com/jbemmel/sitg/internal/config"
)

type Step struct {
	Line   int
	Config *config.Config
}

// Parse validates every step before any traffic starts. Common CLI arguments
// precede each line, so explicit step flags override the common defaults.
func Parse(r io.Reader, common []string) ([]Step, error) {
	scanner := bufio.NewScanner(r)
	scanner.Buffer(make([]byte, 4096), 1024*1024)
	var steps []Step
	line := 0
	for scanner.Scan() {
		line++
		args, err := split(scanner.Text())
		if err != nil {
			return nil, fmt.Errorf("line %d: %w", line, err)
		}
		if len(args) == 0 {
			continue
		}
		if args[0] == "sitg" {
			args = args[1:]
		}
		if len(args) == 0 {
			return nil, fmt.Errorf("line %d: missing CLI parameters", line)
		}
		cfg, err := config.Parse(append(append([]string{}, common...), args...))
		if err != nil {
			return nil, fmt.Errorf("line %d: %w", line, err)
		}
		cfg.ApplyPatternDefaults()
		steps = append(steps, Step{Line: line, Config: cfg})
	}
	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("line %d: %w", line+1, err)
	}
	if len(steps) == 0 {
		return nil, fmt.Errorf("scenario contains no steps")
	}
	return steps, nil
}

// split supports quotes, escapes, and shell-style comments at word boundaries.
// Variable expansion, substitution, and shell execution are deliberately absent.
func split(line string) ([]string, error) {
	var args []string
	var word strings.Builder
	var quote rune
	escaped, started := false, false
	flush := func() {
		if started {
			args = append(args, word.String())
			word.Reset()
			started = false
		}
	}
	for _, c := range line {
		if escaped {
			word.WriteRune(c)
			started = true
			escaped = false
			continue
		}
		if c == '\\' && quote != '\'' {
			escaped = true
			started = true
			continue
		}
		if quote != 0 {
			if c == quote {
				quote = 0
			} else {
				word.WriteRune(c)
			}
			continue
		}
		if c == '#' && !started {
			break
		}
		if c == '\'' || c == '"' {
			quote = c
			started = true
			continue
		}
		if unicode.IsSpace(c) {
			flush()
			continue
		}
		word.WriteRune(c)
		started = true
	}
	if escaped {
		return nil, fmt.Errorf("trailing escape")
	}
	if quote != 0 {
		return nil, fmt.Errorf("unterminated quote")
	}
	flush()
	return args, nil
}
