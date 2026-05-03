package parser

import (
	"errors"
	"strconv"
	"strings"
	"time"
)

// SyslogMessage holds the parsed fields of a syslog line. Fields that aren't
// present in the wire format (RFC3164 has no MsgID/StructuredData/etc.) are
// left empty.
type SyslogMessage struct {
	Format    string // "rfc3164" | "rfc5424"
	Priority  int    // raw PRI = facility*8 + severity
	Facility  int    // 0..23
	Severity  int    // 0..7  (0=emerg, 7=debug)
	Timestamp time.Time
	Hostname  string
	AppName   string // RFC5424 APP-NAME, RFC3164 TAG
	ProcID    string // RFC5424 PROCID, RFC3164 PID-from-tag
	MsgID     string // RFC5424 only
	Message   string // free-form body
}

// ParseSyslog detects format and dispatches. Returns an error if the line
// has no parseable PRI; the caller is expected to pass the original bytes
// downstream as a malformed-passthrough event in that case.
func ParseSyslog(line string) (*SyslogMessage, error) {
	pri, rest, err := parsePriority(line)
	if err != nil {
		return nil, err
	}

	msg := &SyslogMessage{
		Priority: pri,
		Facility: pri / 8,
		Severity: pri % 8,
	}

	// RFC5424 starts with "1 " right after the PRI. RFC3164 starts with a
	// timestamp like "Oct 11 22:14:15". Distinguish by the version byte.
	if len(rest) >= 2 && rest[0] == '1' && rest[1] == ' ' {
		msg.Format = "rfc5424"
		return parseRFC5424(msg, rest[2:])
	}
	msg.Format = "rfc3164"
	return parseRFC3164(msg, rest)
}

// parsePriority reads "<NN>" prefix. Returns priority and the remainder.
func parsePriority(line string) (int, string, error) {
	if len(line) < 3 || line[0] != '<' {
		return 0, "", errors.New("missing PRI")
	}
	end := strings.IndexByte(line, '>')
	if end < 2 || end > 4 {
		return 0, "", errors.New("malformed PRI")
	}
	pri, err := strconv.Atoi(line[1:end])
	if err != nil {
		return 0, "", errors.New("non-numeric PRI")
	}
	if pri < 0 || pri > 191 {
		return 0, "", errors.New("PRI out of range")
	}
	return pri, line[end+1:], nil
}

// parseRFC3164 parses BSD syslog: TIMESTAMP HOSTNAME TAG[PID]: MESSAGE
//
//	"Oct 11 22:14:15 myhost myapp[1234]: hello world"
//
// The timestamp has a fixed 15-byte width with leading-space single-digit
// days, which makes column-based parsing reliable.
func parseRFC3164(msg *SyslogMessage, s string) (*SyslogMessage, error) {
	if len(s) < 16 {
		// Not enough bytes for the timestamp - treat as just the message.
		msg.Message = s
		return msg, nil
	}

	// Timestamp: bytes 0..14, then a space at byte 15.
	tsStr := s[:15]
	if t, err := parseRFC3164Time(tsStr); err == nil {
		msg.Timestamp = t
		s = s[16:]
	}

	// HOSTNAME is the next token.
	if i := strings.IndexByte(s, ' '); i > 0 {
		msg.Hostname = s[:i]
		s = s[i+1:]
	}

	// TAG[PID]: MESSAGE  -- TAG ends at '[' or ':' or whitespace.
	tagEnd := -1
	for i := 0; i < len(s) && i < 32; i++ {
		c := s[i]
		if c == '[' || c == ':' || c == ' ' {
			tagEnd = i
			break
		}
	}
	if tagEnd > 0 {
		msg.AppName = s[:tagEnd]
		s = s[tagEnd:]
		if len(s) > 0 && s[0] == '[' {
			if end := strings.IndexByte(s, ']'); end > 1 {
				msg.ProcID = s[1:end]
				s = s[end+1:]
			}
		}
		// Skip ": " separator.
		s = strings.TrimPrefix(s, ":")
		s = strings.TrimLeft(s, " ")
	}

	msg.Message = s
	return msg, nil
}

// parseRFC3164Time accepts "Jan _2 15:04:05" (note the leading-space day).
// RFC3164 omits the year, so we use the current year - close enough for
// recent messages, and irrelevant for entity resolution which is the goal.
func parseRFC3164Time(s string) (time.Time, error) {
	t, err := time.Parse(time.Stamp, s)
	if err != nil {
		return time.Time{}, err
	}
	now := time.Now()
	return time.Date(now.Year(), t.Month(), t.Day(), t.Hour(), t.Minute(), t.Second(), 0, time.UTC), nil
}

// parseRFC5424 parses structured syslog:
//
//	VERSION " " TIMESTAMP " " HOSTNAME " " APP-NAME " " PROCID " " MSGID " " STRUCTURED-DATA " " MSG
//
// Each field is "-" if not present. STRUCTURED-DATA starts with '[' or is "-".
func parseRFC5424(msg *SyslogMessage, s string) (*SyslogMessage, error) {
	// Tokenize the first six fields by space (timestamp has no spaces).
	tokens := make([]string, 0, 6)
	for i := 0; i < 6; i++ {
		sp := strings.IndexByte(s, ' ')
		if sp < 0 {
			return msg, errors.New("rfc5424: short header")
		}
		tokens = append(tokens, s[:sp])
		s = s[sp+1:]
	}

	if tokens[0] != "-" {
		if t, err := time.Parse(time.RFC3339Nano, tokens[0]); err == nil {
			msg.Timestamp = t
		} else if t, err := time.Parse(time.RFC3339, tokens[0]); err == nil {
			msg.Timestamp = t
		}
	}
	msg.Hostname = unhyphen(tokens[1])
	msg.AppName = unhyphen(tokens[2])
	msg.ProcID = unhyphen(tokens[3])
	msg.MsgID = unhyphen(tokens[4])
	// tokens[5] is STRUCTURED-DATA; we skip it for now.

	msg.Message = s
	return msg, nil
}

// unhyphen treats a single "-" as empty - that's the RFC5424 nil sentinel.
func unhyphen(s string) string {
	if s == "-" {
		return ""
	}
	return s
}
