package receivers

import (
	"bytes"
	"encoding/base64"
	"fmt"
	"io"
	"mime"
	"mime/multipart"
	"mime/quotedprintable"
	"net/mail"
	"regexp"
	"strings"
)

// parsedEmail is what the SMTP receiver hands to the pipeline. Every
// field is best-effort: we never fail the message just because parsing
// of one part went wrong. Empty values are normal for messages that
// don't have that part.
type parsedEmail struct {
	subject   string
	bodyText  string // first text/plain part found (or naive-stripped HTML if none)
	bodyHTML  string // first text/html part found (raw, not stripped)
	messageID string
}

// parseEmail walks an RFC 5322 message and pulls out the fields the
// generic profile cares about. v0.3.0 is intentionally simple - per-
// vendor parsers in v0.3.1 will do deeper extraction (named regex
// capture, structured field pulling, etc.).
//
// Always returns a parsedEmail (never nil); err is non-nil only if the
// message couldn't be header-parsed at all (in which case body extraction
// is skipped but the empty parsedEmail is still returned).
func parseEmail(raw []byte) (parsedEmail, error) {
	out := parsedEmail{}

	msg, err := mail.ReadMessage(bytes.NewReader(raw))
	if err != nil {
		return out, fmt.Errorf("header parse: %w", err)
	}

	// MIME-decoded headers ("=?utf-8?B?...?=" style). The mime.WordDecoder
	// handles RFC 2047 properly. Failures fall back to the raw header
	// value, which is better than dropping the field entirely.
	dec := &mime.WordDecoder{}
	out.subject = decodeHeader(dec, msg.Header.Get("Subject"))
	out.messageID = strings.TrimSpace(msg.Header.Get("Message-ID"))

	// Decide MIME structure from Content-Type. If single-part, the body
	// IS the content; if multipart, walk to find text/plain or text/html.
	ct := msg.Header.Get("Content-Type")
	mediaType, params, err := mime.ParseMediaType(ct)
	if err != nil {
		// Missing or malformed Content-Type. Treat the whole body as
		// text/plain - common for old simple notification systems.
		mediaType = "text/plain"
		params = nil
	}

	if strings.HasPrefix(mediaType, "multipart/") {
		extractMultipartParts(msg.Body, params["boundary"], &out)
	} else {
		// Single-part message. Decode by Content-Transfer-Encoding and
		// route to bodyText or bodyHTML based on Content-Type.
		decoded := decodeBody(msg.Body, msg.Header.Get("Content-Transfer-Encoding"))
		if strings.HasPrefix(mediaType, "text/html") {
			out.bodyHTML = decoded
		} else {
			out.bodyText = decoded
		}
	}

	// Fallback: if we got an HTML body but no plain-text body, do a
	// crude tag strip so the generic profile has something readable to
	// surface. v0.3.1 parsers will do better.
	if out.bodyText == "" && out.bodyHTML != "" {
		out.bodyText = naiveHTMLStrip(out.bodyHTML)
	}

	return out, nil
}

// extractMultipartParts recursively walks multipart bodies looking for
// the FIRST text/plain part (preferred) and FIRST text/html part. Other
// parts (attachments, inline images, etc.) are ignored.
//
// Recursion: multipart/alternative inside multipart/mixed is normal for
// emails with attachments; we descend into nested multiparts. Limit
// depth to avoid pathological inputs.
func extractMultipartParts(body io.Reader, boundary string, out *parsedEmail) {
	if boundary == "" {
		return
	}
	walkMultipart(body, boundary, out, 0)
}

const maxMultipartDepth = 5

func walkMultipart(body io.Reader, boundary string, out *parsedEmail, depth int) {
	if depth >= maxMultipartDepth {
		return
	}
	mr := multipart.NewReader(body, boundary)
	for {
		part, err := mr.NextPart()
		if err != nil {
			return // io.EOF or other - stop walking
		}

		ct := part.Header.Get("Content-Type")
		mediaType, params, _ := mime.ParseMediaType(ct)

		if strings.HasPrefix(mediaType, "multipart/") {
			// Nested multipart. Recurse.
			walkMultipart(part, params["boundary"], out, depth+1)
			_ = part.Close()
			continue
		}

		// Skip attachments (Content-Disposition: attachment) - we don't
		// process file attachments in v0.3.0.
		disp := part.Header.Get("Content-Disposition")
		if strings.HasPrefix(strings.ToLower(disp), "attachment") {
			_ = part.Close()
			continue
		}

		switch {
		case strings.HasPrefix(mediaType, "text/plain") && out.bodyText == "":
			out.bodyText = decodeBody(part, part.Header.Get("Content-Transfer-Encoding"))
		case strings.HasPrefix(mediaType, "text/html") && out.bodyHTML == "":
			out.bodyHTML = decodeBody(part, part.Header.Get("Content-Transfer-Encoding"))
		}
		_ = part.Close()

		if out.bodyText != "" && out.bodyHTML != "" {
			return // got both, no need to keep walking
		}
	}
}

// decodeBody applies Content-Transfer-Encoding decoding and returns
// the body as a string. Failures fall back to raw bytes - we'd rather
// surface garbled text than no text.
func decodeBody(r io.Reader, encoding string) string {
	encoding = strings.ToLower(strings.TrimSpace(encoding))
	switch encoding {
	case "quoted-printable":
		decoded, err := io.ReadAll(quotedprintable.NewReader(r))
		if err != nil {
			// Read whatever we got even on error.
			return string(decoded)
		}
		return string(decoded)
	case "base64":
		// Base64 decoder needs the full input first.
		raw, _ := io.ReadAll(r)
		// mime/quotedprintable handles Q-P; for base64 use encoding/base64.
		// Inlined to keep imports tight.
		return decodeBase64(string(raw))
	default:
		// "7bit", "8bit", "binary", or unspecified - read as-is.
		raw, _ := io.ReadAll(r)
		return string(raw)
	}
}

// decodeBase64 strips whitespace and decodes. base64 in MIME bodies
// has line breaks every 76 chars per RFC 2045.
func decodeBase64(s string) string {
	// Strip whitespace before decode.
	clean := strings.Map(func(r rune) rune {
		if r == '\r' || r == '\n' || r == ' ' || r == '\t' {
			return -1
		}
		return r
	}, s)
	dec, err := base64.StdEncoding.DecodeString(clean)
	if err != nil {
		return clean // fall back to raw text
	}
	return string(dec)
}

// =====================================================================
// Header decoding (RFC 2047 encoded-word handling)
// =====================================================================

func decodeHeader(dec *mime.WordDecoder, raw string) string {
	if raw == "" {
		return ""
	}
	decoded, err := dec.DecodeHeader(raw)
	if err != nil {
		return raw
	}
	return decoded
}

// =====================================================================
// HTML naive strip (fallback when no text/plain part exists)
// =====================================================================

var htmlTagRe = regexp.MustCompile(`<[^>]+>`)
var htmlBlockRe = regexp.MustCompile(`(?is)<(script|style)[^>]*>.*?</(script|style)>`)
var multiSpaceRe = regexp.MustCompile(`[ \t]+`)
var multiNewlineRe = regexp.MustCompile(`\n{3,}`)

// naiveHTMLStrip is the bare-minimum HTML-to-text fallback for v0.3.0.
// Removes script/style blocks first, then all tags, then collapses
// whitespace, then decodes the most common HTML entities. Good enough
// for the generic profile to surface a readable preview.
//
// Per-vendor parsers in v0.3.1 will do better with proper HTML parsing.
func naiveHTMLStrip(html string) string {
	// Strip script/style content (not just tags - the body is JS/CSS noise).
	out := htmlBlockRe.ReplaceAllString(html, "")
	// Strip remaining tags.
	out = htmlTagRe.ReplaceAllString(out, "")
	// Decode common entities. Not exhaustive - just the high-frequency ones.
	out = strings.ReplaceAll(out, "&amp;", "&")
	out = strings.ReplaceAll(out, "&lt;", "<")
	out = strings.ReplaceAll(out, "&gt;", ">")
	out = strings.ReplaceAll(out, "&quot;", `"`)
	out = strings.ReplaceAll(out, "&#39;", "'")
	out = strings.ReplaceAll(out, "&nbsp;", " ")
	// Collapse whitespace runs but preserve line structure.
	out = multiSpaceRe.ReplaceAllString(out, " ")
	out = multiNewlineRe.ReplaceAllString(out, "\n\n")
	return strings.TrimSpace(out)
}
