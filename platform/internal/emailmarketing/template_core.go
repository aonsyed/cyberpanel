package emailmarketing

import (
	"fmt"
	"html"
	"net/mail"
	"net/url"
	"regexp"
	"sort"
	"strings"
	"time"
	"unicode/utf8"
)

const (
	maxTemplateBodyBytes = 1 << 20
	maxTemplateVariables = 64
)

var (
	templateTokenPattern = regexp.MustCompile(`\{\{([a-z][a-z0-9_]{0,63})\}\}`)
	htmlTagPattern       = regexp.MustCompile(`(?s)<[^>]*>`)
	anchorPattern        = regexp.MustCompile(`^<a href="([^"]{1,1000}[^"]{0,1000}[^"]{0,48})">$`)
	canonicalAnchorPattern = regexp.MustCompile(`^<a href="([^"]{1,1000}[^"]{0,1000}[^"]{0,48})" rel="noopener noreferrer">$`)
	variableNamePattern  = regexp.MustCompile(`^[a-z][a-z0-9_]{0,63}$`)
)

// SealTemplateVersion validates a closed, data-only template language and
// returns canonical sanitized content with its immutable digest.
func SealTemplateVersion(version MessageTemplateVersion) (MessageTemplateVersion, error) {
	if validateIdentifier(string(version.TenantID)) != nil || validateIdentifier(string(version.TemplateID)) != nil ||
		validateIdentifier(string(version.CreatedBy)) != nil || version.Version == 0 || version.CreatedAt.IsZero() ||
		validateHeaderValue(version.Subject, 998) != nil || validateMailbox(version.From) != nil ||
		(version.ReplyTo != "" && validateMailbox(version.ReplyTo) != nil) || len(version.TextBody) > maxTemplateBodyBytes ||
		len(version.HTMLBody) > maxTemplateBodyBytes || (version.TextBody == "" && version.HTMLBody == "") || !utf8.ValidString(version.TextBody) ||
		!utf8.ValidString(version.HTMLBody) {
		return MessageTemplateVersion{}, ErrInvalid
	}
	variables, err := normalizeTemplateVariables(version.Variables)
	if err != nil {
		return MessageTemplateVersion{}, err
	}
	version.Variables = variables
	if err = validateTemplateTokens(version.Subject, variables); err != nil {
		return MessageTemplateVersion{}, err
	}
	if strings.Contains(version.From, "{{") || strings.Contains(version.ReplyTo, "{{") {
		return MessageTemplateVersion{}, ErrInvalid
	}
	if err = validateTemplateTokens(version.TextBody, variables); err != nil {
		return MessageTemplateVersion{}, err
	}
	version.HTMLBody, err = sanitizeClosedHTML(version.HTMLBody)
	if err != nil || validateTemplateTokens(version.HTMLBody, variables) != nil {
		return MessageTemplateVersion{}, ErrInvalid
	}
	version.Digest = ""
	version.Digest = digestObject(version)
	return version, nil
}

func RenderTemplate(version MessageTemplateVersion, request TemplateRenderRequest, now time.Time) (TemplatePreview, error) {
	sealed, err := SealTemplateVersion(version)
	if err != nil || version.Digest == "" || sealed.Digest != version.Digest || request.TenantID != version.TenantID ||
		request.TemplateID != version.TemplateID || request.TemplateVersion != version.Version || request.RequestedBy == "" ||
		request.RequestedAt.IsZero() || strings.TrimSpace(request.Purpose) == "" || len(request.Purpose) > maxPurposeBytes {
		return TemplatePreview{}, ErrInvalid
	}
	if len(request.Variables) != len(version.Variables) {
		return TemplatePreview{}, ErrInvalid
	}
	allowed := make(map[string]struct{}, len(version.Variables))
	for _, name := range version.Variables {
		allowed[name] = struct{}{}
		if _, present := request.Variables[name]; !present {
			return TemplatePreview{}, ErrInvalid
		}
	}
	for name, value := range request.Variables {
		if _, present := allowed[name]; !present || len(value) > 64*1024 || !utf8.ValidString(value) || hasForbiddenControl(value) {
			return TemplatePreview{}, ErrInvalid
		}
	}
	subject := renderClosed(version.Subject, request.Variables, false)
	if validateHeaderValue(subject, 998) != nil {
		return TemplatePreview{}, ErrInvalid
	}
	preview := TemplatePreview{
		RequestDigest:  digestObject(request),
		Subject:        subject,
		From:           version.From,
		ReplyTo:        version.ReplyTo,
		TextBody:       renderClosed(version.TextBody, request.Variables, false),
		HTMLBody:       renderClosed(version.HTMLBody, request.Variables, true),
		TemplateDigest: version.Digest,
		RenderedAt:     now.UTC(),
	}
	return preview, nil
}

func validateHeaderValue(value string, maximum int) error {
	if value == "" || len(value) > maximum || !utf8.ValidString(value) || strings.ContainsAny(value, "\r\n") || hasForbiddenControl(value) {
		return ErrInvalid
	}
	return nil
}

func validateMailbox(value string) error {
	if validateHeaderValue(value, 320) != nil {
		return ErrInvalid
	}
	parsed, err := mail.ParseAddress(value)
	if err != nil || parsed.Address == "" {
		return ErrInvalid
	}
	identity, err := NormalizeAddress(parsed.Address)
	if err != nil {
		return ErrInvalid
	}
	reparsed, err := mail.ParseAddress(parsed.String())
	if err != nil || !strings.EqualFold(reparsed.Address, identity.Normalized) {
		return ErrInvalid
	}
	return nil
}

func mailboxDomain(value string) (string, error) {
	parsed, err := mail.ParseAddress(value)
	if err != nil {
		return "", ErrInvalid
	}
	identity, err := NormalizeAddress(parsed.Address)
	if err != nil {
		return "", ErrInvalid
	}
	return strings.SplitN(identity.Normalized, "@", 2)[1], nil
}

func normalizeTemplateVariables(input []string) ([]string, error) {
	if len(input) > maxTemplateVariables {
		return nil, ErrInvalid
	}
	seen := make(map[string]struct{}, len(input))
	result := make([]string, 0, len(input))
	for _, name := range input {
		if !variableNamePattern.MatchString(name) || secretLikeVariable(name) {
			return nil, ErrInvalid
		}
		if _, duplicate := seen[name]; duplicate {
			return nil, ErrInvalid
		}
		seen[name] = struct{}{}
		result = append(result, name)
	}
	sort.Strings(result)
	return result, nil
}

func secretLikeVariable(name string) bool {
	for _, fragment := range []string{"secret", "password", "passwd", "token", "credential", "private_key", "api_key", "environment", "env_"} {
		if strings.Contains(name, fragment) {
			return true
		}
	}
	return false
}

func validateTemplateTokens(value string, variables []string) error {
	allowed := make(map[string]struct{}, len(variables))
	for _, name := range variables {
		allowed[name] = struct{}{}
	}
	remainder := templateTokenPattern.ReplaceAllStringFunc(value, func(token string) string { return "" })
	if strings.Contains(remainder, "{{") || strings.Contains(remainder, "}}") || strings.Contains(remainder, "${") || strings.Contains(remainder, "<%") {
		return ErrInvalid
	}
	for _, match := range templateTokenPattern.FindAllStringSubmatch(value, -1) {
		if _, ok := allowed[match[1]]; !ok {
			return ErrInvalid
		}
	}
	return nil
}

func sanitizeClosedHTML(value string) (string, error) {
	if value == "" {
		return "", nil
	}
	if strings.ContainsRune(value, '\x00') || strings.Contains(value, "<!--") || strings.Contains(value, "<!") || strings.Contains(value, "<?") {
		return "", ErrInvalid
	}
	var result strings.Builder
	position := 0
	for _, location := range htmlTagPattern.FindAllStringIndex(value, -1) {
		text := value[position:location[0]]
		if strings.ContainsAny(text, "<>") {
			return "", ErrInvalid
		}
		result.WriteString(text)
		tag := value[location[0]:location[1]]
		lower := strings.ToLower(tag)
		switch lower {
		case "<p>", "</p>", "<br>", "<br/>", "<strong>", "</strong>", "<em>", "</em>", "<ul>", "</ul>", "<ol>", "</ol>", "<li>", "</li>", "</a>":
			result.WriteString(lower)
		default:
			match := anchorPattern.FindStringSubmatch(tag)
			if len(match) != 2 {
				match = canonicalAnchorPattern.FindStringSubmatch(tag)
			}
			if len(match) != 2 {
				return "", ErrInvalid
			}
			href := html.UnescapeString(match[1])
			parsed, err := url.Parse(href)
			if err != nil || (parsed.Scheme != "https" && parsed.Scheme != "mailto") || parsed.User != nil || strings.ContainsAny(href, "\r\n\t") {
				return "", ErrInvalid
			}
			result.WriteString(`<a href="` + html.EscapeString(href) + `" rel="noopener noreferrer">`)
		}
		position = location[1]
	}
	tail := value[position:]
	if strings.ContainsAny(tail, "<>") {
		return "", ErrInvalid
	}
	result.WriteString(tail)
	return result.String(), nil
}

func renderClosed(value string, variables map[string]string, escapeHTML bool) string {
	return templateTokenPattern.ReplaceAllStringFunc(value, func(token string) string {
		name := templateTokenPattern.FindStringSubmatch(token)[1]
		replacement := variables[name]
		if escapeHTML {
			return html.EscapeString(replacement)
		}
		return replacement
	})
}

func hasForbiddenControl(value string) bool {
	for _, r := range value {
		if r < 0x20 && r != '\t' {
			return true
		}
	}
	return false
}

func templateVersionKey(tenant TenantID, id TemplateID, version uint64) string {
	return fmt.Sprintf("%s:%s:%d", tenant, id, version)
}
