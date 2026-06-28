// Package openmalleable implements the server-side subset of the
// OpenMalleableC2 profile format.
package openmalleable

import (
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"net/http"
	"net/url"
	"regexp"
	"strconv"
	"strings"
)

type TransformType string

const (
	TransformBase64    TransformType = "base64"
	TransformBase64URL TransformType = "base64url"
	TransformNetBIOS   TransformType = "netbios"
	TransformNetBIOSU  TransformType = "netbiosu"
	TransformMask      TransformType = "mask"
	TransformPrepend   TransformType = "prepend"
	TransformAppend    TransformType = "append"
)

type TerminationType string

const (
	TerminationHeader    TerminationType = "header"
	TerminationParameter TerminationType = "parameter"
	TerminationPrint     TerminationType = "print"
	TerminationURIAppend TerminationType = "uri-append"
)

type Transform struct {
	Type     TransformType
	Argument string
}

type Termination struct {
	Type   TerminationType
	Target string
}

type TransformChain struct {
	Transforms  []Transform
	Termination Termination
}

type Header struct {
	Key   string
	Value string
}

type Parameter struct {
	Key   string
	Value string
}

type HttpConfig struct {
	Headers    map[string]string
	HeaderList []Header

	Parameters    map[string]string
	ParameterList []Parameter

	Metadata *TransformChain
	ID       *TransformChain
	Output   *TransformChain
}

type HttpTransaction struct {
	Variant string
	Method  string
	URIs    []string
	Client  HttpConfig
	Server  HttpConfig
}

type HttpRequest struct {
	Method  string
	URI     string
	Path    string
	Query   map[string]string
	Headers map[string]string
	Body    []byte
}

type HttpResponse struct {
	StatusCode int
	Headers    map[string]string
	HeaderList []Header
	Body       []byte
}

type ProfileMismatchError struct {
	Reason  string
	Details string
}

func (e *ProfileMismatchError) Error() string {
	return fmt.Sprintf("%s: %s", e.Reason, e.Details)
}

type MalleableProfile struct {
	ProfileName          string
	UserAgent            string
	HeadersRemove        []string
	HTTPGetTransactions  map[string]*HttpTransaction
	HTTPPostTransactions map[string]*HttpTransaction
}

func NewMalleableProfile(profileContent string) *MalleableProfile {
	profile := &MalleableProfile{
		HTTPGetTransactions:  map[string]*HttpTransaction{},
		HTTPPostTransactions: map[string]*HttpTransaction{},
	}
	profile.parse(profileContent)
	return profile
}

func (p *MalleableProfile) parse(content string) {
	content = stripComments(content)

	if match := regexp.MustCompile(`set\s+sample_name\s+"((?:[^"\\]|\\.)*)"`).FindStringSubmatch(content); match != nil {
		p.ProfileName = decodeString(match[1])
	}
	if match := regexp.MustCompile(`set\s+useragent\s+"((?:[^"\\]|\\.)*)"`).FindStringSubmatch(content); match != nil {
		p.UserAgent = decodeString(match[1])
	}
	if match := regexp.MustCompile(`set\s+headers_remove\s+"((?:[^"\\]|\\.)*)"`).FindStringSubmatch(content); match != nil {
		rawHeaders := decodeString(match[1])
		for _, header := range strings.Split(rawHeaders, ",") {
			if trimmed := strings.TrimSpace(header); trimmed != "" {
				p.HeadersRemove = append(p.HeadersRemove, trimmed)
			}
		}
	}

	for _, block := range findNamedBlocks(content, "http-get") {
		transaction := p.parseHTTPTransaction("GET", block.variant, block.content)
		p.HTTPGetTransactions[block.variant] = transaction
	}
	for _, block := range findNamedBlocks(content, "http-post") {
		transaction := p.parseHTTPTransaction("POST", block.variant, block.content)
		p.HTTPPostTransactions[block.variant] = transaction
	}
}

func (p *MalleableProfile) parseHTTPTransaction(method, variant, content string) *HttpTransaction {
	uris := []string{}
	verb := method
	clientConfig := newHTTPConfig()
	serverConfig := newHTTPConfig()

	if match := regexp.MustCompile(`set\s+uri\s+"((?:[^"\\]|\\.)*)"`).FindStringSubmatch(content); match != nil {
		uris = strings.Fields(decodeString(match[1]))
	}
	if match := regexp.MustCompile(`set\s+verb\s+"((?:[^"\\]|\\.)*)"`).FindStringSubmatch(content); match != nil {
		verb = strings.ToUpper(decodeString(match[1]))
	}
	if clientContent, ok := extractBlockContent(content, "client"); ok {
		parseConfigBlock(clientContent, &clientConfig)
	}
	if serverContent, ok := extractBlockContent(content, "server"); ok {
		parseConfigBlock(serverContent, &serverConfig)
	}

	return &HttpTransaction{
		Variant: variant,
		Method:  verb,
		URIs:    uris,
		Client:  clientConfig,
		Server:  serverConfig,
	}
}

func newHTTPConfig() HttpConfig {
	return HttpConfig{
		Headers:    map[string]string{},
		Parameters: map[string]string{},
	}
}

func parseConfigBlock(content string, config *HttpConfig) {
	headerRe := regexp.MustCompile(`header\s+"((?:[^"\\]|\\.)*)"\s+"((?:[^"\\]|\\.)*)"`)
	for _, match := range headerRe.FindAllStringSubmatch(content, -1) {
		name := decodeString(match[1])
		value := decodeString(match[2])
		setConfigHeader(config, name, value)
	}

	paramRe := regexp.MustCompile(`parameter\s+"((?:[^"\\]|\\.)*)"\s+"((?:[^"\\]|\\.)*)"`)
	for _, match := range paramRe.FindAllStringSubmatch(content, -1) {
		key := decodeString(match[1])
		value := decodeString(match[2])
		setConfigParameter(config, key, value)
	}

	if metadataContent, ok := extractBlockContent(content, "metadata"); ok {
		chain := parseTransformChain(metadataContent)
		config.Metadata = &chain
	}
	if idContent, ok := extractBlockContent(content, "id"); ok {
		chain := parseTransformChain(idContent)
		config.ID = &chain
	}
	if outputContent, ok := extractBlockContent(content, "output"); ok {
		chain := parseTransformChain(outputContent)
		config.Output = &chain
	}
}

func setConfigHeader(config *HttpConfig, key, value string) {
	config.Headers[key] = value
	for i := range config.HeaderList {
		if config.HeaderList[i].Key == key {
			config.HeaderList[i].Value = value
			return
		}
	}
	config.HeaderList = append(config.HeaderList, Header{Key: key, Value: value})
}

func setConfigParameter(config *HttpConfig, key, value string) {
	config.Parameters[key] = value
	for i := range config.ParameterList {
		if config.ParameterList[i].Key == key {
			config.ParameterList[i].Value = value
			return
		}
	}
	config.ParameterList = append(config.ParameterList, Parameter{Key: key, Value: value})
}

func parseTransformChain(content string) TransformChain {
	transforms := []Transform{}
	termination := Termination{Type: TerminationPrint}

	for _, stmt := range splitStatements(content) {
		stmt = strings.TrimSpace(stmt)
		if stmt == "" {
			continue
		}

		switch {
		case strings.HasPrefix(stmt, "header"):
			if match := regexp.MustCompile(`header\s+"((?:[^"\\]|\\.)*)"`).FindStringSubmatch(stmt); match != nil {
				termination = Termination{Type: TerminationHeader, Target: decodeString(match[1])}
				return TransformChain{Transforms: transforms, Termination: termination}
			}
		case strings.HasPrefix(stmt, "parameter"):
			if match := regexp.MustCompile(`parameter\s+"((?:[^"\\]|\\.)*)"`).FindStringSubmatch(stmt); match != nil {
				termination = Termination{Type: TerminationParameter, Target: decodeString(match[1])}
				return TransformChain{Transforms: transforms, Termination: termination}
			}
		case stmt == "print":
			termination = Termination{Type: TerminationPrint}
			return TransformChain{Transforms: transforms, Termination: termination}
		case stmt == "uri-append":
			termination = Termination{Type: TerminationURIAppend}
			return TransformChain{Transforms: transforms, Termination: termination}
		case strings.HasPrefix(stmt, "prepend"):
			if match := regexp.MustCompile(`prepend\s+"((?:[^"\\]|\\.)*)"`).FindStringSubmatch(stmt); match != nil {
				transforms = append(transforms, Transform{Type: TransformPrepend, Argument: match[1]})
			}
		case strings.HasPrefix(stmt, "append"):
			if match := regexp.MustCompile(`append\s+"((?:[^"\\]|\\.)*)"`).FindStringSubmatch(stmt); match != nil {
				transforms = append(transforms, Transform{Type: TransformAppend, Argument: match[1]})
			}
		case stmt == "base64":
			transforms = append(transforms, Transform{Type: TransformBase64})
		case stmt == "base64url":
			transforms = append(transforms, Transform{Type: TransformBase64URL})
		case stmt == "netbios":
			transforms = append(transforms, Transform{Type: TransformNetBIOS})
		case stmt == "netbiosu":
			transforms = append(transforms, Transform{Type: TransformNetBIOSU})
		case stmt == "mask":
			transforms = append(transforms, Transform{Type: TransformMask})
		}
	}

	return TransformChain{Transforms: transforms, Termination: termination}
}

type namedBlock struct {
	variant string
	content string
}

func findNamedBlocks(content, keyword string) []namedBlock {
	results := []namedBlock{}
	idx := 0
	for {
		pos := strings.Index(content[idx:], keyword)
		if pos == -1 {
			break
		}
		pos += idx
		if pos > 0 {
			prev := rune(content[pos-1])
			if (prev >= 'a' && prev <= 'z') || (prev >= 'A' && prev <= 'Z') || (prev >= '0' && prev <= '9') {
				idx = pos + len(keyword)
				continue
			}
		}

		i := pos + len(keyword)
		for i < len(content) && isSpace(content[i]) {
			i++
		}

		variant := "default"
		if i < len(content) && content[i] == '"' {
			i++
			start := i
			for i < len(content) && content[i] != '"' {
				if content[i] == '\\' && i+1 < len(content) {
					i += 2
					continue
				}
				i++
			}
			variant = content[start:i]
			i++
		}

		for i < len(content) && isSpace(content[i]) {
			i++
		}
		if i >= len(content) || content[i] != '{' {
			idx = pos + len(keyword)
			continue
		}
		blockContent, endPos, ok := extractBracedContent(content, i)
		if ok {
			results = append(results, namedBlock{variant: variant, content: blockContent})
			idx = endPos
		} else {
			idx = pos + len(keyword)
		}
	}
	return results
}

func extractBlockContent(content, keyword string) (string, bool) {
	pos := strings.Index(content, keyword)
	if pos == -1 {
		return "", false
	}
	i := pos + len(keyword)
	for i < len(content) && isSpace(content[i]) {
		i++
	}
	if i >= len(content) || content[i] != '{' {
		return "", false
	}
	block, _, ok := extractBracedContent(content, i)
	return block, ok
}

func extractBracedContent(content string, bracePos int) (string, int, bool) {
	depth := 0
	start := bracePos + 1
	inString := false
	for i := bracePos; i < len(content); i++ {
		ch := content[i]
		if inString {
			if ch == '\\' && i+1 < len(content) {
				i++
				continue
			}
			if ch == '"' {
				inString = false
			}
			continue
		}
		switch ch {
		case '"':
			inString = true
		case '{':
			depth++
		case '}':
			depth--
			if depth == 0 {
				return content[start:i], i + 1, true
			}
		}
	}
	return "", len(content), false
}

func splitStatements(content string) []string {
	statements := []string{}
	var b strings.Builder
	inString := false
	for i := 0; i < len(content); i++ {
		ch := content[i]
		if inString {
			if ch == '\\' && i+1 < len(content) {
				b.WriteByte(ch)
				b.WriteByte(content[i+1])
				i++
				continue
			}
			if ch == '"' {
				inString = false
			}
			b.WriteByte(ch)
			continue
		}
		switch ch {
		case '"':
			inString = true
			b.WriteByte(ch)
		case ';':
			stmt := strings.TrimSpace(b.String())
			if stmt != "" {
				statements = append(statements, stmt)
			}
			b.Reset()
		default:
			b.WriteByte(ch)
		}
	}
	if tail := strings.TrimSpace(b.String()); tail != "" {
		statements = append(statements, tail)
	}
	return statements
}

func stripComments(content string) string {
	var result strings.Builder
	inString := false
	for i := 0; i < len(content); i++ {
		ch := content[i]
		if inString {
			if ch == '\\' && i+1 < len(content) {
				result.WriteByte(ch)
				result.WriteByte(content[i+1])
				i++
				continue
			}
			if ch == '"' {
				inString = false
			}
			result.WriteByte(ch)
			continue
		}
		switch ch {
		case '"':
			inString = true
			result.WriteByte(ch)
		case '#':
			for i < len(content) && content[i] != '\n' {
				i++
			}
			if i < len(content) && content[i] == '\n' {
				result.WriteByte('\n')
			}
		default:
			result.WriteByte(ch)
		}
	}
	return result.String()
}

func ApplyTransform(data []byte, transform Transform) ([]byte, error) {
	switch transform.Type {
	case TransformBase64:
		out := make([]byte, base64.StdEncoding.EncodedLen(len(data)))
		base64.StdEncoding.Encode(out, data)
		return out, nil
	case TransformBase64URL:
		return []byte(base64.RawURLEncoding.EncodeToString(data)), nil
	case TransformNetBIOS:
		return netbiosEncode(data, 'a'), nil
	case TransformNetBIOSU:
		return netbiosEncode(data, 'A'), nil
	case TransformMask:
		return maskEncode(data)
	case TransformPrepend:
		if transform.Argument != "" {
			return append([]byte(decodeString(transform.Argument)), data...), nil
		}
	case TransformAppend:
		if transform.Argument != "" {
			result := append([]byte{}, data...)
			result = append(result, []byte(decodeString(transform.Argument))...)
			return result, nil
		}
	}
	return data, nil
}

func ReverseTransform(data []byte, transform Transform) ([]byte, error) {
	switch transform.Type {
	case TransformBase64:
		out, err := base64.StdEncoding.DecodeString(string(data))
		if err != nil {
			return nil, &ProfileMismatchError{Reason: "transform", Details: "base64 decode failed: " + err.Error()}
		}
		return out, nil
	case TransformBase64URL:
		out, err := base64.RawURLEncoding.DecodeString(string(data))
		if err != nil {
			out, err = base64.URLEncoding.DecodeString(string(data))
		}
		if err != nil {
			return nil, &ProfileMismatchError{Reason: "transform", Details: "base64url decode failed: " + err.Error()}
		}
		return out, nil
	case TransformNetBIOS:
		return netbiosDecode(data, 'a'), nil
	case TransformNetBIOSU:
		return netbiosDecode(data, 'A'), nil
	case TransformMask:
		return maskDecode(data)
	case TransformPrepend:
		if transform.Argument != "" {
			arg := []byte(decodeString(transform.Argument))
			if strings.HasPrefix(string(data), string(arg)) {
				return data[len(arg):], nil
			}
			return nil, &ProfileMismatchError{Reason: "transform", Details: "prepend mismatch"}
		}
	case TransformAppend:
		if transform.Argument != "" {
			arg := []byte(decodeString(transform.Argument))
			if strings.HasSuffix(string(data), string(arg)) {
				return data[:len(data)-len(arg)], nil
			}
			return nil, &ProfileMismatchError{Reason: "transform", Details: "append mismatch"}
		}
	}
	return data, nil
}

func ApplyChain(data []byte, chain TransformChain) ([]byte, error) {
	result := append([]byte{}, data...)
	var err error
	for _, transform := range chain.Transforms {
		result, err = ApplyTransform(result, transform)
		if err != nil {
			return nil, err
		}
	}
	return result, nil
}

func ReverseChain(data []byte, chain TransformChain) ([]byte, error) {
	result := append([]byte{}, data...)
	var err error
	for i := len(chain.Transforms) - 1; i >= 0; i-- {
		result, err = ReverseTransform(result, chain.Transforms[i])
		if err != nil {
			return nil, err
		}
	}
	return result, nil
}

func netbiosEncode(data []byte, base byte) []byte {
	result := make([]byte, 0, len(data)*2)
	for _, b := range data {
		result = append(result, base+(b>>4), base+(b&0x0f))
	}
	return result
}

func netbiosDecode(data []byte, base byte) []byte {
	result := make([]byte, 0, len(data)/2)
	for i := 0; i < len(data); i += 2 {
		if i+1 < len(data) {
			high := data[i] - base
			low := data[i+1] - base
			result = append(result, (high<<4)|low)
		}
	}
	return result
}

func maskEncode(data []byte) ([]byte, error) {
	key := make([]byte, 4)
	if _, err := rand.Read(key); err != nil {
		return nil, err
	}
	result := append([]byte{}, key...)
	for i, b := range data {
		result = append(result, b^key[i%4])
	}
	return result, nil
}

func maskDecode(data []byte) ([]byte, error) {
	if len(data) < 4 {
		return nil, &ProfileMismatchError{Reason: "transform", Details: "mask decode expects 4-byte key"}
	}
	key := data[:4]
	masked := data[4:]
	result := make([]byte, 0, len(masked))
	for i, b := range masked {
		result = append(result, b^key[i%4])
	}
	return result, nil
}

func decodeString(s string) string {
	var result strings.Builder
	for i := 0; i < len(s); {
		if s[i] == '\\' && i+1 < len(s) {
			next := s[i+1]
			switch next {
			case 'n':
				result.WriteByte('\n')
				i += 2
			case 'r':
				result.WriteByte('\r')
				i += 2
			case 't':
				result.WriteByte('\t')
				i += 2
			case '\\':
				result.WriteByte('\\')
				i += 2
			case 'x':
				if i+3 < len(s) {
					if value, err := strconv.ParseUint(s[i+2:i+4], 16, 8); err == nil {
						result.WriteByte(byte(value))
						i += 4
					} else {
						result.WriteByte(next)
						i += 2
					}
				} else {
					result.WriteByte(next)
					i += 2
				}
			case 'u':
				if i+5 < len(s) {
					if value, err := strconv.ParseInt(s[i+2:i+6], 16, 32); err == nil {
						result.WriteRune(rune(value))
						i += 6
					} else {
						result.WriteByte(next)
						i += 2
					}
				} else {
					result.WriteByte(next)
					i += 2
				}
			default:
				result.WriteByte(next)
				i += 2
			}
			continue
		}
		result.WriteByte(s[i])
		i++
	}
	return result.String()
}

type MalleableServer struct {
	Profile *MalleableProfile
}

func NewMalleableServer(profile *MalleableProfile) *MalleableServer {
	return &MalleableServer{Profile: profile}
}

func (s *MalleableServer) FindGetVariant(method, path string) string {
	if !strings.EqualFold(method, http.MethodGet) {
		return ""
	}
	return s.findVariant(path, s.Profile.HTTPGetTransactions)
}

func (s *MalleableServer) FindPostVariant(method, path string) string {
	if !strings.EqualFold(method, http.MethodPost) {
		return ""
	}
	return s.findVariant(path, s.Profile.HTTPPostTransactions)
}

func (s *MalleableServer) findVariant(path string, transactions map[string]*HttpTransaction) string {
	bestVariant := ""
	bestLen := -1
	for name, tx := range transactions {
		if tx == nil {
			continue
		}
		for _, uri := range tx.URIs {
			if strings.HasPrefix(path, uri) && len(uri) > bestLen {
				bestVariant = name
				bestLen = len(uri)
			}
		}
	}
	return bestVariant
}

func (s *MalleableServer) ExtractMetadata(request HttpRequest, variant string) ([]byte, error) {
	if variant == "" {
		variant = "default"
	}
	transaction := s.Profile.HTTPGetTransactions[variant]
	if transaction == nil || transaction.Client.Metadata == nil {
		return nil, fmt.Errorf("no metadata chain for variant %s", variant)
	}
	if !pathMatches(request.Path, transaction.URIs) {
		return nil, &ProfileMismatchError{Reason: "uri", Details: fmt.Sprintf("request path '%s' does not match any http-get uri", request.Path)}
	}
	data, err := s.extractFromRequest(request, transaction.Client.Metadata.Termination, transaction.URIs)
	if err != nil {
		return nil, err
	}
	return ReverseChain(data, *transaction.Client.Metadata)
}

func (s *MalleableServer) ExtractSessionID(request HttpRequest, variant string) ([]byte, error) {
	if variant == "" {
		variant = "default"
	}
	transaction := s.Profile.HTTPPostTransactions[variant]
	if transaction == nil || transaction.Client.ID == nil {
		return nil, fmt.Errorf("no id chain for variant %s", variant)
	}
	if !pathMatches(request.Path, transaction.URIs) {
		return nil, &ProfileMismatchError{Reason: "uri", Details: fmt.Sprintf("request path '%s' does not match any http-post uri", request.Path)}
	}
	data, err := s.extractFromRequest(request, transaction.Client.ID.Termination, transaction.URIs)
	if err != nil {
		return nil, err
	}
	return ReverseChain(data, *transaction.Client.ID)
}

func (s *MalleableServer) ExtractOutput(request HttpRequest, variant string) ([]byte, error) {
	if variant == "" {
		variant = "default"
	}
	transaction := s.Profile.HTTPPostTransactions[variant]
	if transaction == nil || transaction.Client.Output == nil {
		return nil, fmt.Errorf("no output chain for variant %s", variant)
	}
	if !pathMatches(request.Path, transaction.URIs) {
		return nil, &ProfileMismatchError{Reason: "uri", Details: fmt.Sprintf("request path '%s' does not match any http-post uri", request.Path)}
	}
	data, err := s.extractFromRequest(request, transaction.Client.Output.Termination, transaction.URIs)
	if err != nil {
		return nil, err
	}
	return ReverseChain(data, *transaction.Client.Output)
}

func (s *MalleableServer) BuildGetResponse(data []byte, variant string) (HttpResponse, error) {
	if variant == "" {
		variant = "default"
	}
	transaction := s.Profile.HTTPGetTransactions[variant]
	if transaction == nil {
		return HttpResponse{}, fmt.Errorf("no transaction for variant %s", variant)
	}

	response := newHTTPResponse(200, transaction.Server.HeaderList)
	if transaction.Server.Output != nil {
		transformed, err := ApplyChain(data, *transaction.Server.Output)
		if err != nil {
			return HttpResponse{}, err
		}
		switch transaction.Server.Output.Termination.Type {
		case TerminationPrint:
			response.Body = transformed
		case TerminationHeader:
			addResponseHeader(&response, transaction.Server.Output.Termination.Target, string(transformed))
		}
	}
	return response, nil
}

func (s *MalleableServer) BuildPostResponse(data []byte, variant string) (HttpResponse, error) {
	if variant == "" {
		variant = "default"
	}
	transaction := s.Profile.HTTPPostTransactions[variant]
	if transaction == nil {
		return HttpResponse{}, fmt.Errorf("no transaction for variant %s", variant)
	}

	response := newHTTPResponse(200, transaction.Server.HeaderList)
	if transaction.Server.Output != nil && len(data) > 0 {
		transformed, err := ApplyChain(data, *transaction.Server.Output)
		if err != nil {
			return HttpResponse{}, err
		}
		if transaction.Server.Output.Termination.Type == TerminationPrint {
			response.Body = transformed
		}
	}
	return response, nil
}

func (s *MalleableServer) extractFromRequest(request HttpRequest, termination Termination, uris []string) ([]byte, error) {
	switch termination.Type {
	case TerminationHeader:
		return []byte(request.Headers[termination.Target]), nil
	case TerminationParameter:
		return []byte(request.Query[termination.Target]), nil
	case TerminationPrint:
		return request.Body, nil
	case TerminationURIAppend:
		if len(uris) == 0 {
			return nil, &ProfileMismatchError{Reason: "uri", Details: "uri-append used but no uris configured"}
		}
		for _, base := range uris {
			if strings.HasPrefix(request.Path, base) {
				return []byte(request.Path[len(base):]), nil
			}
		}
		return nil, &ProfileMismatchError{Reason: "uri", Details: fmt.Sprintf("request path '%s' does not match any uri-append base", request.Path)}
	}
	return []byte{}, nil
}

func newHTTPResponse(status int, headers []Header) HttpResponse {
	response := HttpResponse{
		StatusCode: status,
		Headers:    map[string]string{},
	}
	for _, header := range headers {
		addResponseHeader(&response, header.Key, header.Value)
	}
	return response
}

func addResponseHeader(response *HttpResponse, key, value string) {
	response.Headers[key] = value
	response.HeaderList = append(response.HeaderList, Header{Key: key, Value: value})
}

func pathMatches(path string, uris []string) bool {
	for _, uri := range uris {
		if strings.HasPrefix(path, uri) {
			return true
		}
	}
	return false
}

func ParseHTTPRequest(rawRequest string) (HttpRequest, error) {
	lines := strings.Split(rawRequest, "\r\n")
	if len(lines) == 0 {
		return HttpRequest{}, fmt.Errorf("empty request")
	}

	requestLine := strings.Split(lines[0], " ")
	if len(requestLine) < 3 {
		return HttpRequest{}, fmt.Errorf("invalid request line")
	}
	method := requestLine[0]
	fullURI := requestLine[1]

	path := fullURI
	query := map[string]string{}
	if strings.Contains(fullURI, "?") {
		parts := strings.SplitN(fullURI, "?", 2)
		path = parts[0]
		query = parseRawQuery(parts[1])
	}

	headers := map[string]string{}
	i := 1
	for i < len(lines) && lines[i] != "" {
		if strings.Contains(lines[i], ":") {
			kv := strings.SplitN(lines[i], ":", 2)
			headers[strings.TrimSpace(kv[0])] = strings.TrimSpace(kv[1])
		}
		i++
	}

	body := []byte{}
	if i < len(lines) {
		body = []byte(strings.Join(lines[i+1:], "\r\n"))
	}

	return HttpRequest{
		Method:  method,
		URI:     fullURI,
		Path:    path,
		Query:   query,
		Headers: headers,
		Body:    body,
	}, nil
}

func NewHTTPRequestFromHTTP(r *http.Request, body []byte) HttpRequest {
	query := parseRawQuery(r.URL.RawQuery)

	headers := map[string]string{}
	for key, values := range r.Header {
		if len(values) > 0 {
			headers[key] = values[0]
		}
	}
	if r.Host != "" {
		headers["Host"] = r.Host
	}

	host := headers["Host"]
	if host == "" {
		host = "127.0.0.1:8080"
	}
	return HttpRequest{
		Method:  r.Method,
		URI:     "http://" + host + flaskFullPath(r.URL),
		Path:    r.URL.Path,
		Query:   query,
		Headers: headers,
		Body:    body,
	}
}

func parseRawQuery(rawQuery string) map[string]string {
	query := map[string]string{}
	for _, param := range strings.Split(rawQuery, "&") {
		if param == "" {
			continue
		}
		kv := strings.SplitN(param, "=", 2)
		key := queryComponentNoPlusDecode(kv[0])
		value := ""
		if len(kv) == 2 {
			value = queryComponentNoPlusDecode(kv[1])
		}
		query[key] = value
	}
	return query
}

func queryComponentNoPlusDecode(value string) string {
	decoded, err := url.PathUnescape(value)
	if err != nil {
		return value
	}
	return decoded
}

func flaskFullPath(u *url.URL) string {
	if u.RawQuery != "" {
		return u.Path + "?" + u.RawQuery
	}
	return u.Path + "?"
}

func isSpace(ch byte) bool {
	return ch == ' ' || ch == '\t' || ch == '\r' || ch == '\n'
}
