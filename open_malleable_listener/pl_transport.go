package main

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/rc4"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"os"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/gin-gonic/gin"

	"adaptix_listener_open_malleable/openmalleable"
)

type Listener struct {
	transport *TransportMalleable
}

type TransportMalleable struct {
	GinEngine *gin.Engine
	Server    *http.Server
	Config    TransportConfig
	Name      string
	Active    bool

	Profile *openmalleable.MalleableProfile
	MServer *openmalleable.MalleableServer
}

type TransportConfig struct {
	HostBind          string   `json:"host_bind"`
	PortBind          int      `json:"port_bind"`
	CallbackAddresses []string `json:"callback_addresses"`
	EncryptKey        string   `json:"encrypt_key"`

	Ssl         bool   `json:"ssl"`
	SslCert     []byte `json:"ssl_cert"`
	SslKey      []byte `json:"ssl_key"`
	SslCertPath string `json:"ssl_cert_path"`
	SslKeyPath  string `json:"ssl_key_path"`

	// Malleable profile content (base64-encoded from the file selector)
	MalleableProfileB64 string `json:"malleable_profile"`
	// Decoded profile text stored for serialization
	MalleableProfileText string `json:"malleable_profile_text"`

	HostHeader         []string `json:"host_header"`
	TrustXForwardedFor bool     `json:"x-forwarded-for"`
	WebPageError       string   `json:"page-error"`

	Protocol string `json:"protocol"`

	// Agent-facing config fields (for profile exchange with agent extender)
	// These are derived from the malleable profile and stored for GenerateProfiles
	HttpMethod     string   `json:"http_method"`
	Uri            []string `json:"uri"`
	ParameterName  string   `json:"hb_header"`
	UserAgent      []string `json:"user_agent"`
	RequestHeaders string   `json:"request_headers"`
	WebPageOutput  string   `json:"page-payload"`
}

func validConfig(config string) error {
	var conf TransportConfig
	err := json.Unmarshal([]byte(config), &conf)
	if err != nil {
		return err
	}

	if conf.HostBind == "" {
		return errors.New("HostBind is required")
	}

	if conf.PortBind < 1 || conf.PortBind > 65535 {
		return errors.New("PortBind must be in the range 1-65535")
	}

	if len(conf.CallbackAddresses) == 0 {
		return errors.New("callback_addresses is required")
	}
	for _, line := range conf.CallbackAddresses {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}

		host, portStr, err := net.SplitHostPort(line)
		if err != nil {
			return fmt.Errorf("Invalid address (cannot split host:port): %s", line)
		}

		port, err := strconv.Atoi(portStr)
		if err != nil || port < 1 || port > 65535 {
			return fmt.Errorf("Invalid port: %s", line)
		}

		ip := net.ParseIP(host)
		if ip == nil {
			if len(host) == 0 || len(host) > 253 {
				return fmt.Errorf("Invalid host: %s", line)
			}
			parts := strings.Split(host, ".")
			for _, part := range parts {
				if len(part) == 0 || len(part) > 63 {
					return fmt.Errorf("Invalid host: %s", line)
				}
			}
		}
	}

	match, _ := regexp.MatchString("^[0-9a-f]{32}$", conf.EncryptKey)
	if len(conf.EncryptKey) != 32 || !match {
		return errors.New("encrypt_key must be 32 hex characters")
	}

	if conf.MalleableProfileB64 == "" {
		return errors.New("malleable_profile is required")
	}

	return nil
}

func (t *TransportMalleable) InitProfile() error {
	profileText := t.Config.MalleableProfileText
	if profileText == "" && t.Config.MalleableProfileB64 != "" {
		decoded, err := base64.StdEncoding.DecodeString(t.Config.MalleableProfileB64)
		if err != nil {
			return fmt.Errorf("failed to decode malleable profile: %v", err)
		}
		profileText = string(decoded)
		t.Config.MalleableProfileText = profileText
	}
	if profileText == "" {
		return errors.New("malleable profile content is empty")
	}

	t.Profile = openmalleable.NewMalleableProfile(profileText)
	t.MServer = openmalleable.NewMalleableServer(t.Profile)

	// Derive agent-facing config from the malleable profile
	t.deriveProfileConfig()

	return nil
}

func (t *TransportMalleable) deriveProfileConfig() {
	// Extract URIs from http-get and http-post transactions
	var uris []string
	for _, tx := range t.Profile.HTTPGetTransactions {
		uris = append(uris, tx.URIs...)
	}
	for _, tx := range t.Profile.HTTPPostTransactions {
		uris = append(uris, tx.URIs...)
	}
	if len(uris) == 0 {
		uris = []string{"/"}
	}
	t.Config.Uri = uris

	// Set HTTP method from the GET transaction
	t.Config.HttpMethod = "GET"
	for _, tx := range t.Profile.HTTPGetTransactions {
		if tx.Method != "" {
			t.Config.HttpMethod = tx.Method
		}
		break
	}

	// Set user agent
	if t.Profile.UserAgent != "" {
		t.Config.UserAgent = []string{t.Profile.UserAgent}
	} else {
		t.Config.UserAgent = []string{"Mozilla/5.0"}
	}

	// Build request headers from GET client config
	var headerLines []string
	for _, tx := range t.Profile.HTTPGetTransactions {
		for _, h := range tx.Client.HeaderList {
			headerLines = append(headerLines, fmt.Sprintf("%s: %s", h.Key, h.Value))
		}
		break
	}
	t.Config.RequestHeaders = strings.Join(headerLines, "\r\n")
	if t.Config.RequestHeaders != "" {
		t.Config.RequestHeaders += "\r\n"
	}

	// Determine the heartbeat parameter name from the metadata termination
	t.Config.ParameterName = "Cookie"
	for _, tx := range t.Profile.HTTPGetTransactions {
		if tx.Client.Metadata != nil {
			switch tx.Client.Metadata.Termination.Type {
			case openmalleable.TerminationHeader:
				t.Config.ParameterName = tx.Client.Metadata.Termination.Target
			case openmalleable.TerminationParameter:
				t.Config.ParameterName = tx.Client.Metadata.Termination.Target
			}
		}
		break
	}

}

func (t *TransportMalleable) Start(ts Teamserver) error {
	var err error

	gin.SetMode(gin.ReleaseMode)
	router := gin.New()
	router.NoRoute(t.pageError)

	// Register all methods — the malleable profile determines which are valid
	router.Any("/*endpoint", t.processRequest)

	t.Active = true

	t.Server = &http.Server{
		Addr:    fmt.Sprintf("%s:%d", t.Config.HostBind, t.Config.PortBind),
		Handler: router,
	}

	if t.Config.Ssl {
		fmt.Printf("   Started listener '%s': https://%s:%d\n", t.Name, t.Config.HostBind, t.Config.PortBind)

		listenerPath := ListenerDataDir + "/" + t.Name
		_, err = os.Stat(listenerPath)
		if os.IsNotExist(err) {
			err = os.Mkdir(listenerPath, os.ModePerm)
			if err != nil {
				return fmt.Errorf("failed to create %s folder: %s", listenerPath, err.Error())
			}
		}

		t.Config.SslCertPath = listenerPath + "/listener.crt"
		t.Config.SslKeyPath = listenerPath + "/listener.key"

		if len(t.Config.SslCert) == 0 || len(t.Config.SslKey) == 0 || !t.certificateCoversConfiguredHosts(t.Config.SslCert) {
			err = t.generateSelfSignedCert(t.Config.SslCertPath, t.Config.SslKeyPath)
			if err != nil {
				t.Active = false
				fmt.Println("Error generating self-signed certificate:", err)
				return err
			}
		} else {
			err = os.WriteFile(t.Config.SslCertPath, t.Config.SslCert, 0600)
			if err != nil {
				return err
			}
			err = os.WriteFile(t.Config.SslKeyPath, t.Config.SslKey, 0600)
			if err != nil {
				return err
			}
		}

		cert, err := tls.LoadX509KeyPair(t.Config.SslCertPath, t.Config.SslKeyPath)
		if err != nil {
			t.Active = false
			return fmt.Errorf("failed to load certificate: %v", err)
		}

		t.Server.TLSConfig = &tls.Config{
			Certificates: []tls.Certificate{cert},
			MinVersion:   tls.VersionTLS10,
			MaxVersion:   tls.VersionTLS13,
			CipherSuites: []uint16{
				tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
				tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
				tls.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256,
				tls.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA,
				tls.TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA,
				tls.TLS_RSA_WITH_AES_128_GCM_SHA256,
				tls.TLS_RSA_WITH_AES_256_GCM_SHA384,
				tls.TLS_RSA_WITH_AES_128_CBC_SHA256,
				tls.TLS_RSA_WITH_AES_128_CBC_SHA,
				tls.TLS_RSA_WITH_AES_256_CBC_SHA,
			},
		}

		go func() {
			err = t.Server.ListenAndServeTLS("", "")
			if err != nil && !errors.Is(err, http.ErrServerClosed) {
				fmt.Printf("Error starting HTTPS server: %v\n", err)
				return
			}
			t.Active = true
		}()

	} else {
		fmt.Printf("   Started listener '%s': http://%s:%d\n", t.Name, t.Config.HostBind, t.Config.PortBind)

		go func() {
			err = t.Server.ListenAndServe()
			if err != nil && !errors.Is(err, http.ErrServerClosed) {
				fmt.Printf("Error starting HTTP server: %v\n", err)
				return
			}
			t.Active = true
		}()
	}

	time.Sleep(500 * time.Millisecond)
	return err
}

func (t *TransportMalleable) Stop() error {
	var (
		ctx          context.Context
		cancel       context.CancelFunc
		err          error
		listenerPath = ListenerDataDir + "/" + t.Name
	)

	ctx, cancel = context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	_, err = os.Stat(listenerPath)
	if err == nil {
		err = os.RemoveAll(listenerPath)
		if err != nil {
			return fmt.Errorf("failed to remove %s folder: %s", listenerPath, err.Error())
		}
	}

	err = t.Server.Shutdown(ctx)
	return err
}

func (t *TransportMalleable) processRequest(ctx *gin.Context) {
	var (
		ExternalIP   string
		err          error
		agentType    string
		agentId      string
		beat         []byte
		bodyData     []byte
		responseData []byte
	)

	// Determine client IP
	if t.Config.TrustXForwardedFor && ctx.Request.Header.Get("X-Forwarded-For") != "" {
		ExternalIP = ctx.Request.Header.Get("X-Forwarded-For")
	} else {
		ExternalIP = strings.Split(ctx.Request.RemoteAddr, ":")[0]
	}

	// Log request received with method/path/remote address
	fmt.Printf("[DEBUG] Host:%s | Request received: %s %s from %s\n", ctx.Request.Host, ctx.Request.Method, ctx.Request.URL.Path, ExternalIP)
	fmt.Printf("[DEBUG] Request Headers: %v\n", ctx.Request.Header)

	// Read body
	body, err := io.ReadAll(ctx.Request.Body)
	if err != nil {
		fmt.Printf("[DEBUG] Failed to read request body: %v\n", err)
		t.pageError(ctx)
		return
	}

	// Build openmalleable request from Gin context
	httpRequest := openmalleable.NewHTTPRequestFromHTTP(ctx.Request, body)

	// Validate host header if configured in listener settings or the malleable profile.
	validHostHeaders := t.effectiveHostHeaders()
	if len(validHostHeaders) > 0 {
		requestHost := ctx.Request.Host
		hhValid := false
		for _, configHH := range validHostHeaders {
			if configHH == requestHost {
				hhValid = true
				break
			}
		}
		if !hhValid {
			fmt.Printf("[DEBUG] Host header validation failed: expected one of %v, got %s\n", validHostHeaders, requestHost)
			t.pageError(ctx)
			return
		}
	}

	// Try to handle as GET (check-in/task retrieval) first
	if t.tryHandleGet(ctx, httpRequest, ExternalIP) {
		return
	}

	// Try to handle as POST (task result submission)
	if t.tryHandlePost(ctx, httpRequest, ExternalIP) {
		return
	}

	// Neither matched — this is a stray request
	fmt.Printf("[DEBUG] Request didn't match GET metadata or POST session/output extraction fields\n")
	t.pageError(ctx)
	_ = agentType
	_ = agentId
	_ = beat
	_ = bodyData
	_ = responseData
	_ = err
}

func (t *TransportMalleable) findGetVariant(method, path string) string {
	if t == nil || t.MServer == nil {
		return ""
	}
	return t.MServer.FindGetVariant(method, path)
}

func (t *TransportMalleable) findPostVariant(method, path string) string {
	if t == nil || t.MServer == nil {
		return ""
	}
	return t.MServer.FindPostVariant(method, path)
}

func (t *TransportMalleable) tryHandleGet(ctx *gin.Context, httpRequest openmalleable.HttpRequest, externalIP string) bool {
	variant := t.findGetVariant(httpRequest.Method, httpRequest.Path)
	if variant == "" {
		return false
	}

	metadata, err := t.MServer.ExtractMetadata(httpRequest, variant)
	if err != nil {
		fmt.Printf("[DEBUG] GET metadata extraction failed: %v\n", err)
		t.pageError(ctx)
		return true
	}

	agentType, agentId, beat, err := t.parseMetadataBeat(metadata)
	if err != nil {
		fmt.Printf("[DEBUG] Failed to parse metadata beat: %v\n", err)
		t.pageError(ctx)
		return true
	}

	created := false
	if !Ts.TsAgentIsExists(agentId) {
		_, err = Ts.TsAgentCreate(agentType, agentId, beat, t.Name, externalIP, true)
		if err != nil {
			fmt.Printf("[DEBUG] Failed to create new agent %s: %v\n", agentId, err)
			t.pageError(ctx)
			return true
		}
		created = true
	}

	if created {
		fmt.Printf("[DEBUG] Successful new agent created: id=%s type=%s ip=%s\n", agentId, agentType, externalIP)
	} else {
		fmt.Printf("[DEBUG] Successful tick/update from agent %s (GET request matched)\n", agentId)
	}

	_ = Ts.TsAgentSetTick(agentId, t.Name)

	responseData, err := Ts.TsAgentGetHostedAll(agentId, 0x1900000) // 25 Mb
	if err != nil {
		fmt.Printf("[DEBUG] Failed to get hosted tasks for agent %s: %v\n", agentId, err)
		t.pageError(ctx)
		return true
	}

	response, err := t.MServer.BuildGetResponse(responseData, variant)
	if err != nil {
		fmt.Printf("[DEBUG] Failed to build malleable GET response: %v\n", err)
		t.pageError(ctx)
		return true
	}

	t.sendMalleableResponse(ctx, response)
	return true
}

func (t *TransportMalleable) tryHandlePost(ctx *gin.Context, httpRequest openmalleable.HttpRequest, externalIP string) bool {
	variant := t.findPostVariant(httpRequest.Method, httpRequest.Path)
	if variant == "" {
		return false
	}

	sessionID, err := t.MServer.ExtractSessionID(httpRequest, variant)
	if err != nil {
		fmt.Printf("[DEBUG] POST session ID extraction failed: %v\n", err)
		t.pageError(ctx)
		return true
	}

	outputData, err := t.MServer.ExtractOutput(httpRequest, variant)
	if err != nil {
		fmt.Printf("[DEBUG] POST output extraction failed: %v\n", err)
		t.pageError(ctx)
		return true
	}

	agentType, agentId, beat, err := t.parseMetadataBeat(sessionID)
	if err != nil {
		fmt.Printf("[DEBUG] Failed to parse session ID beat: %v\n", err)
		t.pageError(ctx)
		return true
	}

	if !Ts.TsAgentIsExists(agentId) {
		_, err = Ts.TsAgentCreate(agentType, agentId, beat, t.Name, externalIP, true)
		if err != nil {
			fmt.Printf("[DEBUG] Failed to create new agent %s from POST: %v\n", agentId, err)
			t.pageError(ctx)
			return true
		}
		fmt.Printf("[DEBUG] Successful new agent created: id=%s type=%s ip=%s\n", agentId, agentType, externalIP)
	} else {
		fmt.Printf("[DEBUG] Successful tick/update from agent %s (POST request matched)\n", agentId)
	}

	_ = Ts.TsAgentSetTick(agentId, t.Name)

	if err := Ts.TsAgentProcessData(agentId, outputData); err != nil {
		fmt.Printf("[DEBUG] Failed to process agent output for %s: %v\n", agentId, err)
		t.pageError(ctx)
		return true
	}

	response, err := t.MServer.BuildPostResponse([]byte{}, variant)
	if err != nil {
		fmt.Printf("[DEBUG] Failed to build malleable POST response: %v\n", err)
		t.pageError(ctx)
		return true
	}

	t.sendMalleableResponse(ctx, response)
	return true
}

func (t *TransportMalleable) parseMetadataBeat(data []byte) (string, string, []byte, error) {
	if len(data) < 8 {
		return "", "", nil, errors.New("metadata too short")
	}

	encKey, err := hex.DecodeString(t.Config.EncryptKey)
	if err != nil {
		return "", "", nil, errors.New("failed to decode encrypt key")
	}

	rc4cipher, err := rc4.NewCipher(encKey)
	if err != nil {
		return "", "", nil, errors.New("rc4 cipher error")
	}

	decrypted := make([]byte, len(data))
	rc4cipher.XORKeyStream(decrypted, data)

	agentType := uint(binary.BigEndian.Uint32(decrypted[:4]))
	decrypted = decrypted[4:]
	agentId := uint(binary.BigEndian.Uint32(decrypted[:4]))
	agentInfo := decrypted[4:]

	return fmt.Sprintf("%08x", agentType), fmt.Sprintf("%08x", agentId), agentInfo, nil
}

func (t *TransportMalleable) sendMalleableResponse(ctx *gin.Context, response openmalleable.HttpResponse) {
	for _, header := range response.HeaderList {
		ctx.Header(header.Key, header.Value)
	}

	statusCode := response.StatusCode
	if statusCode == 0 {
		statusCode = 200
	}

	if len(response.Body) > 0 {
		ctx.Data(statusCode, "", response.Body)
	} else {
		ctx.Status(statusCode)
	}
}

func (t *TransportMalleable) generateSelfSignedCert(certFile, keyFile string) error {
	var (
		certData   []byte
		keyData    []byte
		certBuffer bytes.Buffer
		keyBuffer  bytes.Buffer
		privateKey *rsa.PrivateKey
		err        error
	)

	privateKey, err = rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return fmt.Errorf("failed to generate private key: %v", err)
	}

	serialNumberLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	serialNumber, err := rand.Int(rand.Reader, serialNumberLimit)
	if err != nil {
		return fmt.Errorf("failed to generate serial number: %v", err)
	}

	template := x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			CommonName: t.certificateCommonName(),
		},
		NotBefore: time.Now(),
		NotAfter:  time.Now().Add(365 * 24 * time.Hour),

		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}

	hostBind := strings.TrimSpace(t.Config.HostBind)
	if hostBind == "" || hostBind == "0.0.0.0" || hostBind == "::" {
		template.DNSNames = []string{"localhost"}
		template.IPAddresses = []net.IP{net.ParseIP("127.0.0.1"), net.ParseIP("::1")}
	} else if ip := net.ParseIP(hostBind); ip != nil {
		template.IPAddresses = []net.IP{ip}
	} else {
		template.DNSNames = []string{hostBind}
	}
	t.addCertificateHosts(&template)

	certData, err = x509.CreateCertificate(rand.Reader, &template, &template, &privateKey.PublicKey, privateKey)
	if err != nil {
		return fmt.Errorf("failed to create certificate: %v", err)
	}

	err = pem.Encode(&certBuffer, &pem.Block{Type: "CERTIFICATE", Bytes: certData})
	if err != nil {
		return fmt.Errorf("failed to write certificate: %v", err)
	}

	t.Config.SslCert = certBuffer.Bytes()
	err = os.WriteFile(certFile, t.Config.SslCert, 0644)
	if err != nil {
		return fmt.Errorf("failed to create certificate file: %v", err)
	}

	keyData = x509.MarshalPKCS1PrivateKey(privateKey)
	err = pem.Encode(&keyBuffer, &pem.Block{Type: "RSA PRIVATE KEY", Bytes: keyData})
	if err != nil {
		return fmt.Errorf("failed to write private key: %v", err)
	}

	t.Config.SslKey = keyBuffer.Bytes()
	err = os.WriteFile(keyFile, t.Config.SslKey, 0644)
	if err != nil {
		return fmt.Errorf("failed to create key file: %v", err)
	}

	return nil
}

func (t *TransportMalleable) certificateCommonName() string {
	for _, host := range t.certificateHosts() {
		return host
	}
	hostBind := normalizeCertificateHost(t.Config.HostBind)
	if hostBind != "" && hostBind != "0.0.0.0" && hostBind != "::" {
		return hostBind
	}
	return "localhost"
}

func (t *TransportMalleable) addCertificateHosts(template *x509.Certificate) {
	for _, host := range t.certificateHosts() {
		if ip := net.ParseIP(host); ip != nil {
			template.IPAddresses = appendUniqueIP(template.IPAddresses, ip)
		} else {
			template.DNSNames = appendUniqueString(template.DNSNames, host)
		}
	}
}

func (t *TransportMalleable) certificateCoversConfiguredHosts(certPEM []byte) bool {
	hosts := t.certificateHosts()
	if len(hosts) == 0 {
		return true
	}

	block, _ := pem.Decode(certPEM)
	if block == nil {
		return false
	}

	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return false
	}

	for _, host := range hosts {
		if err := cert.VerifyHostname(host); err != nil {
			return false
		}
	}
	return true
}

func (t *TransportMalleable) certificateHosts() []string {
	var hosts []string
	for _, hostHeader := range t.effectiveHostHeaders() {
		host := normalizeCertificateHost(hostHeader)
		if host != "" {
			hosts = appendUniqueString(hosts, host)
		}
	}
	return hosts
}

func (t *TransportMalleable) effectiveHostHeaders() []string {
	var hosts []string
	for _, hostHeader := range t.Config.HostHeader {
		hostHeader = strings.TrimSpace(hostHeader)
		if hostHeader != "" {
			hosts = appendUniqueString(hosts, hostHeader)
		}
	}
	for _, hostHeader := range t.profileHostHeaders() {
		hostHeader = strings.TrimSpace(hostHeader)
		if hostHeader != "" {
			hosts = appendUniqueString(hosts, hostHeader)
		}
	}
	return hosts
}

func (t *TransportMalleable) profileHostHeaders() []string {
	if t == nil || t.Profile == nil {
		return nil
	}

	var hosts []string
	for _, tx := range t.Profile.HTTPGetTransactions {
		hosts = appendProfileHostHeaders(hosts, tx.Client.HeaderList)
	}
	for _, tx := range t.Profile.HTTPPostTransactions {
		hosts = appendProfileHostHeaders(hosts, tx.Client.HeaderList)
	}
	return hosts
}

func appendProfileHostHeaders(hosts []string, headers []openmalleable.Header) []string {
	for _, header := range headers {
		if strings.EqualFold(strings.TrimSpace(header.Key), "Host") {
			host := strings.TrimSpace(header.Value)
			if host != "" {
				hosts = appendUniqueString(hosts, host)
			}
		}
	}
	return hosts
}

func normalizeCertificateHost(host string) string {
	host = strings.TrimSpace(host)
	if host == "" {
		return ""
	}
	if strings.Contains(host, "://") {
		if start := strings.Index(host, "://"); start >= 0 {
			host = host[start+3:]
		}
		if slash := strings.Index(host, "/"); slash >= 0 {
			host = host[:slash]
		}
	}
	if parsedHost, _, err := net.SplitHostPort(host); err == nil {
		host = parsedHost
	} else if strings.HasPrefix(host, "[") && strings.HasSuffix(host, "]") {
		host = strings.TrimPrefix(strings.TrimSuffix(host, "]"), "[")
	}
	return strings.TrimSpace(host)
}

func appendUniqueString(values []string, value string) []string {
	for _, existing := range values {
		if strings.EqualFold(existing, value) {
			return values
		}
	}
	return append(values, value)
}

func appendUniqueIP(values []net.IP, value net.IP) []net.IP {
	for _, existing := range values {
		if existing.Equal(value) {
			return values
		}
	}
	return append(values, value)
}

func (t *TransportMalleable) pageError(ctx *gin.Context) {
	ctx.Writer.WriteHeader(http.StatusNotFound)
	html := []byte(t.Config.WebPageError)
	_, _ = ctx.Writer.Write(html)
}
