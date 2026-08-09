package registration

import (
	"bytes"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/x509"
	"encoding/base64"
	"encoding/binary"
	"encoding/pem"
	"fmt"
	"io"
	"net"
	"net/http"
	"strconv"
	"strings"
	"sync/atomic"
	"time"

	"github.com/CyberTKR/line-go/api"
	"github.com/CyberTKR/line-go/protocol"
)

const linePublicKey = `-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAsMC6HAYeMq4R59e2yRw6
W1OWT2t9aepiAp4fbSCXzRj7A29BOAFAvKlzAub4oxN13Nt8dbcB+ICAufyDnN5N
d3+vXgDxEXZ/sx2/wuFbC3B3evSNKR4hKcs80suRs8aL6EeWi+bAU2oYIc78Bbqh
Nzx0WCzZSJbMBFw1VlsU/HQ/XdiUufopl5QSa0S246XXmwJmmXRO0v7bNvrxaNV0
cbviGkOvTlBt1+RerIFHMTw3SwLDnCOolTz3CuE5V2OrPZCmC0nlmPRzwUfxoxxs
/6qFdpZNoORH/s5mQenSyqPkmH8TBOlHJWPH3eN1k6aZIlK5S54mcUb/oNRRq9wD
1wIDAQAB
-----END PUBLIC KEY-----`

var legyIV = []byte{78, 9, 72, 62, 56, 245, 255, 114, 128, 18, 123, 158, 251, 92, 45, 51}

type ServiceError struct {
	Method  string
	Details map[int16]any
}

func (e *ServiceError) Error() string {
	code, _ := integerField(e.Details, 1)
	message, _ := e.Details[2].(string)
	message = strings.TrimSpace(message)
	if code == 0 && isTemporaryServerMessage(message) {
		return fmt.Sprintf("%s: LINE reported a temporary server error (code=0); retry the same registration session shortly", e.Method)
	}
	if message != "" {
		return fmt.Sprintf("%s: LINE rejected the request (code=%d): %s", e.Method, code, message)
	}
	var explanation string
	switch code {
	case 0:
		explanation = "LINE returned an unspecified server error; retry later"
	case 1:
		explanation = "invalid request; check that the mobile number format matches the selected region"
	case 5:
		explanation = "human verification is required"
	case 8:
		explanation = "the registration session is no longer valid; start registration again"
	case 35:
		explanation = "the request was blocked by LINE; avoid repeated attempts and try again later"
	default:
		explanation = "LINE did not provide an error description"
	}
	return fmt.Sprintf("%s: %s (code=%d)", e.Method, explanation, code)
}

func (e *ServiceError) Temporary() bool {
	message, _ := e.Details[2].(string)
	return e.Code() == 0 && isTemporaryServerMessage(message)
}

func isTemporaryServerMessage(message string) bool {
	normalized := strings.ToLower(strings.TrimSpace(message))
	return normalized == "" ||
		strings.Contains(normalized, "server error") ||
		strings.Contains(normalized, "サーバーエラー") ||
		strings.Contains(normalized, "서버 오류")
}

func (e *ServiceError) Code() int64 {
	code, _ := integerField(e.Details, 1)
	return code
}

func (e *ServiceError) WebAuthDetails() (WebAuthDetails, bool) {
	fields, ok := e.Details[11].(map[int16]any)
	if !ok {
		return WebAuthDetails{}, false
	}
	baseURL, _ := fields[1].(string)
	token, _ := fields[2].(string)
	details := WebAuthDetails{BaseURL: baseURL, Authorization: token}
	return details, details.Valid()
}

type legyClient struct {
	application string
	userAgent   string
	language    string
	le          int
	aesKey      []byte
	xLCS        string
	http        *http.Client
	sequence    atomic.Uint64
}

func newLegyClient(application, userAgent, language string, timeout time.Duration) (*legyClient, error) {
	aesKey := make([]byte, 16)
	if _, err := rand.Read(aesKey); err != nil {
		return nil, fmt.Errorf("generate LEGY AES key: %w", err)
	}
	block, _ := pem.Decode([]byte(linePublicKey))
	if block == nil {
		return nil, fmt.Errorf("decode LINE public key")
	}
	parsed, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("parse LINE public key: %w", err)
	}
	publicKey, ok := parsed.(*rsa.PublicKey)
	if !ok {
		return nil, fmt.Errorf("LINE public key is not RSA")
	}
	encryptedKey, err := rsa.EncryptOAEP(sha1.New(), rand.Reader, publicKey, aesKey, nil)
	if err != nil {
		return nil, fmt.Errorf("encrypt LEGY AES key: %w", err)
	}
	dialer := &net.Dialer{Timeout: 10 * time.Second, KeepAlive: 30 * time.Second}
	transport := &http.Transport{
		Proxy:                 http.ProxyFromEnvironment,
		DialContext:           dialer.DialContext,
		ForceAttemptHTTP2:     false,
		MaxIdleConns:          16,
		MaxIdleConnsPerHost:   8,
		IdleConnTimeout:       90 * time.Second,
		TLSHandshakeTimeout:   10 * time.Second,
		ExpectContinueTimeout: time.Second,
	}
	return &legyClient{
		application: application,
		userAgent:   userAgent,
		language:    language,
		le:          7,
		aesKey:      aesKey,
		xLCS:        "0008" + base64.StdEncoding.EncodeToString(encryptedKey),
		http:        &http.Client{Transport: transport, Timeout: timeout},
	}, nil
}

func (c *legyClient) close() {
	if transport, ok := c.http.Transport.(*http.Transport); ok {
		transport.CloseIdleConnections()
	}
}

func (c *legyClient) call(ctx context.Context, method, path string, fields []protocol.Field) (any, error) {
	sequence := c.sequence.Add(1)
	thriftBody, err := protocol.EncodeBinaryCall(method, fields, sequence)
	if err != nil {
		return nil, fmt.Errorf("encode %s: %w", method, err)
	}
	innerHeaders, err := encodeInnerHeaders(map[string]string{"x-lpqs": path})
	if err != nil {
		return nil, err
	}
	plaintext := append(innerHeaders, thriftBody...)
	if c.le&4 != 0 {
		plaintext = append([]byte{byte(c.le)}, plaintext...)
	}
	encrypted, err := encryptCBC(c.aesKey, plaintext)
	if err != nil {
		return nil, err
	}
	if c.le&2 != 0 {
		encrypted = append(encrypted, legyMAC(c.aesKey, encrypted)...)
	}

	request, err := http.NewRequestWithContext(ctx, http.MethodPost, api.RegistrationGatewayURL, bytes.NewReader(encrypted))
	if err != nil {
		return nil, fmt.Errorf("create LEGY request: %w", err)
	}
	request.Header.Set("x-line-application", c.application)
	request.Header.Set("x-le", strconv.Itoa(c.le))
	request.Header.Set("x-lap", "5")
	request.Header.Set("x-lpv", "1")
	request.Header.Set("x-lcs", c.xLCS)
	request.Header.Set("user-agent", c.userAgent)
	request.Header.Set("content-type", "application/x-thrift; protocol=TBINARY")
	request.Header.Set("x-lal", c.language)
	request.Header.Set("x-lhm", http.MethodPost)
	request.Header.Set("x-line-chrome-version", "3.1.0")
	request.Header.Set("accept", "*/*")
	request.Header.Set("connection", "keep-alive")

	response, err := c.http.Do(request)
	if err != nil {
		return nil, fmt.Errorf("LEGY request: %w", err)
	}
	defer response.Body.Close()
	raw, err := io.ReadAll(response.Body)
	if err != nil {
		return nil, fmt.Errorf("read LEGY response: %w", err)
	}
	if len(raw) == 0 {
		return nil, fmt.Errorf("%s: empty LEGY response (HTTP %d)", method, response.StatusCode)
	}
	decrypted, err := decryptCBC(c.aesKey, raw)
	if err != nil {
		return nil, fmt.Errorf("decrypt %s: %w", method, err)
	}
	if c.le&4 != 0 {
		if len(decrypted) == 0 {
			return nil, fmt.Errorf("%s: missing LEGY marker", method)
		}
		decrypted = decrypted[1:]
	}
	inner, thriftResponse, err := decodeInnerHeaders(decrypted)
	if err != nil {
		return nil, fmt.Errorf("decode %s LEGY headers: %w", method, err)
	}
	if response.StatusCode != http.StatusOK || (inner["x-lc"] != "" && inner["x-lc"] != "200") {
		return nil, fmt.Errorf("%s: LEGY rejected request HTTP=%d x-lc=%s", method, response.StatusCode, inner["x-lc"])
	}
	message, err := protocol.DecodeBinaryMessage(thriftResponse)
	if err != nil {
		return nil, fmt.Errorf("decode %s thrift response: %w", method, err)
	}
	if message.Type == 3 {
		return nil, fmt.Errorf("%s: thrift application exception", method)
	}
	if message.Type != 2 || message.Name != method || message.SequenceID != sequence {
		return nil, fmt.Errorf("%s: mismatched thrift response name=%q type=%d seq=%d", method, message.Name, message.Type, message.SequenceID)
	}
	if result, ok := message.Fields[0]; ok {
		return result, nil
	}
	if details, ok := message.Fields[1].(map[int16]any); ok {
		return nil, &ServiceError{Method: method, Details: details}
	}
	if len(message.Fields) == 0 {
		return nil, nil
	}
	return nil, fmt.Errorf("%s: missing result", method)
}

func encodeInnerHeaders(headers map[string]string) ([]byte, error) {
	var body bytes.Buffer
	if err := binary.Write(&body, binary.BigEndian, uint16(len(headers))); err != nil {
		return nil, err
	}
	for key, value := range headers {
		if len(key) > 65535 || len(value) > 65535 {
			return nil, fmt.Errorf("LEGY header too long")
		}
		_ = binary.Write(&body, binary.BigEndian, uint16(len(key)))
		body.WriteString(key)
		_ = binary.Write(&body, binary.BigEndian, uint16(len(value)))
		body.WriteString(value)
	}
	if body.Len() > 65535 {
		return nil, fmt.Errorf("LEGY headers too large")
	}
	result := make([]byte, 2+body.Len())
	binary.BigEndian.PutUint16(result, uint16(body.Len()))
	copy(result[2:], body.Bytes())
	return result, nil
}

func decodeInnerHeaders(data []byte) (map[string]string, []byte, error) {
	if len(data) < 4 {
		return nil, nil, fmt.Errorf("truncated LEGY headers")
	}
	headerLength := int(binary.BigEndian.Uint16(data[:2]))
	end := headerLength + 2
	if end > len(data) {
		return nil, nil, fmt.Errorf("invalid LEGY header length %d", headerLength)
	}
	count := int(binary.BigEndian.Uint16(data[2:4]))
	position := 4
	headers := make(map[string]string, count)
	for range count {
		if position+2 > end {
			return nil, nil, fmt.Errorf("truncated LEGY header key")
		}
		keyLength := int(binary.BigEndian.Uint16(data[position : position+2]))
		position += 2
		if position+keyLength+2 > end {
			return nil, nil, fmt.Errorf("truncated LEGY header value")
		}
		key := string(data[position : position+keyLength])
		position += keyLength
		valueLength := int(binary.BigEndian.Uint16(data[position : position+2]))
		position += 2
		if position+valueLength > end {
			return nil, nil, fmt.Errorf("truncated LEGY header value")
		}
		headers[key] = string(data[position : position+valueLength])
		position += valueLength
	}
	return headers, data[end:], nil
}

func encryptCBC(key, plaintext []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	padding := block.BlockSize() - len(plaintext)%block.BlockSize()
	padded := make([]byte, len(plaintext)+padding)
	copy(padded, plaintext)
	for index := len(plaintext); index < len(padded); index++ {
		padded[index] = byte(padding)
	}
	result := make([]byte, len(padded))
	cipher.NewCBCEncrypter(block, legyIV).CryptBlocks(result, padded)
	return result, nil
}

func decryptCBC(key, ciphertext []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	aligned := len(ciphertext) - len(ciphertext)%block.BlockSize()
	if aligned == 0 {
		return nil, fmt.Errorf("invalid LEGY ciphertext length %d", len(ciphertext))
	}
	result := make([]byte, aligned)
	cipher.NewCBCDecrypter(block, legyIV).CryptBlocks(result, ciphertext[:aligned])
	padding := int(result[len(result)-1])
	if padding < 1 || padding > block.BlockSize() || padding > len(result) {
		return nil, fmt.Errorf("invalid LEGY PKCS7 padding")
	}
	for _, value := range result[len(result)-padding:] {
		if int(value) != padding {
			return nil, fmt.Errorf("invalid LEGY PKCS7 padding")
		}
	}
	return result[:len(result)-padding], nil
}

func legyMAC(key, data []byte) []byte {
	opad := make([]byte, 16)
	ipad := make([]byte, 16)
	for index := range 16 {
		opad[index] = 0x5c ^ key[index]
		ipad[index] = 0x36 ^ key[index]
	}
	innerInput := append(ipad, data...)
	inner := xxhash32(innerInput, 0)
	var innerBytes [4]byte
	binary.BigEndian.PutUint32(innerBytes[:], inner)
	outerInput := append(opad, innerBytes[:]...)
	outer := xxhash32(outerInput, 0)
	var result [4]byte
	binary.BigEndian.PutUint32(result[:], outer)
	return result[:]
}

func xxhash32(data []byte, seed uint32) uint32 {
	const (
		prime1 uint32 = 2654435761
		prime2 uint32 = 2246822519
		prime3 uint32 = 3266489917
		prime4 uint32 = 668265263
		prime5 uint32 = 374761393
	)
	position := 0
	var hash uint32
	if len(data) >= 16 {
		v1 := seed + prime1 + prime2
		v2 := seed + prime2
		v3 := seed
		v4 := seed - prime1
		for position <= len(data)-16 {
			v1 = xxround(v1, binary.LittleEndian.Uint32(data[position:]))
			v2 = xxround(v2, binary.LittleEndian.Uint32(data[position+4:]))
			v3 = xxround(v3, binary.LittleEndian.Uint32(data[position+8:]))
			v4 = xxround(v4, binary.LittleEndian.Uint32(data[position+12:]))
			position += 16
		}
		hash = rotateLeft(v1, 1) + rotateLeft(v2, 7) + rotateLeft(v3, 12) + rotateLeft(v4, 18)
	} else {
		hash = seed + prime5
	}
	hash += uint32(len(data))
	for position <= len(data)-4 {
		hash += binary.LittleEndian.Uint32(data[position:]) * prime3
		hash = rotateLeft(hash, 17) * prime4
		position += 4
	}
	for position < len(data) {
		hash += uint32(data[position]) * prime5
		hash = rotateLeft(hash, 11) * prime1
		position++
	}
	hash ^= hash >> 15
	hash *= prime2
	hash ^= hash >> 13
	hash *= prime3
	hash ^= hash >> 16
	return hash
}

func xxround(accumulator, input uint32) uint32 {
	accumulator += input * 2246822519
	accumulator = rotateLeft(accumulator, 13)
	return accumulator * 2654435761
}

func rotateLeft(value uint32, count uint) uint32 {
	return value<<count | value>>(32-count)
}

func integerField(fields map[int16]any, id int16) (int64, bool) {
	switch value := fields[id].(type) {
	case int8:
		return int64(value), true
	case int16:
		return int64(value), true
	case int32:
		return int64(value), true
	case int64:
		return value, true
	default:
		return 0, false
	}
}

func stringField(fields map[int16]any, id int16) string {
	value, _ := fields[id].(string)
	return strings.TrimSpace(value)
}
