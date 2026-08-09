package registration

import (
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha1"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"strings"
	"time"

	"github.com/CyberTKR/line-go/api"
	"github.com/CyberTKR/line-go/protocol"
)

type Config struct {
	Application         string
	UserAgent           string
	Language            string
	DeviceModel         string
	DisplayName         string
	Password            string
	Timeout             time.Duration
	BrowserExecutable   string
	VerificationMethod  string
	SIMHNI              string
	SIMCarrier          string
	VerificationTimeout time.Duration
}

type Event struct {
	Step    int
	Kind    string
	Message string
}

type Result struct {
	MID            string
	AuthKey        string
	PrimaryToken   string
	AccessToken    string
	RefreshToken   string
	DurationSec    int64
	LoginSessionID string
	DeviceUID      string
	DisplayName    string
	Region         string
}

type PINProvider func(context.Context) (string, error)
type EventHandler func(Event)

type Client struct {
	config   Config
	legy     *legyClient
	verifier HumanVerifier
}

func New(config Config) (*Client, error) {
	if strings.TrimSpace(config.Application) == "" || strings.TrimSpace(config.UserAgent) == "" {
		return nil, fmt.Errorf("registration application and user agent are required")
	}
	if strings.TrimSpace(config.DeviceModel) == "" {
		config.DeviceModel = "SM-S928B"
	}
	if strings.TrimSpace(config.DisplayName) == "" {
		config.DisplayName = "LINE User"
	}
	if strings.TrimSpace(config.Language) == "" {
		config.Language = "ja_JP"
	}
	if err := validateRegistrationPassword(config.Password); err != nil {
		return nil, err
	}
	config.VerificationMethod = strings.ToLower(strings.TrimSpace(config.VerificationMethod))
	if config.VerificationMethod == "" {
		config.VerificationMethod = "auto"
	}
	if config.VerificationMethod != "auto" && config.VerificationMethod != "sms" && config.VerificationMethod != "voice" {
		return nil, fmt.Errorf("verification method must be auto, sms, or voice")
	}
	config.SIMHNI = strings.TrimSpace(config.SIMHNI)
	config.SIMCarrier = strings.TrimSpace(config.SIMCarrier)
	if (config.SIMHNI == "") != (config.SIMCarrier == "") {
		return nil, fmt.Errorf("SIM HNI and carrier must be provided together")
	}
	if config.SIMHNI != "" {
		if len(config.SIMHNI) < 5 || len(config.SIMHNI) > 6 {
			return nil, fmt.Errorf("SIM HNI must contain 5 or 6 digits")
		}
		for _, character := range config.SIMHNI {
			if character < '0' || character > '9' {
				return nil, fmt.Errorf("SIM HNI must contain only digits")
			}
		}
	}
	legy, err := newLegyClient(config.Application, config.UserAgent, config.Language, config.Timeout)
	if err != nil {
		return nil, err
	}
	return &Client{
		config: config,
		legy:   legy,
		verifier: BrowserVerifier{
			Executable: config.BrowserExecutable,
			Timeout:    config.VerificationTimeout,
		},
	}, nil
}

func (c *Client) Close() { c.legy.close() }

func (c *Client) RegisterPhone(ctx context.Context, phone, region string, providePIN PINProvider, emit EventHandler) (Result, error) {
	phone = strings.TrimSpace(phone)
	region = strings.ToUpper(strings.TrimSpace(region))
	if phone == "" || region == "" {
		return Result{}, fmt.Errorf("phone and region are required")
	}
	switch region {
	case "TW", "TH", "JP", "KR", "HK":
	default:
		return Result{}, fmt.Errorf("unsupported registration region %q; use TW, TH, JP, KR, or HK", region)
	}
	phone, err := validatePhoneForRegion(phone, region)
	if err != nil {
		return Result{}, err
	}
	if providePIN == nil {
		return Result{}, fmt.Errorf("PIN provider is required")
	}
	notify := func(step int, kind, message string) {
		if emit != nil {
			emit(Event{Step: step, Kind: kind, Message: message})
		}
	}

	notify(1, "progress", "Opening registration session")
	opened, err := c.call(ctx, "openSession", []protocol.Field{
		protocol.F(1, protocol.Struct, []protocol.Field{
			protocol.MapField(1, protocol.String, protocol.String, map[any]any{}),
		}),
	})
	if err != nil {
		return Result{}, err
	}
	authSessionID := resultString(opened, 1)
	if authSessionID == "" {
		return Result{}, fmt.Errorf("openSession returned no session ID")
	}

	notify(2, "progress", "Retrieving country information")
	simCard := []protocol.Field{protocol.F(1, protocol.String, region)}
	if c.config.SIMHNI != "" {
		simCard = append(simCard,
			protocol.F(2, protocol.String, c.config.SIMHNI),
			protocol.F(3, protocol.String, c.config.SIMCarrier),
		)
		notify(2, "sim_profile", fmt.Sprintf("Using SIM profile country=%s HNI=%s carrier=%s", region, c.config.SIMHNI, c.config.SIMCarrier))
	}
	if _, err := c.call(ctx, "getCountryInfo", []protocol.Field{
		protocol.F(1, protocol.String, authSessionID),
		protocol.F(11, protocol.Struct, simCard),
	}); err != nil {
		return Result{}, err
	}

	notify(3, "progress", "Checking phone registration availability")
	allowed, err := c.call(ctx, "getAllowedRegistrationMethod", []protocol.Field{
		protocol.F(1, protocol.String, authSessionID),
		protocol.F(2, protocol.String, region),
	})
	if err != nil {
		return Result{}, err
	}
	method, ok := resultInteger(allowed, 1)
	if !ok {
		method, ok = anyInteger(allowed)
	}
	if !ok || method != 1 {
		return Result{}, fmt.Errorf("phone registration is not available for region %s", region)
	}

	deviceUID, err := randomHex(16)
	if err != nil {
		return Result{}, err
	}
	phoneStruct := func(number string) []protocol.Field {
		return []protocol.Field{
			protocol.F(1, protocol.String, number),
			protocol.F(2, protocol.String, region),
		}
	}
	notify(4, "progress", "Retrieving SMS verification methods")
	verification, err := c.call(ctx, "getPhoneVerifMethodForRegistration", []protocol.Field{
		protocol.F(1, protocol.Struct, []protocol.Field{
			protocol.F(1, protocol.String, authSessionID),
			protocol.F(2, protocol.Struct, []protocol.Field{
				protocol.F(1, protocol.String, deviceUID),
				protocol.F(2, protocol.String, c.config.DeviceModel),
			}),
			protocol.F(3, protocol.Struct, phoneStruct(phone)),
		}),
	})
	if err != nil {
		return Result{}, err
	}
	verificationFields, ok := verification.(map[int16]any)
	if !ok {
		return Result{}, fmt.Errorf("verification method response has an unexpected shape")
	}
	methods, ok := verificationFields[1].([]any)
	if !ok || len(methods) == 0 {
		return Result{}, fmt.Errorf("LINE returned no phone verification method")
	}
	formattedPhone := stringField(verificationFields, 2)
	if formattedPhone == "" {
		formattedPhone = phone
	}
	availableMethods := make([]int64, 0, len(methods))
	for _, method := range methods {
		if value, valid := anyInteger(method); valid {
			availableMethods = append(availableMethods, value)
		}
	}
	verificationMethod, methodName, err := selectVerificationMethod(availableMethods, c.config.VerificationMethod)
	if err != nil {
		return Result{}, err
	}
	notify(4, "verification_methods", fmt.Sprintf("Verification target %s; available methods: %s; selected: %s", maskPhone(formattedPhone), verificationMethodNames(availableMethods), methodName))

	notify(5, "progress", "Requesting SMS PIN")
	sendPIN := func() (any, error) {
		return c.call(ctx, "requestToSendPhonePinCode", []protocol.Field{
			protocol.F(1, protocol.Struct, []protocol.Field{
				protocol.F(1, protocol.String, authSessionID),
				protocol.F(2, protocol.Struct, phoneStruct(formattedPhone)),
				protocol.F(3, protocol.I32, verificationMethod),
			}),
		})
	}
	if _, err := c.callWithHumanVerification(ctx, sendPIN, notify); err != nil {
		return Result{}, err
	}

	pin, err := providePIN(ctx)
	if err != nil {
		return Result{}, fmt.Errorf("read PIN: %w", err)
	}
	pin = strings.TrimSpace(pin)
	if pin == "" {
		return Result{}, fmt.Errorf("PIN is empty")
	}
	notify(6, "progress", "Verifying SMS PIN")
	verifyPIN := func() (any, error) {
		return c.call(ctx, "verifyPhonePinCode", []protocol.Field{
			protocol.F(1, protocol.Struct, []protocol.Field{
				protocol.F(1, protocol.String, authSessionID),
				protocol.F(2, protocol.Struct, phoneStruct(phone)),
				protocol.F(3, protocol.String, pin),
			}),
		})
	}
	if _, err := c.callWithHumanVerification(ctx, verifyPIN, notify); err != nil {
		return Result{}, err
	}

	notify(7, "progress", "Validating profile name")
	if _, err := c.call(ctx, "validateProfile", []protocol.Field{
		protocol.F(1, protocol.String, authSessionID),
		protocol.F(2, protocol.String, c.config.DisplayName),
	}); err != nil {
		return Result{}, err
	}

	notify(8, "progress", "Retrieving password parameters")
	passwordResponse, err := c.call(ctx, "getPasswordHashingParametersForPwdReg", []protocol.Field{
		protocol.F(1, protocol.Struct, []protocol.Field{protocol.F(1, protocol.String, authSessionID)}),
	})
	if err != nil {
		return Result{}, err
	}
	parameters, err := parsePasswordParameters(passwordResponse)
	if err != nil {
		return Result{}, err
	}
	notify(9, "progress", "Deriving password hash locally")
	hashedPassword, err := derivePassword(c.config.Password, parameters)
	if err != nil {
		return Result{}, err
	}
	notify(10, "progress", "Saving password hash")
	if _, err := c.call(ctx, "setHashedPassword", []protocol.Field{
		protocol.F(1, protocol.Struct, []protocol.Field{
			protocol.F(1, protocol.String, authSessionID),
			protocol.F(2, protocol.String, hashedPassword),
		}),
	}); err != nil {
		return Result{}, err
	}

	notify(11, "progress", "Completing account registration")
	register := func() (any, error) {
		return c.call(ctx, "registerPrimaryUsingPhoneWithTokenV3", []protocol.Field{
			protocol.F(2, protocol.String, authSessionID),
		})
	}
	registered, err := c.callWithHumanVerification(ctx, register, notify)
	if err != nil {
		return Result{}, err
	}
	result, err := parseResult(registered)
	if err != nil {
		return Result{}, err
	}
	result.DeviceUID = deviceUID
	result.DisplayName = c.config.DisplayName
	result.Region = region
	result.PrimaryToken, err = createPrimaryToken(result.AuthKey)
	if err != nil {
		return Result{}, err
	}
	notify(11, "complete", "Registration completed")
	return result, nil
}

func selectVerificationMethod(available []int64, requested string) (int64, string, error) {
	desired := int64(0)
	switch requested {
	case "sms":
		desired = 1
	case "voice":
		desired = 2
	case "auto":
		if len(available) > 0 {
			desired = available[0]
		}
	}
	for _, method := range available {
		if method == desired {
			return method, verificationMethodName(method), nil
		}
	}
	return 0, "", fmt.Errorf("requested %s verification is unavailable; LINE offered %s", requested, verificationMethodNames(available))
}

func verificationMethodName(method int64) string {
	switch method {
	case 1:
		return "SMS"
	case 2:
		return "voice call"
	case 3:
		return "SMS pull"
	default:
		return fmt.Sprintf("unknown(%d)", method)
	}
}

func verificationMethodNames(methods []int64) string {
	if len(methods) == 0 {
		return "none"
	}
	names := make([]string, 0, len(methods))
	for _, method := range methods {
		names = append(names, verificationMethodName(method))
	}
	return strings.Join(names, ", ")
}

func maskPhone(phone string) string {
	runes := []rune(strings.TrimSpace(phone))
	if len(runes) <= 4 {
		return strings.Repeat("*", len(runes))
	}
	visible := 4
	return strings.Repeat("*", len(runes)-visible) + string(runes[len(runes)-visible:])
}

func validatePhoneForRegion(phone, region string) (string, error) {
	normalized := strings.NewReplacer(" ", "", "-", "", "(", "", ")", "").Replace(strings.TrimSpace(phone))
	if normalized == "" {
		return "", fmt.Errorf("phone number is required")
	}
	for index, character := range normalized {
		if character == '+' && index == 0 {
			continue
		}
		if character < '0' || character > '9' {
			return "", fmt.Errorf("phone number contains unsupported characters")
		}
	}
	valid := false
	example := ""
	switch region {
	case "TW":
		valid = len(normalized) == 10 && strings.HasPrefix(normalized, "09") || len(normalized) == 13 && strings.HasPrefix(normalized, "+8869")
		example = "09XXXXXXXX or +8869XXXXXXXX"
	case "KR":
		valid = len(normalized) == 11 && strings.HasPrefix(normalized, "010") || len(normalized) == 13 && strings.HasPrefix(normalized, "+8210")
		example = "010XXXXXXXX or +8210XXXXXXXX"
	case "TH":
		valid = len(normalized) == 10 && strings.HasPrefix(normalized, "0") || len(normalized) == 12 && strings.HasPrefix(normalized, "+66")
		example = "0XXXXXXXXX or +66XXXXXXXXX"
	case "JP":
		localMobile := strings.HasPrefix(normalized, "070") || strings.HasPrefix(normalized, "080") || strings.HasPrefix(normalized, "090")
		internationalMobile := strings.HasPrefix(normalized, "+8170") || strings.HasPrefix(normalized, "+8180") || strings.HasPrefix(normalized, "+8190")
		valid = len(normalized) == 11 && localMobile || len(normalized) == 13 && internationalMobile
		example = "070/080/090XXXXXXXX or +8170/+8180/+8190XXXXXXXX"
	case "HK":
		valid = len(normalized) == 8 || len(normalized) == 12 && strings.HasPrefix(normalized, "+852")
		example = "XXXXXXXX or +852XXXXXXXX"
	}
	if !valid {
		return "", fmt.Errorf("phone number format does not match region %s; expected a mobile number such as %s", region, example)
	}
	return normalized, nil
}

func (c *Client) call(ctx context.Context, method string, fields []protocol.Field) (any, error) {
	return c.legy.call(ctx, method, api.RegistrationPath, fields)
}

func (c *Client) callWithHumanVerification(ctx context.Context, call func() (any, error), notify func(int, string, string)) (any, error) {
	result, err := call()
	if err == nil {
		return result, nil
	}
	serviceError, ok := err.(*ServiceError)
	if !ok || serviceError.Code() != 5 {
		return nil, err
	}
	details, ok := serviceError.WebAuthDetails()
	if !ok {
		return nil, fmt.Errorf("%s returned human verification without valid WebAuthDetails", serviceError.Method)
	}
	notify(0, "human_verification", "LINE requested human verification; opening the official page in Chrome")
	if err := c.verifier.Verify(ctx, details); err != nil {
		return nil, fmt.Errorf("manual human verification: %w", err)
	}
	notify(0, "human_verification_complete", "Human verification accepted; retrying in the same session")
	return call()
}

func parsePasswordParameters(value any) (passwordParameters, error) {
	outer, ok := value.(map[int16]any)
	if !ok {
		return passwordParameters{}, fmt.Errorf("password parameter response has an unexpected shape")
	}
	hashing, ok := outer[1].(map[int16]any)
	if !ok {
		return passwordParameters{}, fmt.Errorf("password hashing parameters are missing")
	}
	scryptFields, ok := hashing[2].(map[int16]any)
	if !ok {
		return passwordParameters{}, fmt.Errorf("scrypt parameters are missing")
	}
	dkLen, ok := integerField(scryptFields, 3)
	if !ok || dkLen <= 0 || dkLen > 4096 {
		return passwordParameters{}, fmt.Errorf("invalid scrypt output length")
	}
	result := passwordParameters{
		HMACKey: stringField(hashing, 1),
		Salt:    stringField(scryptFields, 1),
		NRP:     stringField(scryptFields, 2),
		DKLen:   int(dkLen),
	}
	if result.HMACKey == "" || result.Salt == "" || result.NRP == "" {
		return passwordParameters{}, fmt.Errorf("incomplete password hashing parameters")
	}
	return result, nil
}

func parseResult(value any) (Result, error) {
	fields, ok := value.(map[int16]any)
	if !ok {
		return Result{}, fmt.Errorf("registration response has an unexpected shape")
	}
	token, ok := fields[2].(map[int16]any)
	if !ok {
		return Result{}, fmt.Errorf("registration token response is missing")
	}
	duration, _ := integerField(token, 3)
	result := Result{
		AuthKey:        stringField(fields, 1),
		AccessToken:    stringField(token, 1),
		RefreshToken:   stringField(token, 2),
		DurationSec:    duration,
		LoginSessionID: stringField(token, 5),
		MID:            stringField(fields, 3),
	}
	if result.AuthKey == "" || result.AccessToken == "" || result.RefreshToken == "" || result.MID == "" {
		return Result{}, fmt.Errorf("registration response is incomplete")
	}
	return result, nil
}

func createPrimaryToken(authKey string) (string, error) {
	separator := strings.IndexByte(authKey, ':')
	if separator <= 0 || separator == len(authKey)-1 {
		return "", fmt.Errorf("invalid auth key")
	}
	key, err := base64.StdEncoding.DecodeString(authKey[separator+1:])
	if err != nil {
		return "", fmt.Errorf("decode auth key: %w", err)
	}
	iat := base64.StdEncoding.EncodeToString([]byte(fmt.Sprintf("iat: %d\n", time.Now().Unix()*60))) + "."
	mac := hmac.New(sha1.New, key)
	_, _ = mac.Write([]byte(iat))
	return authKey[:separator] + ":" + iat + "." + base64.StdEncoding.EncodeToString(mac.Sum(nil)), nil
}

func randomHex(size int) (string, error) {
	raw := make([]byte, size)
	if _, err := rand.Read(raw); err != nil {
		return "", fmt.Errorf("generate device UID: %w", err)
	}
	return hex.EncodeToString(raw), nil
}

func resultString(value any, fieldID int16) string {
	if text, ok := value.(string); ok {
		return strings.TrimSpace(text)
	}
	if fields, ok := value.(map[int16]any); ok {
		return stringField(fields, fieldID)
	}
	return ""
}

func resultInteger(value any, fieldID int16) (int64, bool) {
	if fields, ok := value.(map[int16]any); ok {
		return integerField(fields, fieldID)
	}
	return 0, false
}

func anyInteger(value any) (int64, bool) {
	switch number := value.(type) {
	case int8:
		return int64(number), true
	case int16:
		return int64(number), true
	case int32:
		return int64(number), true
	case int64:
		return number, true
	default:
		return 0, false
	}
}
