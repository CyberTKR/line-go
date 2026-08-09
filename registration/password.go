package registration

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"strconv"
	"unicode"
	"unicode/utf8"

	"golang.org/x/crypto/scrypt"
)

const maxScryptMemory = 512 * 1024 * 1024

type passwordParameters struct {
	HMACKey string
	Salt    string
	NRP     string
	DKLen   int
}

func validateRegistrationPassword(password string) error {
	if utf8.RuneCountInString(password) < 8 {
		return fmt.Errorf("LINEGO_REGISTER_PASSWORD must contain at least 8 characters")
	}
	categories := 0
	hasUpper := false
	hasLower := false
	hasDigit := false
	hasSymbol := false
	for _, character := range password {
		switch {
		case unicode.IsUpper(character):
			hasUpper = true
		case unicode.IsLower(character):
			hasLower = true
		case unicode.IsDigit(character):
			hasDigit = true
		case unicode.IsPunct(character) || unicode.IsSymbol(character):
			hasSymbol = true
		}
	}
	for _, present := range []bool{hasUpper, hasLower, hasDigit, hasSymbol} {
		if present {
			categories++
		}
	}
	if categories < 3 {
		return fmt.Errorf("LINEGO_REGISTER_PASSWORD must include at least 3 of these categories: uppercase letter, lowercase letter, number, symbol")
	}
	return nil
}

func derivePassword(password string, parameters passwordParameters) (string, error) {
	if password == "" {
		return "", fmt.Errorf("registration password is empty")
	}
	packed, err := strconv.ParseUint(parameters.NRP, 16, 24)
	if err != nil {
		return "", fmt.Errorf("invalid scrypt nrp: %w", err)
	}
	logN := int((packed >> 16) & 0xffff)
	r := int((packed >> 8) & 0xff)
	p := int(packed & 0xff)
	if logN < 1 || logN > 15 || r < 1 || p < 1 || parameters.DKLen < 1 {
		return "", fmt.Errorf("unsafe scrypt parameters")
	}
	N := 1 << logN
	requiredMemory := int64(128)*int64(N)*int64(r) + int64(128)*int64(r)*int64(p) + 1024*1024
	if requiredMemory > maxScryptMemory {
		return "", fmt.Errorf("server scrypt parameters exceed 512 MiB safety limit")
	}
	hmacKey, err := base64.StdEncoding.DecodeString(parameters.HMACKey)
	if err != nil {
		return "", fmt.Errorf("decode password HMAC key: %w", err)
	}
	salt, err := base64.StdEncoding.DecodeString(parameters.Salt)
	if err != nil {
		return "", fmt.Errorf("decode password salt: %w", err)
	}
	mac := hmac.New(sha256.New, hmacKey)
	_, _ = mac.Write([]byte(password))
	derived, err := scrypt.Key(mac.Sum(nil), salt, N, r, p, parameters.DKLen)
	if err != nil {
		return "", fmt.Errorf("derive registration password: %w", err)
	}
	return "$s0$" + parameters.NRP + "$" + parameters.Salt + "$" + base64.StdEncoding.EncodeToString(derived), nil
}
