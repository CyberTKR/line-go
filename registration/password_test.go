package registration

import "testing"

func TestValidateRegistrationPassword(t *testing.T) {
	tests := []struct {
		name     string
		password string
		valid    bool
	}{
		{name: "all categories", password: "Secure1!", valid: true},
		{name: "three categories", password: "Secure123", valid: true},
		{name: "too short", password: "Ab1!", valid: false},
		{name: "two categories", password: "abcdefgh1", valid: false},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			err := validateRegistrationPassword(test.password)
			if test.valid && err != nil {
				t.Fatalf("expected valid password: %v", err)
			}
			if !test.valid && err == nil {
				t.Fatal("expected password validation error")
			}
		})
	}
}
