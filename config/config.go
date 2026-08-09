package config

import "time"

type Config struct {
	Host        string
	Application string
	UserAgent   string
	Language    string
	Timeout     time.Duration
	SessionPath string
	Debug       bool
}

func FromEnv() Config {
	return Config{
		Host:        env("LINEGO_API_HOST", DefaultHost),
		Application: env("LINEGO_APPLICATION", DefaultApplication),
		UserAgent:   env("LINE_USER_AGENT", DefaultUserAgent),
		Language:    env("LINEGO_LANGUAGE", "en_US"),
		Timeout:     durationEnv("LINEGO_API_TIMEOUT", 120*time.Second),
		SessionPath: defaultSessionPath(),
		Debug:       boolEnv("LINEGO_DEBUG", false),
	}
}
