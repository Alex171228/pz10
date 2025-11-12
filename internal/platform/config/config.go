package config

import (
    "log"
    "os"
    "time"
)

type Config struct {
    Port         string
    JWTSecret    []byte
    AccessTTL    time.Duration
    RefreshTTL   time.Duration
}

func Load() Config {
	// load .env if present (ignore error if file not found)
	_ = godotenv.Load()

    port := os.Getenv("APP_PORT")
    if port == "" { port = "8081" }

    secret := os.Getenv("JWT_SECRET")
    if secret == "" {
        log.Fatal("JWT_SECRET is required")
    }

    access := os.Getenv("JWT_ACCESS_TTL")
    if access == "" { access = "15m" }
    accessDur, err := time.ParseDuration(access)
    if err != nil { log.Fatal("bad JWT_ACCESS_TTL") }

    refresh := os.Getenv("JWT_REFRESH_TTL")
    if refresh == "" { refresh = "168h" } // 7 days
    refreshDur, err := time.ParseDuration(refresh)
    if err != nil { log.Fatal("bad JWT_REFRESH_TTL") }

    return Config{
        Port: ":" + port,
        JWTSecret: []byte(secret),
        AccessTTL: accessDur,
        RefreshTTL: refreshDur,
    }
}
