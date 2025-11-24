package config

import (
	"log"
	"os"
	"time"

	"github.com/joho/godotenv"
)

type Config struct {
	JWTSecret  []byte
	AccessTTL  time.Duration
	RefreshTTL time.Duration
}

func Load() Config {
	// Загружаем .env, если есть
	_ = godotenv.Load()

	secret := os.Getenv("JWT_SECRET")
	if secret == "" {
		log.Fatal("JWT_SECRET is required")
	}

	accessTTL := parseDuration("JWT_ACCESS_TTL", "15m")
	refreshTTL := parseDuration("JWT_REFRESH_TTL", "168h") // 7 дней

	return Config{
		JWTSecret:  []byte(secret),
		AccessTTL:  accessTTL,
		RefreshTTL: refreshTTL,
	}
}

func parseDuration(name, def string) time.Duration {
	val := os.Getenv(name)
	if val == "" {
		val = def
	}
	d, err := time.ParseDuration(val)
	if err != nil {
		log.Fatalf("Invalid %s: %v", name, err)
	}
	return d
}
