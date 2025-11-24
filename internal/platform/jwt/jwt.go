package jwt

import (
	"errors"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

type Manager struct {
	secret     []byte
	accessTTL  time.Duration
	refreshTTL time.Duration
}

func NewManager(secret []byte, accessTTL, refreshTTL time.Duration) *Manager {
	return &Manager{
		secret:     secret,
		accessTTL:  accessTTL,
		refreshTTL: refreshTTL,
	}
}

// tokenType: "access" или "refresh"
func (m *Manager) generateToken(userID int64, email, role, tokenType string, ttl time.Duration) (string, error) {
	now := time.Now()
	claims := jwt.MapClaims{
		"sub":        userID,
		"email":      email,
		"role":       role,
		"token_type": tokenType,
		"iat":        now.Unix(),
		"exp":        now.Add(ttl).Unix(),
		"iss":        "pz10-auth",
		"aud":        "pz10-clients",
	}

	t := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	return t.SignedString(m.secret)
}

func (m *Manager) GenerateAccessToken(userID int64, email, role string) (string, error) {
	return m.generateToken(userID, email, role, "access", m.accessTTL)
}

func (m *Manager) GenerateRefreshToken(userID int64, email, role string) (string, error) {
	return m.generateToken(userID, email, role, "refresh", m.refreshTTL)
}

// Parse возвращает claims как map[string]any
func (m *Manager) Parse(tokenStr string) (map[string]any, error) {
	token, err := jwt.Parse(tokenStr, func(t *jwt.Token) (any, error) {
		// проверяем алгоритм
		if t.Method.Alg() != jwt.SigningMethodHS256.Alg() {
			return nil, errors.New("invalid signing method")
		}
		return m.secret, nil
	},
		jwt.WithAudience("pz10-clients"),
		jwt.WithIssuer("pz10-auth"),
	)
	if err != nil {
		return nil, err
	}
	if !token.Valid {
		return nil, errors.New("invalid token")
	}

	claims, ok := token.Claims.(jwt.MapClaims)
	if !ok {
		return nil, errors.New("invalid claims type")
	}

	return map[string]any(claims), nil
}
