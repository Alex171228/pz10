package jwt

import (
    "errors"
    "time"

    "github.com/golang-jwt/jwt/v5"
    "github.com/google/uuid"
)

type Validator interface {
    SignAccess(userID int64, email, role string) (string, string, error)   // token, jti
    SignRefresh(userID int64, email, role string) (string, string, error)  // token, jti
    ParseAccess(tokenStr string) (jwt.MapClaims, error)
    ParseRefresh(tokenStr string) (jwt.MapClaims, error)
}

type HS256 struct {
    secret     []byte
    accessTTL  time.Duration
    refreshTTL time.Duration
}

func NewHS256(secret []byte, accessTTL, refreshTTL time.Duration) *HS256 {
    return &HS256{secret: secret, accessTTL: accessTTL, refreshTTL: refreshTTL}
}

func (h *HS256) baseClaims(userID int64, email, role, typ string, ttl time.Duration) jwt.MapClaims {
    now := time.Now()
    return jwt.MapClaims{
        "sub":   userID,
        "email": email,
        "role":  role,
        "iat":   now.Unix(),
        "exp":   now.Add(ttl).Unix(),
        "iss":   "pz10-auth",
        "aud":   "pz10-clients",
        "typ":   typ,
        "jti":   uuid.NewString(),
    }
}

func (h *HS256) sign(claims jwt.MapClaims) (string, string, error) {
    t := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
    tok, err := t.SignedString(h.secret)
    if err != nil { return "", "", err }
    jti, _ := claims["jti"].(string)
    return tok, jti, nil
}

func (h *HS256) SignAccess(userID int64, email, role string) (string, string, error) {
    claims := h.baseClaims(userID, email, role, "access", h.accessTTL)
    return h.sign(claims)
}

func (h *HS256) SignRefresh(userID int64, email, role string) (string, string, error) {
    claims := h.baseClaims(userID, email, role, "refresh", h.refreshTTL)
    return h.sign(claims)
}

func parseWithChecks(tokenStr string, secret []byte, expectedTyp string) (jwt.MapClaims, error) {
    t, err := jwt.Parse(tokenStr, func(t *jwt.Token) (any, error) { return secret, nil },
        jwt.WithValidMethods([]string{"HS256"}),
        jwt.WithAudience("pz10-clients"),
        jwt.WithIssuer("pz10-auth"),
    )
    if err != nil || !t.Valid { return nil, err }
    claims, ok := t.Claims.(jwt.MapClaims)
    if !ok { return nil, errors.New("bad claims") }
    if typ, _ := claims["typ"].(string); typ != expectedTyp {
        return nil, errors.New("wrong token type")
    }
    return claims, nil
}

func (h *HS256) ParseAccess(tokenStr string) (jwt.MapClaims, error)  { return parseWithChecks(tokenStr, h.secret, "access") }
func (h *HS256) ParseRefresh(tokenStr string) (jwt.MapClaims, error) { return parseWithChecks(tokenStr, h.secret, "refresh") }
