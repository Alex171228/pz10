package middleware

import (
	"context"
	"net/http"
	"strings"

	jwtmanager "pz10/internal/platform/jwt"
)

type ctxKey int

const ctxClaimsKey ctxKey = iota

// AuthN — проверяет JWT из Authorization: Bearer <token>
// и кладёт claims в контекст.
func AuthN(m *jwtmanager.Manager) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			h := r.Header.Get("Authorization")
			if h == "" || !strings.HasPrefix(h, "Bearer ") {
				http.Error(w, "unauthorized", http.StatusUnauthorized)
				return
			}

			raw := strings.TrimPrefix(h, "Bearer ")
			claims, err := m.Parse(raw)
			if err != nil {
				http.Error(w, "unauthorized", http.StatusUnauthorized)
				return
			}

			// Разрешаем только access-токен в этом middleware
			if t, ok := claims["token_type"].(string); !ok || t != "access" {
				http.Error(w, "unauthorized", http.StatusUnauthorized)
				return
			}

			ctx := context.WithValue(r.Context(), ctxClaimsKey, claims)
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}

// GetClaims — вытащить claims из контекста в хендлерах.
func GetClaims(r *http.Request) map[string]any {
	claims, _ := r.Context().Value(ctxClaimsKey).(map[string]any)
	return claims
}
