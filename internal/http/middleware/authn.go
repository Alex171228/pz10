package middleware

import (
    "context"
    "net/http"
    "strings"
)

type ctxKey string

const claimsKey ctxKey = "claims"

type Claims map[string]any

func ClaimsFromContext(ctx context.Context) Claims {
    if v := ctx.Value(claimsKey); v != nil {
        if c, ok := v.(Claims); ok { return c }
    }
    return nil
}

func AuthN(v interface{ ParseAccess(string) (any, error) }) func(http.Handler) http.Handler {
    return func(next http.Handler) http.Handler {
        return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
            h := r.Header.Get("Authorization")
            if h == "" || !strings.HasPrefix(h, "Bearer ") {
                http.Error(w, "unauthorized", http.StatusUnauthorized); return
            }
            raw := strings.TrimPrefix(h, "Bearer ")
            mc, err := v.ParseAccess(raw)
            if err != nil {
                http.Error(w, "unauthorized", http.StatusUnauthorized); return
            }
            claims := Claims(mc.(map[string]any))
            ctx := context.WithValue(r.Context(), claimsKey, claims)
            next.ServeHTTP(w, r.WithContext(ctx))
        })
    }
}
