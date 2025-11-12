package middleware

import (
    "net/http"
    "strconv"

    "github.com/go-chi/chi/v5"
)

// SelfOrAdmin allows if role==admin or sub == {id} from URL.
func SelfOrAdmin() func(http.Handler) http.Handler {
    return func(next http.Handler) http.Handler {
        return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
            claims := ClaimsFromContext(r.Context())
            if claims == nil { http.Error(w, "unauthorized", http.StatusUnauthorized); return }
            role, _ := claims["role"].(string)
            if role == "admin" { next.ServeHTTP(w, r); return }

            idStr := chi.URLParam(r, "id")
            want, err := strconv.ParseInt(idStr, 10, 64)
            if err != nil { http.Error(w, "bad id", http.StatusBadRequest); return }
            var sub int64
            switch v := claims["sub"].(type) {
            case float64: sub = int64(v)
            case int64:   sub = v
            }

            if sub != want { http.Error(w, "forbidden", http.StatusForbidden); return }
            next.ServeHTTP(w, r)
        })
    }
}
