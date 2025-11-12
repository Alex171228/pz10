package core

import (
    "encoding/json"
    "net/http"
    "strconv"
    "time"

    "github.com/go-chi/chi/v5"

    "example.com/pz10-auth/internal/http/middleware"
)

type userRepo interface{
    CheckPassword(email, pass string) (interface{ ID int64; Email, Role string }, error)
    ByID(id int64) (interface{ ID int64; Email, Role string }, error)
}

type jwtSigner interface{
    SignAccess(userID int64, email, role string) (string, string, error)   // token, jti
    SignRefresh(userID int64, email, role string) (string, string, error)  // token, jti
}

type refreshParser interface{
    ParseRefresh(tokenStr string) (any, error)
}

type blacklist interface{
    Revoke(jti string, expUnix int64)
    IsRevoked(jti string) bool
    Sweep()
}

type Service struct{
    repo userRepo
    jwt  jwtSigner
    refP refreshParser
    bl   blacklist
}

func NewService(r userRepo, j jwtSigner, p refreshParser, bl blacklist) *Service {
    return &Service{repo: r, jwt: j, refP: p, bl: bl}
}

// --- HTTP helpers ---

func jsonOK(w http.ResponseWriter, v any){ w.Header().Set("Content-Type","application/json"); _ = json.NewEncoder(w).Encode(v) }
func httpError(w http.ResponseWriter, code int, msg string){ w.Header().Set("Content-Type","application/json"); w.WriteHeader(code); _=json.NewEncoder(w).Encode(map[string]any{"error": msg, "timestamp": time.Now().UTC()}) }

// --- Handlers ---

func (s *Service) LoginHandler(w http.ResponseWriter, r *http.Request) {
    var in struct{ Email, Password string }
    if err := json.NewDecoder(r.Body).Decode(&in); err != nil || in.Email=="" || in.Password=="" {
        httpError(w, 400, "invalid_credentials"); return
    }
    u, err := s.repo.CheckPassword(in.Email, in.Password)
    if err != nil { httpError(w, 401, "unauthorized"); return }

    access, _, err := s.jwt.SignAccess(u.ID, u.Email, u.Role)
    if err != nil { httpError(w, 500, "token_error"); return }
    refresh, _, err := s.jwt.SignRefresh(u.ID, u.Email, u.Role)
    if err != nil { httpError(w, 500, "token_error"); return }

    jsonOK(w, map[string]any{"access_token": access, "refresh_token": refresh})
}

func (s *Service) RefreshHandler(w http.ResponseWriter, r *http.Request) {
    var in struct{ Refresh string `json:"refresh"` }
    if err := json.NewDecoder(r.Body).Decode(&in); err != nil || in.Refresh=="" {
        httpError(w, 400, "invalid_refresh"); return
    }
    mc, err := s.refP.ParseRefresh(in.Refresh)
    if err != nil { httpError(w, 401, "invalid_refresh"); return }
    claims := mc.(map[string]any)

    // Check blacklist
    jti, _ := claims["jti"].(string)
    if jti == "" { httpError(w, 401, "invalid_refresh"); return }
    if s.bl.IsRevoked(jti) { httpError(w, 401, "refresh_revoked"); return }

    // Revoke current refresh (one-time use)
    expF, _ := claims["exp"].(float64)
    expUnix := int64(expF)
    s.bl.Revoke(jti, expUnix)

    // Issue new pair
    userID := int64(claims["sub"].(float64))
    email, _ := claims["email"].(string)
    role, _ := claims["role"].(string)
    access, _, err := s.jwt.SignAccess(userID, email, role)
    if err != nil { httpError(w, 500, "token_error"); return }
    refresh, _, err := s.jwt.SignRefresh(userID, email, role)
    if err != nil { httpError(w, 500, "token_error"); return }

    jsonOK(w, map[string]any{"access_token": access, "refresh_token": refresh})
}

func (s *Service) MeHandler(w http.ResponseWriter, r *http.Request) {
    claims := middleware.ClaimsFromContext(r.Context())
    jsonOK(w, map[string]any{
        "id": claims["sub"], "email": claims["email"], "role": claims["role"],
    })
}

func (s *Service) AdminStats(w http.ResponseWriter, r *http.Request) {
    jsonOK(w, map[string]any{"users": 2, "version": "1.0"})
}

func (s *Service) GetUserHandler(w http.ResponseWriter, r *http.Request) {
    idParam := chi.URLParam(r, "id")
    id, err := strconv.ParseInt(idParam, 10, 64)
    if err != nil { httpError(w, 400, "bad id"); return }
    u, err := s.repo.ByID(id)
    if err != nil { httpError(w, 404, "not_found"); return }
    jsonOK(w, User{ID: u.ID, Email: u.Email, Role: u.Role})
}
