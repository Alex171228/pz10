package core

import (
	"encoding/json"
	"net/http"
	"strconv"
	"sync"
	"time"

	"github.com/go-chi/chi/v5"

	"pz10/internal/http/middleware"
	"pz10/internal/repo"
)

type userRepo interface {
	CheckPassword(email, pass string) (repo.UserRecord, error)
	GetByID(id int64) (repo.UserRecord, error)
}

type jwtMgr interface {
	GenerateAccessToken(userID int64, email, role string) (string, error)
	GenerateRefreshToken(userID int64, email, role string) (string, error)
	Parse(token string) (map[string]any, error)
}

type Service struct {
	repo userRepo
	jwt  jwtMgr

	mu               sync.Mutex
	refreshBlacklist map[string]int64 // refreshToken -> exp (unix)
}

func NewService(r userRepo, j jwtMgr) *Service {
	return &Service{
		repo:             r,
		jwt:              j,
		refreshBlacklist: make(map[string]int64),
	}
}

// LoginHandler: email+password -> access+refresh
func (s *Service) LoginHandler(w http.ResponseWriter, r *http.Request) {
	var in struct {
		Email    string `json:"email"`
		Password string `json:"password"`
	}

	if err := json.NewDecoder(r.Body).Decode(&in); err != nil || in.Email == "" || in.Password == "" {
		httpError(w, http.StatusBadRequest, "invalid_credentials")
		return
	}

	u, err := s.repo.CheckPassword(in.Email, in.Password)
	if err != nil {
		httpError(w, http.StatusUnauthorized, "invalid_credentials")
		return
	}

	access, err := s.jwt.GenerateAccessToken(u.ID, u.Email, u.Role)
	if err != nil {
		httpError(w, http.StatusInternalServerError, "token_error")
		return
	}

	refresh, err := s.jwt.GenerateRefreshToken(u.ID, u.Email, u.Role)
	if err != nil {
		httpError(w, http.StatusInternalServerError, "token_error")
		return
	}

	jsonOK(w, map[string]any{
		"access":  access,
		"refresh": refresh,
	})
}

// RefreshHandler: принимает refresh -> проверяет -> выдаёт новую пару
func (s *Service) RefreshHandler(w http.ResponseWriter, r *http.Request) {
	var in struct {
		Refresh string `json:"refresh"`
	}

	if err := json.NewDecoder(r.Body).Decode(&in); err != nil || in.Refresh == "" {
		httpError(w, http.StatusBadRequest, "invalid_refresh")
		return
	}

	claims, err := s.jwt.Parse(in.Refresh)
	if err != nil {
		httpError(w, http.StatusUnauthorized, "invalid_refresh")
		return
	}

	// Проверка типа токена
	if t, ok := claims["token_type"].(string); !ok || t != "refresh" {
		httpError(w, http.StatusUnauthorized, "invalid_refresh")
		return
	}

	// Проверка blacklist
	s.mu.Lock()
	expBlack, blacklisted := s.refreshBlacklist[in.Refresh]
	if blacklisted {
		if expBlack > time.Now().Unix() {
			s.mu.Unlock()
			httpError(w, http.StatusUnauthorized, "refresh_revoked")
			return
		}
		// exp уже прошёл — можно удалить
		delete(s.refreshBlacklist, in.Refresh)
	}
	s.mu.Unlock()

	// Берём данные пользователя из клеймов
	sub, _ := claims["sub"].(float64) // jwt числа как float64
	email, _ := claims["email"].(string)
	role, _ := claims["role"].(string)
	expAny, _ := claims["exp"].(float64)

	userID := int64(sub)

	// Генерим новую пару
	access, err := s.jwt.GenerateAccessToken(userID, email, role)
	if err != nil {
		httpError(w, http.StatusInternalServerError, "token_error")
		return
	}

	newRefresh, err := s.jwt.GenerateRefreshToken(userID, email, role)
	if err != nil {
		httpError(w, http.StatusInternalServerError, "token_error")
		return
	}

	// Старый refresh добавляем в blacklist до времени его exp
	s.mu.Lock()
	s.refreshBlacklist[in.Refresh] = int64(expAny)
	s.mu.Unlock()

	jsonOK(w, map[string]any{
		"access":  access,
		"refresh": newRefresh,
	})
}

// MeHandler: читает клеймы из контекста
func (s *Service) MeHandler(w http.ResponseWriter, r *http.Request) {
	claims := middleware.GetClaims(r)
	jsonOK(w, map[string]any{
		"id":    claims["sub"],
		"email": claims["email"],
		"role":  claims["role"],
	})
}

// AdminStats: только для админов
func (s *Service) AdminStats(w http.ResponseWriter, r *http.Request) {
	jsonOK(w, map[string]any{
		"users":   2,
		"version": "1.0",
	})
}

// UserByIDHandler: ABAC — user может только свой id; admin — любой
func (s *Service) UserByIDHandler(w http.ResponseWriter, r *http.Request) {
	claims := middleware.GetClaims(r)
	role, _ := claims["role"].(string)
	sub, _ := claims["sub"].(float64)
	userIDFromToken := int64(sub)

	idStr := chi.URLParam(r, "id")
	id, err := strconv.ParseInt(idStr, 10, 64)
	if err != nil {
		httpError(w, http.StatusBadRequest, "bad_id")
		return
	}

	// ABAC-правило:
	// - роль user -> только свой id
	// - роль admin -> может любой
	if role == "user" && id != userIDFromToken {
		httpError(w, http.StatusForbidden, "forbidden")
		return
	}

	u, err := s.repo.GetByID(id)
	if err != nil {
		httpError(w, http.StatusNotFound, "not_found")
		return
	}

	jsonOK(w, User{
		ID:    u.ID,
		Email: u.Email,
		Role:  u.Role,
	})
}

// --- helpers ---

func jsonOK(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(v)
}

func httpError(w http.ResponseWriter, code int, msg string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(map[string]string{"error": msg})
}
