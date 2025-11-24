package router

import (
	"net/http"

	"github.com/go-chi/chi/v5"

	"pz10/internal/core"
	"pz10/internal/http/middleware"
	"pz10/internal/platform/config"
	jwtmanager "pz10/internal/platform/jwt"
	"pz10/internal/repo"
)

func Build(cfg config.Config) http.Handler {
	r := chi.NewRouter()

	// DI
	userRepo := repo.NewUserMem()
	jwtMgr := jwtmanager.NewManager(cfg.JWTSecret, cfg.AccessTTL, cfg.RefreshTTL)
	svc := core.NewService(userRepo, jwtMgr)

	// Публичные маршруты
	r.Post("/api/v1/login", svc.LoginHandler)
	r.Post("/api/v1/refresh", svc.RefreshHandler)

	// Защищённые маршруты (admin + user)
	r.Group(func(priv chi.Router) {
		priv.Use(middleware.AuthN(jwtMgr))
		priv.Use(middleware.AuthZRoles("admin", "user"))

		priv.Get("/api/v1/me", svc.MeHandler)
		priv.Get("/api/v1/users/{id}", svc.UserByIDHandler) // ABAC внутри хендлера
	})

	// Только admin
	r.Group(func(admin chi.Router) {
		admin.Use(middleware.AuthN(jwtMgr))
		admin.Use(middleware.AuthZRoles("admin"))

		admin.Get("/api/v1/admin/stats", svc.AdminStats)
	})

	return r
}
