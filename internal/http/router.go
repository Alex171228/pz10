package router

import (
    "net/http"

    "github.com/go-chi/chi/v5"

    "example.com/pz10-auth/internal/core"
    "example.com/pz10-auth/internal/http/middleware"
    "example.com/pz10-auth/internal/platform/config"
    "example.com/pz10-auth/internal/platform/jwt"
    "example.com/pz10-auth/internal/repo"
)

func Build(cfg config.Config) http.Handler {
    r := chi.NewRouter()

    // DI
    userRepo := repo.NewUserMem()
    blacklist := repo.NewBlacklist()
    jwtv := jwt.NewHS256(cfg.JWTSecret, cfg.AccessTTL, cfg.RefreshTTL)
    svc := core.NewService(userRepo, jwtv, jwtv, blacklist)

    // Public routes
    r.Post("/api/v1/login", svc.LoginHandler)
    r.Post("/api/v1/refresh", svc.RefreshHandler)

    // Private routes (access required)
    r.Group(func(priv chi.Router) {
        priv.Use(middleware.AuthN(jwtv))
        priv.Use(middleware.AuthZRoles("admin","user"))
        priv.Get("/api/v1/me", svc.MeHandler)
    })

    // Admin only
    r.Group(func(admin chi.Router) {
        admin.Use(middleware.AuthN(jwtv))
        admin.Use(middleware.AuthZRoles("admin"))
        admin.Get("/api/v1/admin/stats", svc.AdminStats)
    })

    // ABAC: self-or-admin
    r.Group(func(g chi.Router) {
        g.Use(middleware.AuthN(jwtv))
        g.Use(middleware.SelfOrAdmin())
        g.Get("/api/v1/users/{id}", svc.GetUserHandler)
    })

    return r
}
