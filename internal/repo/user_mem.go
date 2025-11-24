package repo

import (
	"errors"

	"golang.org/x/crypto/bcrypt"
)

type UserRecord struct {
	ID    int64
	Email string
	Role  string
	Hash  []byte
}

type UserMem struct {
	usersByEmail map[string]UserRecord
	usersByID    map[int64]UserRecord
}

var (
	ErrNotFound = errors.New("user not found")
	ErrBadCreds = errors.New("bad credentials")
)

func NewUserMem() *UserMem {
	hash := func(p string) []byte {
		h, _ := bcrypt.GenerateFromPassword([]byte(p), bcrypt.DefaultCost)
		return h
	}

	u := &UserMem{
		usersByEmail: map[string]UserRecord{},
		usersByID:    map[int64]UserRecord{},
	}

	admin := UserRecord{ID: 1, Email: "admin@example.com", Role: "admin", Hash: hash("secret123")}
	user := UserRecord{ID: 2, Email: "user@example.com", Role: "user", Hash: hash("secret123")}

	u.usersByEmail[admin.Email] = admin
	u.usersByEmail[user.Email] = user

	u.usersByID[admin.ID] = admin
	u.usersByID[user.ID] = user

	return u
}

func (r *UserMem) CheckPassword(email, pass string) (UserRecord, error) {
	u, ok := r.usersByEmail[email]
	if !ok {
		return UserRecord{}, ErrNotFound
	}
	if bcrypt.CompareHashAndPassword(u.Hash, []byte(pass)) != nil {
		return UserRecord{}, ErrBadCreds
	}
	return u, nil
}

func (r *UserMem) GetByID(id int64) (UserRecord, error) {
	u, ok := r.usersByID[id]
	if !ok {
		return UserRecord{}, ErrNotFound
	}
	return u, nil
}
