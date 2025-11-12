package repo

import (
    "errors"
    "strconv"

    "golang.org/x/crypto/bcrypt"
)

type UserRecord struct {
    ID    int64
    Email string
    Role  string
    Hash  []byte
}

type UserMem struct{ byEmail map[string]UserRecord; byID map[int64]UserRecord }

func NewUserMem() *UserMem {
    mk := func(id int64, email, role, pass string) UserRecord {
        h, _ := bcrypt.GenerateFromPassword([]byte(pass), bcrypt.DefaultCost)
        return UserRecord{ID: id, Email: email, Role: role, Hash: h}
    }
    u1 := mk(1, "admin@example.com", "admin", "secret123")
    u2 := mk(2, "user@example.com", "user", "secret123")
    return &UserMem{byEmail: map[string]UserRecord{u1.Email: u1, u2.Email: u2}, byID: map[int64]UserRecord{u1.ID: u1, u2.ID: u2}}
}

var ErrNotFound = errors.New("user not found")
var ErrBadCreds = errors.New("bad credentials")

func (r *UserMem) ByEmail(email string) (UserRecord, error) {
    u, ok := r.byEmail[email]
    if !ok { return UserRecord{}, ErrNotFound }
    return u, nil
}

func (r *UserMem) ByID(id int64) (UserRecord, error) {
    u, ok := r.byID[id]
    if !ok { return UserRecord{}, ErrNotFound }
    return u, nil
}

func (r *UserMem) CheckPassword(email, pass string) (UserRecord, error) {
    u, err := r.ByEmail(email)
    if err != nil { return UserRecord{}, ErrNotFound }
    if bcrypt.CompareHashAndPassword(u.Hash, []byte(pass)) != nil {
        return UserRecord{}, ErrBadCreds
    }
    return u, nil
}

// Helper: string id -> int64
func ParseID(s string) (int64, error) { return strconv.ParseInt(s, 10, 64) }
