package repo

import (
    "sync"
    "time"
)

type Blacklist struct {
    mu   sync.RWMutex
    data map[string]int64 // jti -> expUnix
}

func NewBlacklist() *Blacklist { return &Blacklist{data: make(map[string]int64)} }

// Revoke marks refresh jti as revoked until exp.
func (b *Blacklist) Revoke(jti string, expUnix int64) {
    b.mu.Lock(); defer b.mu.Unlock()
    b.data[jti] = expUnix
}

func (b *Blacklist) IsRevoked(jti string) bool {
    b.mu.RLock(); defer b.mu.RUnlock()
    exp, ok := b.data[jti]
    if !ok { return false }
    return time.Now().Unix() <= exp
}

// Sweep deletes expired revocations.
func (b *Blacklist) Sweep() {
    now := time.Now().Unix()
    b.mu.Lock(); defer b.mu.Unlock()
    for jti, exp := range b.data {
        if exp < now {
            delete(b.data, jti)
        }
    }
}
