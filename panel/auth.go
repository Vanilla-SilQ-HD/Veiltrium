package main

import (
	"crypto/pbkdf2"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"fmt"
	"os"
	"strconv"
	"strings"
)

// Password hashes: "pbkdf2-sha256$<iterations>$<salt b64>$<key b64>" (PBKDF2, RFC 8018).
const (
	hashScheme     = "pbkdf2-sha256"
	hashIterations = 600000
	hashKeyLen     = 32
)

// HashPassword returns a new salted hash line for the password.
func HashPassword(password string) (string, error) {
	if len(password) < 12 || len(password) > 256 {
		return "", errors.New("the password must be 12 to 256 characters")
	}
	salt := make([]byte, 16)
	if _, err := rand.Read(salt); err != nil {
		return "", err
	}
	key, err := pbkdf2.Key(sha256.New, password, salt, hashIterations, hashKeyLen)
	if err != nil {
		return "", err
	}
	enc := base64.RawStdEncoding
	return fmt.Sprintf("%s$%d$%s$%s", hashScheme, hashIterations, enc.EncodeToString(salt), enc.EncodeToString(key)), nil
}

// VerifyPassword checks the password against a hash line in constant time.
func VerifyPassword(line, password string) bool {
	parts := strings.Split(strings.TrimSpace(line), "$")
	if len(parts) != 4 || parts[0] != hashScheme {
		return false
	}
	iter, err := strconv.Atoi(parts[1])
	if err != nil || iter < 100000 || iter > 10000000 {
		return false
	}
	enc := base64.RawStdEncoding
	salt, err1 := enc.DecodeString(parts[2])
	want, err2 := enc.DecodeString(parts[3])
	if err1 != nil || err2 != nil || len(salt) < 16 || len(want) != hashKeyLen {
		return false
	}
	got, err := pbkdf2.Key(sha256.New, password, salt, iter, hashKeyLen)
	if err != nil {
		return false
	}
	return subtle.ConstantTimeCompare(got, want) == 1
}

// readHash reads the hash line from the auth file on every login, so a new password
// (veiltrium.sh --panel-password) takes effect without a restart.
func readHash(path string) (string, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return "", err
	}
	line := strings.TrimSpace(string(b))
	if !strings.HasPrefix(line, hashScheme+"$") {
		return "", errors.New("the auth file holds no password hash")
	}
	return line, nil
}
