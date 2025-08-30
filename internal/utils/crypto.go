package utils

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"io"
	"runtime"
	"strconv"
	"strings"

	"golang.org/x/crypto/argon2"
	"golang.org/x/crypto/bcrypt"
)

// Argon2id parameters - tuned defaults for server-side password hashing.
// Memory is expressed in KB for golang.org/x/crypto/argon2.
const (
	argonTime   = 3     // number of iterations
	argonMemory = 65536 // 64 MB (in KB)
	argonKeyLen = 32
	saltLen     = 16
)

func HashPassword(password string) (string, error) {
	if password == "" {
		return "", errors.New("password required")
	}

	// generate random salt
	salt := make([]byte, saltLen)
	if _, err := rand.Read(salt); err != nil {
		return "", err
	}

	threads := uint8(runtime.NumCPU())

	// derive key
	hash := argon2.IDKey([]byte(password), salt, uint32(argonTime), uint32(argonMemory), threads, uint32(argonKeyLen))

	b64Salt := base64.StdEncoding.EncodeToString(salt)
	b64Hash := base64.StdEncoding.EncodeToString(hash)

	encoded := strings.Join([]string{
		"$argon2id",
		"v=19",
		"m=" + strconv.Itoa(argonMemory) + ",t=" + strconv.Itoa(argonTime) + ",p=" + strconv.Itoa(int(threads)),
		b64Salt,
		b64Hash,
	}, "$")

	return encoded, nil
}

func CheckPasswordHash(password, encodedHash string) bool {
	if password == "" || encodedHash == "" {
		return false
	}

	// backward compatibility: bcrypt hashes start with $2a$ or $2b$ or $2y$
	if strings.HasPrefix(encodedHash, "$2a$") || strings.HasPrefix(encodedHash, "$2b$") || strings.HasPrefix(encodedHash, "$2y$") {
		// verify with bcrypt
		if bcrypt.CompareHashAndPassword([]byte(encodedHash), []byte(password)) == nil {
			return true
		}
		return false
	}

	parts := strings.Split(encodedHash, "$")
	// expected parts: "", "argon2id", "v=19", "m=...,t=...,p=...", "salt", "hash"
	if len(parts) != 6 || parts[1] != "argon2id" {
		return false
	}

	paramsPart := parts[3]
	saltB64 := parts[4]
	hashB64 := parts[5]

	// parse params
	var mem, t, p int
	for _, kv := range strings.Split(paramsPart, ",") {
		if strings.HasPrefix(kv, "m=") {
			mem, _ = strconv.Atoi(strings.TrimPrefix(kv, "m="))
		} else if strings.HasPrefix(kv, "t=") {
			t, _ = strconv.Atoi(strings.TrimPrefix(kv, "t="))
		} else if strings.HasPrefix(kv, "p=") {
			p, _ = strconv.Atoi(strings.TrimPrefix(kv, "p="))
		}
	}

	salt, err := base64.StdEncoding.DecodeString(saltB64)
	if err != nil {
		return false
	}

	expectedHash, err := base64.StdEncoding.DecodeString(hashB64)
	if err != nil {
		return false
	}

	computed := argon2.IDKey([]byte(password), salt, uint32(t), uint32(mem), uint8(p), uint32(len(expectedHash)))

	if subtle.ConstantTimeCompare(computed, expectedHash) == 1 {
		return true
	}

	return false
}

// Encrypt encrypts plaintext with a password-derived key using Argon2id (per-encryption salt) and AES-GCM.
// Output format (text): "v1$<salt_b64>$<nonce_b64>$<ct_b64>"
func Encrypt(plaintext, password string) (string, error) {
	if password == "" {
		return "", errors.New("password required")
	}

	// per-encryption random salt
	salt := make([]byte, saltLen)
	if _, err := io.ReadFull(rand.Reader, salt); err != nil {
		return "", err
	}

	threads := uint8(runtime.NumCPU())
	key := argon2.IDKey([]byte(password), salt, uint32(argonTime), uint32(argonMemory), threads, uint32(argonKeyLen))

	block, err := aes.NewCipher(key)
	if err != nil {
		return "", err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}

	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return "", err
	}

	ciphertext := gcm.Seal(nil, nonce, []byte(plaintext), nil)

	bSalt := base64.StdEncoding.EncodeToString(salt)
	bNonce := base64.StdEncoding.EncodeToString(nonce)
	bCT := base64.StdEncoding.EncodeToString(ciphertext)

	encoded := strings.Join([]string{"v1", bSalt, bNonce, bCT}, "$")
	return encoded, nil
}

// Decrypt reads the versioned format produced by Encrypt and attempts to decrypt using Argon2id-derived key.
func Decrypt(ciphertextStr, password string) (string, error) {
	if password == "" || ciphertextStr == "" {
		return "", errors.New("password and ciphertext required")
	}

	parts := strings.Split(ciphertextStr, "$")
	// expected: "v1" "salt" "nonce" "ct"
	if len(parts) != 4 || parts[0] != "v1" {
		return "", errors.New("unsupported ciphertext format")
	}

	salt, err := base64.StdEncoding.DecodeString(parts[1])
	if err != nil {
		return "", err
	}
	nonce, err := base64.StdEncoding.DecodeString(parts[2])
	if err != nil {
		return "", err
	}
	ct, err := base64.StdEncoding.DecodeString(parts[3])
	if err != nil {
		return "", err
	}

	threads := uint8(runtime.NumCPU())
	key := argon2.IDKey([]byte(password), salt, uint32(argonTime), uint32(argonMemory), threads, uint32(argonKeyLen))

	block, err := aes.NewCipher(key[:])
	if err != nil {
		return "", err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}

	if len(nonce) != gcm.NonceSize() {
		return "", errors.New("malformed ciphertext (nonce size mismatch)")
	}

	plaintext, err := gcm.Open(nil, nonce, ct, nil)
	if err != nil {
		return "", err
	}

	return string(plaintext), nil
}

// HashAPIKey creates a keyed HMAC-SHA256 of an API token. Store only the returned value in the database.
// The hmacKey should be a server-managed secret (pepper) kept out of the repository/DB; pass it from config.
func HashAPIKey(token, hmacKey string) (string, error) {
	if token == "" || hmacKey == "" {
		return "", errors.New("token and hmac key required")
	}
	mac := hmac.New(sha256.New, []byte(hmacKey))
	if _, err := mac.Write([]byte(token)); err != nil {
		return "", err
	}
	sum := mac.Sum(nil)
	return base64.StdEncoding.EncodeToString(sum), nil
}

// CompareAPIKey verifies a token against a stored HMAC-SHA256 (base64 encoded).
func CompareAPIKey(token, storedB64, hmacKey string) bool {
	if token == "" || storedB64 == "" || hmacKey == "" {
		return false
	}
	stored, err := base64.StdEncoding.DecodeString(storedB64)
	if err != nil {
		return false
	}
	mac := hmac.New(sha256.New, []byte(hmacKey))
	if _, err := mac.Write([]byte(token)); err != nil {
		return false
	}
	expected := mac.Sum(nil)
	return subtle.ConstantTimeCompare(stored, expected) == 1
}
