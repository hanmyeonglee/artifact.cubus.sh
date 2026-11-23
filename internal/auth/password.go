package auth

import (
	"context"
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"fmt"
	"strconv"
	"strings"

	"golang.org/x/crypto/argon2"
)

const (
	MinPasswordBytes      = 12
	MaxPasswordBytes      = 128
	argonMemoryKiB        = 65536 // 64 MiB
	argonIterations       = 3
	argonParallelism      = 1
	argonSaltBytes        = 16
	argonKeyBytes         = 32
	defaultHashConcurrent = 4
)

var (
	ErrPasswordTooShort = fmt.Errorf("password must be at least %d bytes", MinPasswordBytes)
	ErrPasswordTooLong  = fmt.Errorf("password must be at most %d bytes", MaxPasswordBytes)
	ErrHasherBusy       = errors.New("password verification temporarily saturated")
)

type PasswordHasher struct {
	sem       chan struct{}
	dummyHash string
}

func NewPasswordHasher(maxConcurrent int) *PasswordHasher {
	if maxConcurrent < 1 {
		maxConcurrent = defaultHashConcurrent
	}
	h := &PasswordHasher{
		sem: make(chan struct{}, maxConcurrent),
	}
	dummy, err := hashArgon2idRaw("dummy-timing-equalization-secret")
	if err != nil {
		panic("failed to precompute dummy argon2id hash: " + err.Error())
	}
	h.dummyHash = dummy
	return h
}

func (h *PasswordHasher) Hash(ctx context.Context, password string) (string, error) {
	if len(password) < MinPasswordBytes {
		return "", ErrPasswordTooShort
	}
	if len(password) > MaxPasswordBytes {
		return "", ErrPasswordTooLong
	}
	if err := h.acquire(ctx); err != nil {
		return "", err
	}
	defer h.release()
	return hashArgon2idRaw(password)
}

func (h *PasswordHasher) Verify(ctx context.Context, password, encodedHash string) (bool, error) {
	if len(password) == 0 || len(password) > MaxPasswordBytes {
		return false, nil
	}
	if err := h.acquire(ctx); err != nil {
		return false, err
	}
	defer h.release()
	return verifyArgon2idRaw(password, encodedHash)
}

// VerifyDummy runs identical Argon2id work for unknown/inactive users to prevent username timing oracles.
func (h *PasswordHasher) VerifyDummy(ctx context.Context, password string) error {
	if len(password) == 0 || len(password) > MaxPasswordBytes {
		return nil
	}
	if err := h.acquire(ctx); err != nil {
		return err
	}
	defer h.release()
	_, _ = verifyArgon2idRaw(password, h.dummyHash)
	return nil
}

func (h *PasswordHasher) acquire(ctx context.Context) error {
	select {
	case h.sem <- struct{}{}:
		return nil
	default:
	}
	select {
	case h.sem <- struct{}{}:
		return nil
	case <-ctx.Done():
		return ErrHasherBusy
	}
}

func (h *PasswordHasher) release() {
	<-h.sem
}

func hashArgon2idRaw(password string) (string, error) {
	salt := make([]byte, argonSaltBytes)
	if _, err := rand.Read(salt); err != nil {
		return "", err
	}
	key := argon2.IDKey([]byte(password), salt, argonIterations, argonMemoryKiB, argonParallelism, argonKeyBytes)
	return fmt.Sprintf("$argon2id$v=%d$m=%d,t=%d,p=%d$%s$%s",
		argon2.Version,
		argonMemoryKiB,
		argonIterations,
		argonParallelism,
		base64.RawStdEncoding.EncodeToString(salt),
		base64.RawStdEncoding.EncodeToString(key),
	), nil
}

func verifyArgon2idRaw(password, encoded string) (bool, error) {
	parts := strings.Split(encoded, "$")
	if len(parts) != 6 || parts[0] != "" || parts[1] != "argon2id" {
		return false, errors.New("unsupported password hash format")
	}
	var version int
	if _, err := fmt.Sscanf(parts[2], "v=%d", &version); err != nil || version != argon2.Version {
		return false, errors.New("unsupported argon2id version")
	}

	var memory uint32
	var iterations uint32
	var parallelism uint8
	for _, kv := range strings.Split(parts[3], ",") {
		k, v, ok := strings.Cut(kv, "=")
		if !ok {
			return false, errors.New("malformed argon2id params")
		}
		n, err := strconv.ParseUint(v, 10, 32)
		if err != nil {
			return false, errors.New("invalid argon2id param number")
		}
		switch k {
		case "m":
			memory = uint32(n)
		case "t":
			iterations = uint32(n)
		case "p":
			if n > 255 {
				return false, errors.New("invalid argon2id parallelism")
			}
			parallelism = uint8(n)
		}
	}
	if memory == 0 || iterations == 0 || parallelism == 0 {
		return false, errors.New("incomplete argon2id params")
	}

	salt, err := base64.RawStdEncoding.DecodeString(parts[4])
	if err != nil {
		return false, err
	}
	expected, err := base64.RawStdEncoding.DecodeString(parts[5])
	if err != nil || len(expected) == 0 {
		return false, errors.New("invalid argon2id hash bytes")
	}

	computed := argon2.IDKey([]byte(password), salt, iterations, memory, parallelism, uint32(len(expected)))
	return subtle.ConstantTimeCompare(computed, expected) == 1, nil
}
