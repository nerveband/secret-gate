package otp

import (
	"crypto/hmac"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/base32"
	"encoding/binary"
	"fmt"
	"hash"
	"net/url"
	"strconv"
	"strings"
	"time"
)

func Generate(value string, now time.Time) (string, time.Time, error) {
	secret, digits, period, algorithm := value, 6, int64(30), "SHA1"
	if strings.HasPrefix(strings.ToLower(value), "otpauth://") {
		u, err := url.Parse(value)
		if err != nil || !strings.EqualFold(u.Host, "totp") {
			return "", time.Time{}, fmt.Errorf("only TOTP otpauth URIs are supported")
		}
		secret = u.Query().Get("secret")
		if n, err := strconv.Atoi(u.Query().Get("digits")); err == nil && (n == 6 || n == 8) {
			digits = n
		}
		if n, err := strconv.ParseInt(u.Query().Get("period"), 10, 64); err == nil && n > 0 {
			period = n
		}
		if a := u.Query().Get("algorithm"); a != "" {
			algorithm = strings.ToUpper(a)
		}
	}
	secret = strings.ToUpper(strings.ReplaceAll(strings.TrimSpace(secret), " ", ""))
	key, err := base32.StdEncoding.WithPadding(base32.NoPadding).DecodeString(strings.TrimRight(secret, "="))
	if err != nil || len(key) == 0 {
		return "", time.Time{}, fmt.Errorf("invalid base32 OTP seed")
	}
	var newHash func() hash.Hash
	switch algorithm {
	case "SHA1":
		newHash = sha1.New
	case "SHA256":
		newHash = sha256.New
	case "SHA512":
		newHash = sha512.New
	default:
		return "", time.Time{}, fmt.Errorf("unsupported OTP algorithm %q", algorithm)
	}
	counter := uint64(now.Unix() / period)
	buf := make([]byte, 8)
	binary.BigEndian.PutUint64(buf, counter)
	mac := hmac.New(newHash, key)
	_, _ = mac.Write(buf)
	sum := mac.Sum(nil)
	offset := sum[len(sum)-1] & 0x0f
	number := (uint32(sum[offset])&0x7f)<<24 | uint32(sum[offset+1])<<16 | uint32(sum[offset+2])<<8 | uint32(sum[offset+3])
	mod := uint32(1)
	for i := 0; i < digits; i++ {
		mod *= 10
	}
	expires := time.Unix((now.Unix()/period+1)*period, 0)
	return fmt.Sprintf("%0*d", digits, number%mod), expires, nil
}
