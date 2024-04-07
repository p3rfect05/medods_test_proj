package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"errors"
	"strconv"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"golang.org/x/crypto/bcrypt"
)

var accessTokenLifetime = 5 * time.Minute
var refreshTokenLifetime = 24 * time.Hour

// TODO: move to environment
var key string

const (
	Success           = 0
	ErrorOther        = 1
	ErrorTokenExpired = 2
)

func generateAccessToken(userID string) (string, error) {
	t := jwt.NewWithClaims(jwt.SigningMethodHS512, jwt.MapClaims{
		"sub": userID,
		"exp": time.Now().UTC().Add(accessTokenLifetime).Unix(),
	})

	s, err := t.SignedString([]byte(key))
	if err != nil {
		return "", err
	}

	return s, nil
}

// func generateRefreshToken(user_id string) (string, error) {
// 	t := jwt.NewWithClaims(jwt.SigningMethodHS512, jwt.MapClaims{
// 		"sub": user_id,
// 		"exp": time.Now().UTC().Add(refreshTokenLifetime).Unix(),
// 	})

//		s, err := t.SignedString([]byte(key))
//		if err != nil {
//			return "", err
//		}
//		return s, nil
//	}

// generateRefreshToken generates token with format: <user_id>____<unix-time>
func generateRefreshToken(user_id string, expiresAt time.Time) (string, error) {
	toEncode := user_id + "____" + strconv.FormatInt(expiresAt.Unix(), 10)
	encrypted, err := encrypt(toEncode)
	if err != nil {
		return "", err
	}
	return Base64Encode(encrypted), nil

}
func validateAccessToken(tokenString string) (bool, error) {
	claims := jwt.MapClaims{}
	_, err := jwt.ParseWithClaims(tokenString, claims, func(token *jwt.Token) (interface{}, error) {
		return []byte(key), nil
	})
	if err != nil {
		return false, err
	}

	return true, nil

}

func validateRefreshToken(refreshTokenEncoded string) (string, error) {
	// three possible scenarios
	// since there is at most 1 active refresh token
	// then 1) we get token and hashes match, we just reissue a new pair
	// 2) no active refresh tokens at all: it means we never issued the pair, since
	// even in case refresh token expired it is still active, as expiration check is lazy
	// in other case last check of expiration invalidated the refresh token
	// 3) we get active refresh token but hashes differ,
	// it means someone hijacked the refresh token, so we invalidate every refresh token (at most 1)
	// for current user
	token, err := Base64Decode(refreshTokenEncoded)

	if err != nil {
		return "", err
	}

	decodedToken, err := decrypt(token)
	if err != nil {
		return "", err
	}

	tokenData := strings.Split(decodedToken, "____")
	userGUID := tokenData[0]

	tokenEntry, err := getActiveRefreshToken(userGUID)

	// 2) err != nil when we got no active refresh tokens, it means we never issued them
	// or all of them are expired
	if err != nil {
		return "", err
	}
	// we compare encoded refresh token and hash from the table;
	err = bcrypt.CompareHashAndPassword([]byte(tokenEntry.RefreshTokenHash), []byte(refreshTokenEncoded))

	// 3), it means we need to revoke all of the active tokens
	if err == bcrypt.ErrMismatchedHashAndPassword {
		revokeRefreshTokens(userGUID)
		deleteAllRefreshToken(userGUID)
		return "", err
	} else if err != nil {
		return "", err
	}

	// 1) lastly we check if the refresh token if not expired
	if tokenEntry.ExpiresAt.Unix() <= time.Now().UTC().Unix() {
		revokeRefreshTokens(userGUID)
		return "", errors.New("token is expired")
	}

	// lastly if hashes match and refresh token did not expire
	return userGUID, nil
}

func encrypt(plaintext string) (string, error) {
	blockCipher, err := aes.NewCipher([]byte(key))
	if err != nil {
		return "", err
	}

	gcm, err := cipher.NewGCM(blockCipher)
	if err != nil {
		return "", err
	}

	nonce := make([]byte, gcm.NonceSize())
	if _, err = rand.Read(nonce); err != nil {
		return "", err
	}

	ciphertext := gcm.Seal(nonce, nonce, []byte(plaintext), nil)

	return string(ciphertext), nil
}

// decrypt from base64 to decrypted string
func decrypt(cryptoText string) (string, error) {
	blockCipher, err := aes.NewCipher([]byte(key))
	if err != nil {
		return "", err
	}

	gcm, err := cipher.NewGCM(blockCipher)
	if err != nil {
		return "", err
	}
	data := []byte(cryptoText)
	nonce, ciphertext := data[:gcm.NonceSize()], data[gcm.NonceSize():]

	plaintext, err := gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return "", err
	}

	return string(plaintext), nil
}
