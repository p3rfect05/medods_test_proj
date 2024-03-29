package main

import (
	"math/rand"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/bcrypt"
)

const letterBytes = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"

func randStringBytesRmndr(n int) string {
	b := make([]byte, n)
	for i := range b {
		b[i] = letterBytes[rand.Int63()%int64(len(letterBytes))]
	}
	return string(b)
}

func Test_encrypt(t *testing.T) {

	for i := 0; i < 100; i++ {
		testString := randStringBytesRmndr(64)
		enc, err := encrypt(testString)
		if err != nil {
			t.Errorf("error while encrypting %s: %s", enc, err.Error())

		}
		dec, err := decrypt(enc)

		if err != nil {
			t.Errorf("error while decrypting %s: %s", dec, err.Error())

		}
		if testString != dec {
			t.Errorf("encryption and decryption do not form original string")

		}
	}
}

func Test_decrypt(t *testing.T) {
	testString := randStringBytesRmndr(32)

	enc, err := encrypt(testString)
	if err != nil {
		t.Error("error while encrypting a string")
	}
	dec, err := decrypt(enc)
	if err != nil {
		t.Error("error while decrypting a string")
	}
	if dec != testString {
		t.Error("decrypted and original strings do not match")
	}

	_, err = decrypt("12345678912345")
	if err == nil {
		t.Error("decryption cannot be valid")
	}
}

func Test_generateRefreshToken(t *testing.T) {
	user_id := "wknkfwefieie7"
	token := ""
	for i := 0; i < 100; i++ {
		new_token, err := generateRefreshToken(user_id, time.Now().UTC().Add(refreshTokenLifetime))
		if err != nil {
			t.Errorf("error generating refresh token")

		}
		if token != "" && new_token == token {
			t.Errorf("generateRefreshToken generated the same token")
		}
		token = new_token
	}
}

func Test_generateAccessToken(t *testing.T) {
	userID := "someUserID"

	_, err := generateAccessToken(userID)
	if err != nil {
		t.Errorf("error while generating access token: %s", err)
	}
}

// checking valid, invalid and valid but expired token
func Test_validateAccessToken(t *testing.T) {
	userID := "someUserID"

	accessTokenLifetime = 5 * time.Minute

	token, err := generateAccessToken(userID)
	if err != nil {
		t.Errorf("error while generating access token: %s", err)
	}

	_, err = validateAccessToken(token)
	if err != nil {
		t.Errorf("error while validating access token: %s", err)
	}

	invalidToken := "www"
	_, err = validateAccessToken(invalidToken)
	if err == nil {
		t.Errorf("%s should be invalid token", invalidToken)
	}

	accessTokenLifetime = 500 * time.Millisecond

	expiredToken, err := generateAccessToken(userID)

	if err != nil {
		t.Errorf("error while generating access token: %s", err)
	}

	time.Sleep(1 * time.Second)

	_, err = validateAccessToken(expiredToken)
	if err == nil {
		t.Errorf("token should be expired")
	}

}

func Test_validateRefreshToken(t *testing.T) {

	tokensCollection = "test_collection"
	tokensDatabase = "test_database"

	userID := "test_user"
	refreshTokenLifetime := 500 * time.Millisecond

	err := deleteAllRefreshToken(userID)
	if err != nil {
		t.Errorf("error while cleaning test_collection: %s", err)
	}

	notExistingToken, err := generateRefreshToken(userID, time.Now().UTC().Add(refreshTokenLifetime))
	if err != nil {
		t.Errorf("error while generating refresh token: %s", err)
	}

	_, err = validateRefreshToken(notExistingToken)
	if !strings.Contains(err.Error(), "no document") {
		t.Errorf("should have gotten no documents error, got %s", err)
	}

	oldToken, err := generateRefreshToken(userID, time.Now().UTC().Add(refreshTokenLifetime))
	if err != nil {
		t.Errorf("error while generating refresh token: %s", err)
	}

	newToken, err := generateRefreshToken(userID, time.Now().UTC().Add(refreshTokenLifetime))
	if err != nil {
		t.Errorf("error while generating refresh token: %s", err)
	}

	err = insertRefreshTokenDocument(userID, oldToken, time.Now().UTC().Add(refreshTokenLifetime))
	if err != nil {
		t.Errorf("error while inserting refresh token in document: %s", err)
	}

	err = revokeRefreshTokens(userID)
	if err != nil {
		t.Errorf("error while revoking refresh token from database: %s", err)
	}

	err = insertRefreshTokenDocument(userID, newToken, time.Now().UTC().Add(refreshTokenLifetime))
	if err != nil {
		t.Errorf("error while inserting refresh token in document: %s", err)
	}

	// we inserted two tokens, oldToken is now revoked, so if we used it, both tokens
	// should be invalidated

	_, err = validateRefreshToken(oldToken)
	if err != bcrypt.ErrMismatchedHashAndPassword {
		t.Errorf("should get hash mismatch error, got %s", err)
	}

	// after mismatched hashes we should be sure that no refresh tokens are active

	_, err = getActiveRefreshToken(userID)

	if !strings.Contains(err.Error(), "no document") {
		t.Errorf("should have gotten no documents error, got %s", err)
	}

	// then we check the case when token is expired
	expiredToken, err := generateRefreshToken(userID, time.Now().UTC().Add(refreshTokenLifetime))
	if err != nil {
		t.Errorf("error while generating refresh token: %s", err)
	}
	err = insertRefreshTokenDocument(userID, expiredToken, time.Now().UTC().Add(refreshTokenLifetime))
	if err != nil {
		t.Errorf("error while inserting refresh token in document: %s", err)
	}

	time.Sleep(1 * time.Second)
	_, err = validateRefreshToken(expiredToken)

	if !strings.Contains(err.Error(), "expired") {
		t.Errorf("should have token is expired error, got %s", err)
	}

	// lastly we check valid token
	refreshTokenLifetime = 15 * time.Second
	validToken, err := generateRefreshToken(userID, time.Now().UTC().Add(refreshTokenLifetime))
	if err != nil {
		t.Errorf("error while generating refresh token: %s", err)
	}
	err = insertRefreshTokenDocument(userID, validToken, time.Now().UTC().Add(refreshTokenLifetime))
	if err != nil {
		t.Errorf("error while inserting refresh token in document: %s", err)
	}

	_, err = validateRefreshToken(validToken)

	if err != nil {
		t.Errorf("token should be valid but got error %s", err)
	}

}
