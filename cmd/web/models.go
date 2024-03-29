package main

import (
	"context"
	"encoding/base64"
	"log"
	"time"

	"go.mongodb.org/mongo-driver/bson"
	"golang.org/x/crypto/bcrypt"
)

var tokensDatabase = "tokens"
var tokensCollection = "refresh_tokens_entries"

type RefreshTokenEntry struct {
	ID               string    `bson:"_id,omitempty"`
	RefreshTokenHash string    `bson:"refresh_token_hash"`
	ExpiresAt        time.Time `bson:"expires_at"`
	IsRevoked        bool      `bson:"is_revoked"`
	CreatedAt        time.Time `bson:"created_at"`
	UserGUID         string    `bson:"user_guid"`
}

func Base64Encode(str string) string {
	return base64.StdEncoding.EncodeToString([]byte(str))
}

func Base64Decode(str string) (string, error) {
	data, err := base64.StdEncoding.DecodeString(str)
	if err != nil {
		return "", err
	}
	return string(data), nil

}

func insertRefreshTokenDocument(GUID, refreshToken string, expiresAt time.Time) error {
	refreshTokenHash, _ := bcrypt.GenerateFromPassword([]byte(refreshToken), bcrypt.DefaultCost)
	entry := RefreshTokenEntry{
		RefreshTokenHash: string(refreshTokenHash),
		CreatedAt:        time.Now(),
		IsRevoked:        false,
		ExpiresAt:        expiresAt,
		UserGUID:         GUID,
	}
	collection := client.Database(tokensDatabase).Collection(tokensCollection)
	_, err := collection.InsertOne(context.TODO(), entry)

	if err != nil {
		log.Println("Error inserting refresh token data:", err)
		return err
	}

	return nil

}

func getActiveRefreshToken(GUID string) (*RefreshTokenEntry, error) {

	var token_entry RefreshTokenEntry

	collection := client.Database(tokensDatabase).Collection(tokensCollection)
	err := collection.FindOne(context.TODO(), bson.M{"user_guid": GUID, "is_revoked": false}).Decode(&token_entry)
	if err != nil {
		return nil, err
	}

	return &token_entry, nil

}

func revokeRefreshTokens(GUID string) error {
	collection := client.Database(tokensDatabase).Collection(tokensCollection)
	log.Println("revoking", GUID)
	filter := bson.D{{"user_guid", GUID}, {"is_revoked", false}}

	update := bson.D{{"$set", bson.D{
		{"is_revoked", true},
	}}}

	res, err := collection.UpdateOne(context.TODO(), filter, update)
	log.Println("revoked:", res.MatchedCount)
	if err != nil {
		log.Println(err)
		return err
	}
	return nil
}

func deleteAllRefreshToken(GUID string) error {
	collection := client.Database(tokensDatabase).Collection(tokensCollection)
	_, err := collection.DeleteMany(context.TODO(), bson.D{{"user_guid", GUID}})
	if err != nil {
		log.Println(err)
		return err
	}
	return nil
}
