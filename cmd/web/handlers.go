package main

import (
	"encoding/json"
	"errors"
	"log"
	"net/http"
	"time"
)

type errorJson struct {
	ErrorMessage string `json:"error_message"`
}


// returnErrorJson returns json containing the message error
func returnErrorJson(w http.ResponseWriter, err error) {
	error_json, err := json.MarshalIndent(errorJson{
		ErrorMessage: err.Error(),
	}, "", "\t")
	if err != nil {
		log.Println(err)
		return
	}
	w.Write(error_json)

}

// PostGetTokenPair returns pair of access and refresh tokens
func PostGetTokenPair(w http.ResponseWriter, r *http.Request) {
	type jsonRequest struct {
		GUID string `json:"guid"`
	}
	type jsonResponse struct {
		AccessToken  string `json:"access_token"`
		RefreshToken string `json:"refresh_token"`
	}
	w.Header().Set("Content-Type", "application/json")
	var json_req jsonRequest
	err := json.NewDecoder(r.Body).Decode(&json_req)

	if err != nil {
		log.Println(err)
		returnErrorJson(w, err)
		return
	}
	GUID := json_req.GUID
	accessToken, err := generateAccessToken(GUID)
	if err != nil {
		returnErrorJson(w, err)
		return
	}
	refreshTokenExpirationTime := time.Now().UTC().Add(refreshTokenLifetime)
	refreshToken, err := generateRefreshToken(GUID, refreshTokenExpirationTime)
	if err != nil {
		log.Println(err)
		returnErrorJson(w, err)
		return
	}

	resp := jsonResponse{
		AccessToken:  accessToken,
		RefreshToken: refreshToken,
	}

	resp_json, err := json.MarshalIndent(resp, "", "\t")
	if err != nil {
		returnErrorJson(w, err)
		return
	}

	// before insert we should invalidate the other active refresh token (if it exists)
	err = revokeRefreshTokens(GUID)
	if err != nil {
		returnErrorJson(w, err)
		return
	}

	err = insertRefreshTokenDocument(GUID, refreshToken, refreshTokenExpirationTime)

	if err != nil {
		returnErrorJson(w, err)
		return

	} else {
		log.Println("refresh token was successfully inserted into db")
	}
	w.Write(resp_json)
}


// PostValidateToken checks access token for validity
func PostValidateToken(w http.ResponseWriter, r *http.Request) {
	type jsonRequest struct {
		AccessToken string `json:"access_token"`
	}
	var json_req jsonRequest
	err := json.NewDecoder(r.Body).Decode(&json_req)

	if err != nil {
		log.Println(err)
		returnErrorJson(w, err)
		return
	}
	if ok, err := validateAccessToken(json_req.AccessToken); !ok {
		log.Println(err)
		returnErrorJson(w, err)
		return
	}
	log.Println("Validation is successful")

	type jsonResponse struct {
		Message string `json:"message"`
	}
	resp := jsonResponse{
		Message: "Validation is successful",
	}

	resp_json, err := json.MarshalIndent(resp, "", "\t")
	if err != nil {
		returnErrorJson(w, err)
		return
	}
	w.Write(resp_json)
}


// PostRefreshTokens invalidates old refresh tokens, and give new one
func PostRefreshTokens(w http.ResponseWriter, r *http.Request) {
	type jsonRequest struct {
		RefreshToken string `json:"refresh_token"`
	}

	var json_req jsonRequest
	err := json.NewDecoder(r.Body).Decode(&json_req)
	if err != nil {
		log.Println(err)
		returnErrorJson(w, err)
		return
	}

	userGUID, err := validateRefreshToken(json_req.RefreshToken)
	if err != nil {
		log.Println(err)
		returnErrorJson(w, err)
		return
	}
	if userGUID == "" {
		returnErrorJson(w, errors.New("expired refresh token"))
		return
	}

	// we passed the check so we reissue tokens
	refreshTokenExpirationTime := time.Now().UTC().Add(refreshTokenLifetime)
	refreshToken, err := generateRefreshToken(userGUID, refreshTokenExpirationTime)
	if err != nil {
		log.Println(err)
		returnErrorJson(w, err)
		return
	}
	accessToken, err := generateAccessToken(userGUID)

	if err != nil {
		log.Println(err)
		returnErrorJson(w, err)
		return
	}

	// revoke the current active refresh token since we reissue the new one
	err = revokeRefreshTokens(userGUID)
	if err != nil {
		log.Println(err)
		returnErrorJson(w, err)
		return
	}

	err = insertRefreshTokenDocument(userGUID, refreshToken, refreshTokenExpirationTime)
	if err != nil {
		log.Println(err)
		returnErrorJson(w, err)
		return
	}
	type jsonResponse struct {
		AccessToken  string `json:"access_token"`
		RefreshToken string `json:"refresh_token"`
	}
	resp := jsonResponse{
		AccessToken:  accessToken,
		RefreshToken: refreshToken,
	}

	resp_json, err := json.MarshalIndent(resp, "", "\t")
	if err != nil {
		returnErrorJson(w, err)
		return
	}

	w.Write(resp_json)
}
