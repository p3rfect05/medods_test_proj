package main

import (
	"net/http"

	"github.com/go-chi/chi/v5"
)

func routes() http.Handler {
	mux := chi.NewRouter()

	mux.Post("/get_tokens", PostGetTokenPair)

	//mux.Post("/validate", PostValidateToken): не было в ТЗ, но оставил, иногда полезна

	mux.Post("/reissue", PostRefreshTokens)
	return mux

}
