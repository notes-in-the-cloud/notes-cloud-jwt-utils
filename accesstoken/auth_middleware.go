package accesstoken

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"strings"
)

type userIDKey string

const userIDContextKey userIDKey = "userID"

type jwtValidator interface {
	ValidateAccessToken(rawToken string) (*Claims, error)
}

func AuthMiddleware(jwtValidator jwtValidator) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			authHeader := r.Header.Get("Authorization")
			if authHeader == "" || !strings.HasPrefix(authHeader, "Bearer ") {
				WriteErrorResponse(
					w,
					http.StatusUnauthorized,
					ErrMissingTokenFromHeader,
					"access token should be included in request header",
				)

				return
			}

			token := strings.TrimPrefix(authHeader, "Bearer ")

			claims, err := jwtValidator.ValidateAccessToken(token)
			if err != nil {
				WriteErrorResponse(
					w,
					http.StatusUnauthorized,
					ErrInvalidToken,
					"invalid access token in request header",
				)

				return
			}

			if claims.UserID == "" {
				WriteErrorResponse(
					w,
					http.StatusUnauthorized,
					ErrInvalidToken,
					"invalid access token in request header",
				)

				return
			}

			ctx := context.WithValue(r.Context(), userIDContextKey, claims.UserID)

			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}

const (
	ErrMissingTokenFromHeader = "MISSING_TOKEN_FROM_HEADER"
	ErrInvalidToken           = "INVALID_TOKEN"
)

type ErrorResponse struct {
	Error ErrorDetails `json:"error"`
}

type ErrorDetails struct {
	Code    string `json:"code"`
	Message string `json:"message"`
}

func WriteErrorResponse(
	w http.ResponseWriter,
	statusCode int,
	errorCode string,
	message string,
) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(statusCode)

	response := ErrorResponse{
		Error: ErrorDetails{
			Code:    errorCode,
			Message: message,
		},
	}

	if err := json.NewEncoder(w).Encode(response); err != nil {
		http.Error(w, "failed to encode error response", http.StatusInternalServerError)
	}
}

var ErrMissingUserIDFromContext = errors.New("missing user id from context")

func UserIDFromContext(ctx context.Context) (string, error) {
	userID, ok := ctx.Value(userIDContextKey).(string)
	if !ok || userID == "" {
		return "", ErrMissingUserIDFromContext
	}

	return userID, nil
}
