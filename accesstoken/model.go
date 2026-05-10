package accesstoken

import "time"

type Token struct {
	Token     string    `json:"token"`
	TokenType string    `json:"tokenType"`
	ExpiresIn int       `json:"expiresIn"`
	ExpiresAt time.Time `json:"expiresAt"`
}
