package accesstoken

import (
	"fmt"
	"github.com/golang-jwt/jwt/v5"
	"time"
)

const tokenTypeBearer = "Bearer"

type timeService interface {
	Now() time.Time
}

type Claims struct {
	UserID string `json:"userId"`

	jwt.RegisteredClaims
}

type Service struct {
	timeService        timeService
	cfg                Config
	tokenSigningMethod jwt.SigningMethod
}

func NewService(
	timeService timeService,
	cfg Config,
	tokenSigningMethod jwt.SigningMethod) *Service {
	return &Service{
		timeService:        timeService,
		cfg:                cfg,
		tokenSigningMethod: tokenSigningMethod,
	}
}

func (s *Service) GenerateForUser(
	userID string,
) (*Token, error) {
	now := s.timeService.Now().UTC()
	expiresAt := now.Add(s.cfg.TTL)

	claims := Claims{
		UserID: userID,
		RegisteredClaims: jwt.RegisteredClaims{
			Subject:   userID,
			Issuer:    s.cfg.Issuer,
			Audience:  jwt.ClaimStrings{s.cfg.Audience},
			IssuedAt:  jwt.NewNumericDate(now),
			ExpiresAt: jwt.NewNumericDate(expiresAt),
		},
	}

	signedToken, err := jwt.NewWithClaims(s.tokenSigningMethod, claims).SignedString([]byte(s.cfg.Secret))
	if err != nil {
		return nil, fmt.Errorf("sign access token: %w", err)
	}

	return &Token{
		Token:     signedToken,
		TokenType: tokenTypeBearer,
		ExpiresIn: int(s.cfg.TTL.Seconds()),
		ExpiresAt: expiresAt,
	}, nil
}

func (s *Service) ValidateAccessToken(
	rawToken string,
) (*Claims, error) {
	token, err := jwt.ParseWithClaims(
		rawToken,
		&Claims{},
		func(token *jwt.Token) (any, error) {
			if token.Method != s.tokenSigningMethod {
				return nil, fmt.Errorf("unexpected signing method: %s", token.Method.Alg())
			}

			return []byte(s.cfg.Secret), nil
		},
		jwt.WithValidMethods([]string{s.tokenSigningMethod.Alg()}),
		jwt.WithIssuer(s.cfg.Issuer),
		jwt.WithAudience(s.cfg.Audience),
		jwt.WithExpirationRequired(),
		jwt.WithIssuedAt(),
	)
	if err != nil {
		return nil, fmt.Errorf("parse access token: %w", err)
	}

	claims, ok := token.Claims.(*Claims)
	if !ok || !token.Valid {
		return nil, fmt.Errorf("invalid access token claims")
	}

	return claims, nil
}
