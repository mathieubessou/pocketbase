package security

import (
	"errors"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

// ParseUnverifiedJWT parses JWT and returns its claims
// but DOES NOT verify the signature.
//
// It verifies only the exp, iat and nbf claims.
func ParseUnverifiedJWT(token string) (jwt.MapClaims, error) {
	claims := jwt.MapClaims{}

	parser := &jwt.Parser{}
	_, _, err := parser.ParseUnverified(token, claims)

	if err == nil {
		err = jwt.NewValidator(jwt.WithIssuedAt()).Validate(claims)
	}

	return claims, err
}

// ParseJWT verifies and parses JWT and returns its claims.
func ParseJWT(token string, verificationKey string) (jwt.MapClaims, error) {
	parser := jwt.NewParser(jwt.WithValidMethods([]string{"HS256"}))

	parsedToken, err := parser.Parse(token, func(t *jwt.Token) (any, error) {
		return []byte(verificationKey), nil
	})
	if err != nil {
		return nil, err
	}

	if claims, ok := parsedToken.Claims.(jwt.MapClaims); ok && parsedToken.Valid {
		return claims, nil
	}

	return nil, errors.New("unable to parse token")
}

// NewJWT generates and returns new HS256 signed JWT.
func NewJWT(payload jwt.MapClaims, signingKey string, duration time.Duration) (string, error) {
	claims := jwt.MapClaims{}

	for k, v := range payload {
		claims[k] = v
	}

	// Always set exp after merging the payload so that duration is the
	// authoritative source for the token's expiration and cannot be
	// silently overridden by a caller-supplied "exp" value.
	claims["exp"] = time.Now().Add(duration).Unix()

	return jwt.NewWithClaims(jwt.SigningMethodHS256, claims).SignedString([]byte(signingKey))
}
