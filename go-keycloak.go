package gokeycloak

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"

	"github.com/golang-jwt/jwt/v5"
	jwt "github.com/golang-jwt/jwt/v5"
)

type KeyCloak struct {
	realm         string
	base_url      string
	client_id     string
	client_secret string
}

type Keyfunc func(alg string) (interface{}, error)

func NewKeyCloak(realm string, base_url string, client_id string, client_secret string) KeyCloak {
	ks := KeyCloak{}
	ks.realm = realm
	ks.base_url = base_url
	ks.client_id = client_id
	ks.client_secret = client_secret
	return ks
}

func (ks KeyCloak) GetAccessTokenInfo(accessToken string) error {

	url := fmt.Sprintf("%s/realms/%s/protocol/openid-connect/userinfo", ks.base_url, ks.realm)
	req, _ := http.NewRequest(http.MethodGet, url, nil)
	req.Header = http.Header{
		"Authorization": {"Bearer " + accessToken},
	}
	client := &http.Client{}

	resp, err := client.Do(req)
	if err != nil {
		fmt.Println(err.Error())
	}
	// TODO: to restructure and return the response data bytes.
	fmt.Println(resp.Status)
	return err
}

func (ks KeyCloak) RefreshToken(refreshToken string) error {

	url := fmt.Sprintf("%s/realms/%s/protocol/openid-connect/token", ks.base_url, ks.realm)

	requestBody := map[string]string{}
	requestBody["grant_type"] = "refresh_token"
	requestBody["client_id"] = ks.client_id
	requestBody["refresh_token"] = refreshToken
	if ks.client_secret != "" {
		requestBody["client_secret"] = ks.client_secret
	}
	jsonBody, _ := json.Marshal(requestBody)

	req, _ := http.NewRequest(http.MethodPost, url, bytes.NewBuffer(jsonBody))

	client := &http.Client{}
	resp, err := client.Do(req)

	if err != nil {
		fmt.Println(err.Error())
	}
	// TODO: to restructure and return the response data bytes.
	fmt.Println(resp.Status)
	return err
}

func (ks KeyCloak) VerifyJWTOnline(accessToken string) error {
	url := fmt.Sprintf("%s/realms/%s/protocol/openid-connect/userinfo", ks.base_url, ks.realm)
	req, _ := http.NewRequest(http.MethodGet, url, nil)
	req.Header = http.Header{
		"Authorization": {"Bearer " + accessToken},
	}
	client := &http.Client{}

	resp, err := client.Do(req)
	if err != nil {
		fmt.Println(err.Error())
	}
	// TODO: to restructure and return the response data bytes.
	fmt.Println(resp.Status)
	return err
}

func (ks KeyCloak) VerifyLocal(accessToken string, allowUnSafeNoAlgoSigningMethod bool, keyFunc Keyfunc) error {

	if keyFunc != nil {

		_, err := jwt.Parse(accessToken, func(token *jwt.Token) (interface{}, error) {
			// Don't forget to validate the alg is what you expect:
			if _, ok := token.Method.(*jwt.SigningMethodNone); ok && !allowUnSafeNoAlgoSigningMethod {
				return nil, fmt.Errorf("Unexpected signing method: %v", token.Header["alg"])
			}

			// hmacSampleSecret is a []byte containing your secret, e.g. []byte("my_secret_key")
			return keyFunc(token.Header["alg"])
		})
		return err
	}

	// Entering unsafe zone! you are not passing any key to validate the JWT
	// Do it only for testing
	if allowUnSafeNoAlgoSigningMethod {
		_, err := jwt.Parse(accessToken)
		return err
	}

	return fmt.Errorf("Either allowUnsafe flag or keyFunc required")
}

func (ks KeyCloak) GetClaims(accessToken string) (jwt.Claims, error) {
	token, err := jwt.Parse(accessToken)
	if !err {
		return token.Claims, nil
	}
	return nil, err
}
