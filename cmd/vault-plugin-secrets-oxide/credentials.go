package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/logical"
	"github.com/oxidecomputer/oxide.go/oxide"
)

const deviceCodeGrantType = "urn:ietf:params:oauth:grant-type:device_code"

const clientID = "d958a483-d46d-4b4a-bac1-d8e1c28e33fc"

var deviceHTTPClient = &http.Client{Timeout: 30 * time.Second}

func (b *backend) pathCredentials() *framework.Path {
	return &framework.Path{
		Pattern: "creds/" + framework.GenericNameRegex("name"),
		Fields: map[string]*framework.FieldSchema{
			"name": {
				Type:     framework.TypeLowerCaseString,
				Required: true,
			},
			"ttl": {
				Type: framework.TypeDurationSecond,
			},
		},
		Callbacks: map[logical.Operation]framework.OperationFunc{
			logical.ReadOperation:   b.handleCredentialsRead,
			logical.UpdateOperation: b.handleCredentialsRead,
		},
	}
}

func (b *backend) handleCredentialsRead(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	principalName := d.Get("name").(string)

	principal, err := b.getPrincipal(ctx, req.Storage, principalName)
	if err != nil {
		return nil, fmt.Errorf("error retrieving role: %w", err)
	}

	if principal == nil {
		return nil, errors.New("error retrieving role: role is nil")
	}

	ttl := principal.DefaultTTL
	if reqTTL, ok := d.GetOk("ttl"); ok {
		ttl = time.Second * time.Duration(reqTTL.(int))
	}
	ttl, _, err = framework.CalculateTTL(b.System(), ttl, principal.DefaultTTL, 0, principal.MaxTTL, 0, time.Time{})
	if err != nil {
		return nil, err
	}

	token, err := b.createDeviceToken(ctx, principal, ttl)
	if err != nil {
		return nil, err
	}

	resp := b.Secret("oxide_token").Response(map[string]any{
		"access_token": token.AccessToken,
		"token_type":   token.TokenType,
		"token_id":     token.TokenID,
		"time_expires": token.TimeExpires,
	}, map[string]any{
		"token_id":  token.TokenID,
		"principal": principalName,
	})

	resp.Secret.TTL = ttl

	return resp, nil
}

type deviceAuthReq struct {
	ClientID   string
	TTLSeconds int
}

func (r deviceAuthReq) values() url.Values {
	v := url.Values{"client_id": {r.ClientID}}
	if r.TTLSeconds > 0 {
		v.Set("ttl_seconds", strconv.Itoa(r.TTLSeconds))
	}
	return v
}

type deviceAuthResp struct {
	DeviceCode      string `json:"device_code"`
	UserCode        string `json:"user_code"`
	VerificationURI string `json:"verification_uri"`
	ExpiresIn       int    `json:"expires_in"`
}

type deviceConfirmReq struct {
	UserCode string `json:"user_code"`
}

type deviceTokenReq struct {
	GrantType  string
	DeviceCode string
	ClientID   string
}

func (r deviceTokenReq) values() url.Values {
	return url.Values{
		"grant_type":  {r.GrantType},
		"device_code": {r.DeviceCode},
		"client_id":   {r.ClientID},
	}
}

type deviceTokenResp struct {
	AccessToken string     `json:"access_token"`
	TokenType   string     `json:"token_type"`
	TokenID     string     `json:"token_id"`
	TimeExpires *time.Time `json:"time_expires"`
}

func makeDeviceFormRequest(ctx context.Context, url string, body url.Values) (*http.Response, error) {
	req, err := http.NewRequestWithContext(ctx, "POST", url, strings.NewReader(body.Encode()))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "application/json")
	return deviceHTTPClient.Do(req)
}

func (b *backend) createDeviceToken(ctx context.Context, principal *oxidePrincipal, ttl time.Duration) (*deviceTokenResp, error) {
	oxideClient, err := oxide.NewClient(oxide.WithHost(principal.Host), oxide.WithToken(principal.Token))
	if err != nil {
		return nil, fmt.Errorf("building oxide client: %w", err)
	}

	authHTTPResp, err := makeDeviceFormRequest(ctx, principal.Host+"/device/auth", deviceAuthReq{
		ClientID:   clientID,
		TTLSeconds: int(ttl.Seconds()),
	}.values())
	if err != nil {
		return nil, fmt.Errorf("requesting device code: %w", err)
	}
	defer authHTTPResp.Body.Close()
	if authHTTPResp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("requesting device code: got status %d, expected %d", authHTTPResp.StatusCode, http.StatusOK)
	}

	var authResp deviceAuthResp
	if err := json.NewDecoder(authHTTPResp.Body).Decode(&authResp); err != nil {
		return nil, fmt.Errorf("error decoding device code response: %w", err)
	}

	confirmBody, err := json.Marshal(deviceConfirmReq{UserCode: authResp.UserCode})
	if err != nil {
		return nil, fmt.Errorf("encoding device confirm request: %w", err)
	}
	confirmHTTPResp, err := oxideClient.MakeRequest(ctx, oxide.Request{
		Method: http.MethodPost,
		Path:   "/device/confirm",
		Body:   bytes.NewReader(confirmBody),
	})
	if err != nil {
		return nil, fmt.Errorf("confirming device grant: %w", err)
	}
	defer confirmHTTPResp.Body.Close()
	if confirmHTTPResp.StatusCode != http.StatusNoContent {
		return nil, fmt.Errorf("confirming device grant: got status %d, expected %d", confirmHTTPResp.StatusCode, http.StatusNoContent)
	}

	tokenHTTPResp, err := makeDeviceFormRequest(ctx, principal.Host+"/device/token", deviceTokenReq{
		GrantType:  deviceCodeGrantType,
		DeviceCode: authResp.DeviceCode,
		ClientID:   clientID,
	}.values())
	if err != nil {
		return nil, fmt.Errorf("exchanging device code: %w", err)
	}
	defer tokenHTTPResp.Body.Close()
	if tokenHTTPResp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("exchanging device code: got status %d, expected %d", tokenHTTPResp.StatusCode, http.StatusOK)
	}

	var tokenResp deviceTokenResp
	if err := json.NewDecoder(tokenHTTPResp.Body).Decode(&tokenResp); err != nil {
		return nil, fmt.Errorf("decoding token response: %w", err)
	}

	return &tokenResp, nil
}
