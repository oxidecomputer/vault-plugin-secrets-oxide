package main

import (
	"context"
	"errors"
	"fmt"

	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/logical"
	"github.com/oxidecomputer/oxide.go/oxide"
)

func (b *backend) secrets() []*framework.Secret {
	return []*framework.Secret{
		{
			Type: "oxide_token",
			Fields: map[string]*framework.FieldSchema{
				"access_token": {
					Type: framework.TypeString,
				},
				"token_id": {
					Type: framework.TypeString,
				},
			},
			Revoke: b.tokenRevoke,
		},
	}
}

func (b *backend) tokenRevoke(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	tokenID, ok := req.Secret.InternalData["token_id"].(string)
	if !ok {
		return nil, errors.New("secret is missing token_id data")
	}
	principalName, ok := req.Secret.InternalData["principal"].(string)
	if !ok {
		return nil, errors.New("secret is missing principal data")
	}

	principal, err := b.getPrincipal(ctx, req.Storage, principalName)
	if err != nil {
		return nil, fmt.Errorf("retrieving principal %q: %w", principalName, err)
	}
	if principal == nil {
		return nil, fmt.Errorf("principal %q no longer exists", principalName)
	}

	oxideClient, err := oxide.NewClient(oxide.WithHost(principal.Host), oxide.WithToken(principal.Token))
	if err != nil {
		return nil, fmt.Errorf("building oxide client: %w", err)
	}

	if err := oxideClient.CurrentUserAccessTokenDelete(ctx, oxide.CurrentUserAccessTokenDeleteParams{
		TokenId: tokenID,
	}); err != nil {
		return nil, fmt.Errorf("revoking oxide token %s: %w", tokenID, err)
	}

	return nil, nil
}
