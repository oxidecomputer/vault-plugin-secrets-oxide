package oxidesecrets

import (
	"context"
	"errors"
	"fmt"

	"github.com/openbao/openbao/sdk/v2/framework"
	"github.com/openbao/openbao/sdk/v2/logical"
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
			Revoke: b.handleTokenRevoke,
		},
	}
}

// handleTokenRevoke revokes the Oxide device auth token. Note that revocation is best-effort only:
// the client can use the Oxide device auth token provided by the plugin to request a second device
// auth token directly from Oxide, and that derived token won't be revoked when the original token
// is revoked.
func (b *backend) handleTokenRevoke(
	ctx context.Context,
	req *logical.Request,
	d *framework.FieldData,
) (*logical.Response, error) {
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
		return nil, fmt.Errorf("principal %q does not exist", principalName)
	}

	oxideClient, err := oxide.NewClient(
		oxide.WithHost(principal.Host),
		oxide.WithToken(principal.Token),
	)
	if err != nil {
		return nil, fmt.Errorf("building oxide client: %w", err)
	}

	if err := b.revokeToken(ctx, oxideClient, tokenID, principalName); err != nil {
		return nil, err
	}

	return nil, nil
}

func (b *backend) revokeToken(
	ctx context.Context,
	oxideClient oxideClient,
	tokenID string,
	principalName string,
) error {
	if err := oxideClient.CurrentUserAccessTokenDelete(
		ctx,
		oxide.CurrentUserAccessTokenDeleteParams{
			TokenId: tokenID,
		},
	); err != nil {
		if errors.Is(err, oxide.ErrHTTP404) {
			b.Logger().
				Info("ignoring 404 revoking oxide token", "token_id", tokenID, "principal", principalName)
			return nil
		}
		return fmt.Errorf("revoking oxide token %s: %w", tokenID, err)
	}

	return nil
}
