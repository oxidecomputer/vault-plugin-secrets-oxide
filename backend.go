package oxidesecrets

import (
	"context"

	"github.com/openbao/openbao/sdk/v2/framework"
	"github.com/openbao/openbao/sdk/v2/logical"
)

func Factory(ctx context.Context, c *logical.BackendConfig) (logical.Backend, error) {
	b := Backend(c)
	if err := b.Setup(ctx, c); err != nil {
		return nil, err
	}
	return b, nil
}

type backend struct {
	*framework.Backend
}

const backendHelp = "The Oxide secrets backend mints short-lived Oxide access tokens."

func Backend(_ *logical.BackendConfig) *backend {
	var b backend

	b.Backend = &framework.Backend{
		Help:        backendHelp,
		BackendType: logical.TypeLogical,
		Paths: []*framework.Path{
			b.pathPrincipal(),
			b.pathListPrincipal(),
			b.pathCredentials(),
		},
		Secrets: b.secrets(),
	}

	return &b
}
