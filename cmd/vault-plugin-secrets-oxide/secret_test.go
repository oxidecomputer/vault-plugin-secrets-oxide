package main

import (
	"errors"
	"testing"

	"github.com/openbao/openbao/sdk/v2/logical"
	"github.com/oxidecomputer/oxide.go/oxide"
	"github.com/stretchr/testify/require"
	gomock "go.uber.org/mock/gomock"
)

func TestTokenRevoke(t *testing.T) {
	ctx := t.Context()

	storage := &logical.InmemStorage{}
	config := logical.TestBackendConfig()
	config.StorageView = storage

	rawBackend, err := Factory(ctx, config)
	require.NoError(t, err)
	backend := rawBackend.(*backend)

	for _, tc := range []struct {
		name    string
		apiErr  error
		wantErr string
	}{
		{name: "happy token exists"},
		{
			name:   "happy token not exists",
			apiErr: oxide.ErrHTTP404,
		},
		{
			name:    "sad api error",
			apiErr:  errors.New("boom"),
			wantErr: "revoking oxide token test-token: boom",
		},
	} {
		t.Run(
			tc.name,
			func(t *testing.T) {
				ctx := t.Context()
				ctrl := gomock.NewController(t)
				client := NewMockOxideClient(ctrl)
				client.EXPECT().
					CurrentUserAccessTokenDelete(
						ctx,
						oxide.CurrentUserAccessTokenDeleteParams{TokenId: "test-token"},
					).
					Return(tc.apiErr)

				err := backend.revokeToken(
					ctx,
					client,
					"test-token",
					"test-principal",
				)
				if tc.wantErr == "" {
					require.NoError(t, err)
				} else {
					require.ErrorContains(t, err, tc.wantErr)
					require.ErrorIs(t, err, tc.apiErr)
				}
			},
		)
	}
}
