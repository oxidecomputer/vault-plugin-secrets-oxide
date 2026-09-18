package oxidesecrets

import (
	"testing"

	"github.com/openbao/openbao/sdk/v2/framework"
	"github.com/oxidecomputer/oxide.go/oxide"
	"github.com/stretchr/testify/require"
	gomock "go.uber.org/mock/gomock"
)

func TestUpdatePrincipal(t *testing.T) {
	b := Backend(nil)

	makeData := func(raw map[string]any) *framework.FieldData {
		return &framework.FieldData{
			Raw:    raw,
			Schema: b.pathPrincipal().Fields,
		}
	}

	for _, tc := range []struct {
		name          string
		principal     *oxidePrincipal
		data          *framework.FieldData
		setup         func(*MockOxideClient)
		wantErr       string
		wantPrincipal *oxidePrincipal
	}{
		{
			name:      "happy empty principal",
			principal: new(oxidePrincipal),
			wantPrincipal: &oxidePrincipal{
				Host:   "https://oxide2.example.com",
				Token:  "new-token",
				UserID: "10000000-0000-0000-0000-000000000001",
			},
			data: makeData(
				map[string]any{
					"host":  "https://oxide2.example.com",
					"token": "new-token",
				},
			),
			setup: func(client *MockOxideClient) {
				client.EXPECT().CurrentUserView(gomock.Any()).Return(&oxide.CurrentUser{
					Id: "10000000-0000-0000-0000-000000000001",
				}, nil)
			},
		},
		{
			name: "happy complete principal",
			wantPrincipal: &oxidePrincipal{
				Host:   "https://oxide.example.com",
				Token:  "new-token",
				UserID: "10000000-0000-0000-0000-000000000001",
			},
			principal: &oxidePrincipal{
				Host:   "https://oxide.example.com",
				Token:  "oxide-token-1234",
				UserID: "10000000-0000-0000-0000-000000000001",
			},
			data: makeData(
				map[string]any{
					"host":  "https://oxide.example.com",
					"token": "new-token",
				},
			),
			setup: func(client *MockOxideClient) {
				client.EXPECT().CurrentUserView(gomock.Any()).Return(&oxide.CurrentUser{
					Id: "10000000-0000-0000-0000-000000000001",
				}, nil)
			},
		},
		{
			name: "sad host changed",
			principal: &oxidePrincipal{
				Host:   "https://oxide.example.com",
				Token:  "oxide-token-1234",
				UserID: "10000000-0000-0000-0000-000000000001",
			},
			data: makeData(
				map[string]any{
					"host":  "https://oxide2.example.com",
					"token": "new-token",
				},
			),
			wantErr: "cannot change host",
		},
		{
			name: "sad user changed",
			principal: &oxidePrincipal{
				Host:   "https://oxide.example.com",
				Token:  "oxide-token-1234",
				UserID: "10000000-0000-0000-0000-000000000001",
			},
			data: makeData(
				map[string]any{
					"host":  "https://oxide.example.com",
					"token": "new-token",
				},
			),
			setup: func(client *MockOxideClient) {
				client.EXPECT().CurrentUserView(gomock.Any()).Return(&oxide.CurrentUser{
					Id: "10000000-0000-0000-0000-000000000002",
				}, nil)
			},
			wantErr: "cannot change to a different user id",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			before := *tc.principal
			ctrl := gomock.NewController(t)
			client := NewMockOxideClient(ctrl)
			if tc.setup != nil {
				tc.setup(client)
			}
			clientBuilder := func(host, token string) (oxideClient, error) {
				require.NotNil(t, tc.setup, "unexpected client construction")
				require.Equal(t, tc.data.Raw["host"], host)
				require.Equal(t, tc.data.Raw["token"], token)
				return client, nil
			}

			err := updatePrincipal(
				t.Context(),
				clientBuilder,
				"test-principal",
				tc.principal,
				tc.data,
			)
			if tc.wantErr == "" {
				require.NoError(t, err)
				require.Equal(t, tc.wantPrincipal, tc.principal)
			} else {
				require.ErrorContains(t, err, tc.wantErr)
				require.Equal(t, before, *tc.principal)
			}
		})
	}
}
