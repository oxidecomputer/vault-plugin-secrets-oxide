package oxidesecrets

import (
	"context"
	"net/http"

	"github.com/oxidecomputer/oxide.go/oxide"
)

//go:generate go tool -modfile=tools/go.mod mockgen -source=oxide_client.go -destination=oxide_client_mock_test.go -package=oxidesecrets -mock_names=oxideClient=MockOxideClient
type oxideClient interface {
	CurrentUserView(context.Context) (*oxide.CurrentUser, error)
	CurrentUserAccessTokenDelete(context.Context, oxide.CurrentUserAccessTokenDeleteParams) error
	MakeRequest(context.Context, oxide.Request) (*http.Response, error)
}

type oxideClientFactory func(string, string) (oxideClient, error)

func makeOxideClient(host string, token string) (oxideClient, error) {
	return oxide.NewClient(oxide.WithHost(host), oxide.WithToken(token))
}
