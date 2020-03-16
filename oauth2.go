package lockbox

const (
	oauth2ServiceDefaultBasePath = "/oauth2/v1/"
)

// OAuth2Service is the oauth2 service. Set the BasePath to modify where
// requests will be sent relative to the Client's base URL. OAuth2Service
// should only be instantiated by calling NewClient.
type OAuth2Service struct {
	BasePath string
	client   *Client
}
