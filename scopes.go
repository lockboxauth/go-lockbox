package lockbox

const (
	scopesServiceDefaultBasePath = "/scopes/v1/"
)

// Scope is a permission from the scopes service. It can be attached to a
// session to authorize access to resources.
type Scope struct {
	ID               string   `json:"id"`
	UserPolicy       string   `json:"userPolicy"`
	UserExceptions   []string `json:"userExceptions"`
	ClientPolicy     string   `json:"clientPolicy"`
	ClientExceptions []string `json:"clientExceptions"`
	IsDefault        bool     `json:"isDefault"`
}

// ScopesService is the scopes service. Set the BasePath to modify where
// requests will be sent relative to the Client's base URL. ScopesService
// should only be instantiated by calling NewClient.
type ScopesService struct {
	BasePath string
	client   *Client
}
