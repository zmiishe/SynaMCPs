package providers

type KeycloakProvider struct {
	Issuer   string
	Audience string
	JWKSURL  string
}
