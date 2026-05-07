package providers

type GenericOIDCProvider struct {
	Name     string
	Issuer   string
	Audience string
	JWKSURL  string
}
