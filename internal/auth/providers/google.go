package providers

type GoogleProvider struct {
	Issuer         string
	Audience       string
	AllowedDomains []string
}
