package teleport

import "github.com/zmiishe/synamcps/internal/models"

func MapTraits(p models.Principal, traits map[string][]string) models.Principal {
	p.TeleportTraits = traits
	return p
}
