package policy

import "github.com/zmiishe/synamcps/internal/models"

func CanRead(p models.Principal, d models.DocumentRecord) bool {
	switch d.Visibility {
	case models.VisibilityPublic:
		return true
	case models.VisibilityPersonal:
		return d.OwnerID == p.UserID
	case models.VisibilityGroup:
		return intersects(d.GroupIDs, p.Groups) || d.OwnerID == p.UserID
	default:
		return false
	}
}

func CanWrite(p models.Principal, visibility models.Visibility, groupIDs []string) bool {
	switch visibility {
	case models.VisibilityPublic:
		return hasScope(p.Scopes, "knowledge.write.public")
	case models.VisibilityPersonal:
		return true
	case models.VisibilityGroup:
		return intersects(groupIDs, p.Groups)
	default:
		return false
	}
}

func CanDelete(p models.Principal, d models.DocumentRecord) bool {
	if d.OwnerID == p.UserID {
		return true
	}
	if d.Visibility == models.VisibilityPublic {
		return hasScope(p.Scopes, "knowledge.delete.public")
	}
	if d.Visibility == models.VisibilityGroup {
		return hasScope(p.Scopes, "knowledge.delete.group")
	}
	return false
}

func intersects(a, b []string) bool {
	set := map[string]struct{}{}
	for _, v := range a {
		set[v] = struct{}{}
	}
	for _, v := range b {
		if _, ok := set[v]; ok {
			return true
		}
	}
	return false
}

func hasScope(scopes []string, scope string) bool {
	for _, s := range scopes {
		if s == scope {
			return true
		}
	}
	return false
}
