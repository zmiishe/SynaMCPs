package unit

import (
	"testing"

	"github.com/zmiishe/synamcps/internal/models"
	"github.com/zmiishe/synamcps/internal/policy"
)

func TestCanReadPersonal(t *testing.T) {
	p := models.Principal{UserID: "u1"}
	doc := models.DocumentRecord{OwnerID: "u1", Visibility: models.VisibilityPersonal}
	if !policy.CanRead(p, doc) {
		t.Fatalf("owner should read personal doc")
	}
}

func TestCanReadGroup(t *testing.T) {
	p := models.Principal{UserID: "u2", Groups: []string{"ops"}}
	doc := models.DocumentRecord{OwnerID: "u1", Visibility: models.VisibilityGroup, GroupIDs: []string{"ops"}}
	if !policy.CanRead(p, doc) {
		t.Fatalf("group member should read")
	}
}
