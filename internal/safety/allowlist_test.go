package safety

import (
	"path/filepath"
	"testing"
)

func TestCleanupAllowlistAllowsCacheChildren(t *testing.T) {
	home := filepath.Join(string(filepath.Separator), "Users", "alice")
	path := filepath.Join(home, "Library", "Caches", "example", "file.tmp")
	if !IsCleanupAllowed(path, home) {
		t.Fatalf("expected cache child to be allowed")
	}
}

func TestCleanupAllowlistRejectsCacheRootAndSecrets(t *testing.T) {
	home := filepath.Join(string(filepath.Separator), "Users", "alice")
	if IsCleanupAllowed(filepath.Join(home, "Library", "Caches"), home) {
		t.Fatalf("cache root itself should not be removed")
	}
	if IsCleanupAllowed(filepath.Join(home, ".ssh", "id_ed25519"), home) {
		t.Fatalf("ssh key should never be allowed")
	}
	if IsCleanupAllowed(filepath.Join(home, "project", ".env"), home) {
		t.Fatalf(".env should never be allowed")
	}
}
