package version

import (
	"regexp"
	"testing"
)

func TestVersionIsSemver(t *testing.T) {
	re := regexp.MustCompile(`^\d+\.\d+\.\d+$`)
	if !re.MatchString(Version) {
		t.Fatalf("Version %q is not plain semver", Version)
	}
	if Version != "0.8.3" {
		t.Fatalf("Version = %q, want 0.8.3 for this release", Version)
	}
}
