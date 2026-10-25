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
	if Version != "0.6.0" {
		t.Fatalf("Version = %q, want 0.6.0 for this release", Version)
	}
}
