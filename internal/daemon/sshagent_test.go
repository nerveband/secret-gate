package daemon

import (
	"os"
	"testing"
)

func TestIsSSHPrivateKey(t *testing.T) {
	tests := []struct {
		name   string
		value  string
		expect bool
	}{
		{"RSA key", "-----BEGIN RSA PRIVATE KEY-----\nMIIE...", true},
		{"OpenSSH key", "-----BEGIN OPENSSH PRIVATE KEY-----\nb3Bl...", true},
		{"EC key", "-----BEGIN EC PRIVATE KEY-----\nMHQC...", true},
		{"DSA key", "-----BEGIN DSA PRIVATE KEY-----\nMIIB...", true},
		{"Generic private key", "-----BEGIN PRIVATE KEY-----\nMIIE...", true},
		{"Public key", "-----BEGIN PUBLIC KEY-----\nMIIB...", false},
		{"Certificate", "-----BEGIN CERTIFICATE-----\nMIID...", false},
		{"Random string", "not a key at all", false},
		{"Empty string", "", false},
		{"SSH public key", "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5...", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := IsSSHPrivateKey(tt.value); got != tt.expect {
				t.Errorf("IsSSHPrivateKey() = %v, want %v", got, tt.expect)
			}
		})
	}
}

func TestCreateTempSSHKey(t *testing.T) {
	path, err := CreateTempSSHKey("test-private-key")
	if err != nil {
		t.Fatalf("CreateTempSSHKey: %v", err)
	}
	defer os.Remove(path)

	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat temp key: %v", err)
	}
	if got := info.Mode().Perm(); got != 0600 {
		t.Fatalf("temp key mode = %04o, want 0600", got)
	}

	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read temp key: %v", err)
	}
	if got, want := string(data), "test-private-key\n"; got != want {
		t.Fatalf("temp key contents = %q, want %q", got, want)
	}
}

func TestFindSSHKeyField(t *testing.T) {
	fields := map[string]string{
		"username":    "admin",
		"private_key": "-----BEGIN OPENSSH PRIVATE KEY-----\nb3Bl...",
		"public_key":  "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5...",
	}

	fieldName, value, found := FindSSHKeyField(fields)
	if !found {
		t.Fatal("expected to find SSH key field")
	}
	if fieldName != "private_key" {
		t.Errorf("fieldName = %q, want private_key", fieldName)
	}
	if value != fields["private_key"] {
		t.Error("value doesn't match")
	}
}

func TestFindSSHKeyFieldNotPresent(t *testing.T) {
	fields := map[string]string{
		"username": "admin",
		"password": "secret",
	}

	_, _, found := FindSSHKeyField(fields)
	if found {
		t.Error("should not find SSH key in non-SSH fields")
	}
}
