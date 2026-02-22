package auth

import (
	"encoding/base64"
	"testing"
)

func TestParseSecretStringPlain(t *testing.T) {
	got, err := ParseSecretString("smoke-secret")
	if err != nil {
		t.Fatalf("ParseSecretString returned error: %v", err)
	}
	if string(got) != "smoke-secret" {
		t.Fatalf("unexpected secret bytes: %q", string(got))
	}
}

func TestParseSecretStringBase64(t *testing.T) {
	want := []byte("binary-\x00-secret")
	encoded := "b64:" + base64.StdEncoding.EncodeToString(want)

	got, err := ParseSecretString(encoded)
	if err != nil {
		t.Fatalf("ParseSecretString returned error: %v", err)
	}
	if string(got) != string(want) {
		t.Fatalf("unexpected decoded secret: got=%x want=%x", got, want)
	}
}

func TestParseSecretStringInvalidBase64(t *testing.T) {
	if _, err := ParseSecretString("b64:%%%"); err == nil {
		t.Fatal("expected error for invalid base64 secret")
	}
}
