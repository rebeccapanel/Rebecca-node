package xray

import "testing"

func TestParseX25519Output(t *testing.T) {
	result, err := parseX25519Output("Private key: abc123\nPublic key: def456\n")
	if err != nil {
		t.Fatalf("parseX25519Output failed: %v", err)
	}
	if result.PrivateKey != "abc123" || result.PublicKey != "def456" {
		t.Fatalf("unexpected x25519 result: %#v", result)
	}
}

func TestParseMLDSA65Output(t *testing.T) {
	result, err := parseMLDSA65Output("Seed: seed-value\nVerify: verify-value\n")
	if err != nil {
		t.Fatalf("parseMLDSA65Output failed: %v", err)
	}
	if result.Seed != "seed-value" || result.Verify != "verify-value" {
		t.Fatalf("unexpected mldsa65 result: %#v", result)
	}
}

func TestParseECHOutput(t *testing.T) {
	result, err := parseECHOutput("header\nconfig-list\nother\nserver-keys\n")
	if err != nil {
		t.Fatalf("parseECHOutput failed: %v", err)
	}
	if result.ECHConfigList != "config-list" || result.ECHServerKeys != "server-keys" {
		t.Fatalf("unexpected ECH result: %#v", result)
	}
}

func TestHelperParsersRejectInvalidOutput(t *testing.T) {
	if _, err := parseX25519Output("bad"); err == nil {
		t.Fatal("expected invalid x25519 output to fail")
	}
	if _, err := parseMLDSA65Output("Seed: only-one-line"); err == nil {
		t.Fatal("expected invalid mldsa65 output to fail")
	}
	if _, err := parseECHOutput("too\nshort\n"); err == nil {
		t.Fatal("expected invalid ECH output to fail")
	}
}
