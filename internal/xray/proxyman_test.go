package xray

import (
	"errors"
	"testing"

	"github.com/xtls/xray-core/proxy/vless"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

func TestInboundUserAPIUserCarriesProtocolFields(t *testing.T) {
	user := InboundUser{Protocol: "vless", Email: " 1.a ", ID: "11111111-1111-1111-1111-111111111111", Flow: "xtls-rprx-vision", ReverseTag: "r1"}.apiUser()
	if user["email"] != "1.a" || user["id"] != "11111111-1111-1111-1111-111111111111" || user["flow"] != "xtls-rprx-vision" {
		t.Fatalf("unexpected vless user %#v", user)
	}
	if reverse, _ := user["reverse"].(map[string]any); reverse["tag"] != "r1" {
		t.Fatalf("reverse tag lost: %#v", user)
	}
	account, err := buildUserAccount("vless", user)
	if err != nil || account == nil {
		t.Fatalf("vless account: %v %v", account, err)
	}
	decoded, err := account.GetInstance()
	if err != nil {
		t.Fatal(err)
	}
	if got := decoded.(*vless.Account); got.Id != "11111111-1111-1111-1111-111111111111" || got.Flow != "xtls-rprx-vision" || got.Reverse.GetTag() != "r1" {
		t.Fatalf("unexpected account %+v", got)
	}
}

func TestBuildUserAccountPerProtocol(t *testing.T) {
	cases := map[string]InboundUser{
		"vmess":       {Protocol: "vmess", Email: "u", ID: "11111111-1111-1111-1111-111111111111"},
		"trojan":      {Protocol: "trojan", Email: "u", Password: "secret"},
		"hysteria":    {Protocol: "hysteria", Email: "u", Auth: "token"},
		"masque":      {Protocol: "masque", Email: "u", Password: "secret"},
		"shadowsocks": {Protocol: "shadowsocks", Email: "u", Password: "secret", Method: "aes-256-gcm"},
	}
	for name, user := range cases {
		account, err := buildUserAccount(name, user.apiUser())
		if err != nil || account == nil {
			t.Fatalf("%s account: %v %v", name, account, err)
		}
	}
	ss2022 := InboundUser{Protocol: "shadowsocks", Email: "u", Password: "MDEyMzQ1Njc4OWFiY2RlZjAxMjM0NTY3ODlhYmNkZWY=", Method: "2022-blake3-aes-256-gcm"}
	if account, err := buildUserAccount("shadowsocks", ss2022.apiUser()); err != nil || account == nil {
		t.Fatalf("ss2022 account: %v %v", account, err)
	}
}

func TestInboundUserValidateRejectsIncompleteUsers(t *testing.T) {
	for name, user := range map[string]InboundUser{
		"vless":       {Protocol: "vless", Email: "u"},
		"vmess":       {Protocol: "vmess", Email: "u"},
		"trojan":      {Protocol: "trojan", Email: "u"},
		"hysteria":    {Protocol: "hysteria", Email: "u"},
		"masque":      {Protocol: "masque", Email: "u"},
		"shadowsocks": {Protocol: "shadowsocks", Email: "u"},
		"no email":    {Protocol: "vless", ID: "x"},
		"unsupported": {Protocol: "socks", Email: "u"},
	} {
		if err := user.validate(); err == nil {
			t.Fatalf("%s user without usable credentials must be rejected", name)
		}
	}
	if _, err := buildUserAccount("shadowsocks", InboundUser{Protocol: "shadowsocks", Email: "u", Password: "secret", Method: "rot13"}.apiUser()); err == nil {
		t.Fatal("an unknown shadowsocks cipher must not build an account")
	}
}

func TestClassifyAPIErrorMarksUnavailable(t *testing.T) {
	if !errors.Is(classifyAPIError(status.Error(codes.Unavailable, "down")), ErrAPIUnavailable) {
		t.Fatal("an unreachable API must map to ErrAPIUnavailable")
	}
	plain := errors.New("boom")
	if classifyAPIError(plain) != plain || classifyAPIError(nil) != nil {
		t.Fatal("other errors must pass through")
	}
}
