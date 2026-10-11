package xray

import (
	"encoding/base64"
	"testing"

	"github.com/xtls/xray-core/common/protocol"
	"github.com/xtls/xray-core/common/serial"
	hysteriaAccount "github.com/xtls/xray-core/proxy/hysteria/account"
	"github.com/xtls/xray-core/proxy/shadowsocks"
	shadowsocks2022 "github.com/xtls/xray-core/proxy/shadowsocks_2022"
	"github.com/xtls/xray-core/proxy/trojan"
	"github.com/xtls/xray-core/proxy/vless"
	"github.com/xtls/xray-core/proxy/vmess"
	"google.golang.org/protobuf/proto"
)

func TestShadowsocks2022UserUsesKeyAccount(t *testing.T) {
	key := "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="
	message, err := buildAccountMessage(InboundUser{Protocol: "shadowsocks", Password: key, Method: "2022-blake3-aes-256-gcm"})
	if err != nil {
		t.Fatal(err)
	}
	account, ok := message.(*shadowsocks2022.Account)
	if !ok || account.GetKey() != key {
		t.Fatalf("2022 user must use a key account, got %T", message)
	}
}

func TestShadowsocks2022UserRoundTripsIntoXrayAccount(t *testing.T) {
	key := base64.StdEncoding.EncodeToString(make([]byte, 32))
	message, err := buildAccountMessage(InboundUser{Protocol: "shadowsocks", Password: key, Method: "2022-blake3-aes-256-gcm"})
	if err != nil {
		t.Fatal(err)
	}
	user := &protocol.User{Email: "u", Account: serial.ToTypedMessage(message)}
	memory, err := user.ToMemoryUser()
	if err != nil {
		t.Fatal(err)
	}
	account, ok := memory.Account.(*shadowsocks2022.MemoryAccount)
	if !ok || account.Key != key {
		t.Fatalf("Xray must convert the user into a 2022 memory account, got %T", memory.Account)
	}
}

func TestShadowsocks2022UserRejectsWrongKeyLength(t *testing.T) {
	if _, err := buildAccountMessage(InboundUser{Protocol: "shadowsocks", Password: "c2VjcmV0", Method: "2022-blake3-aes-256-gcm"}); err == nil {
		t.Fatal("a non-32-byte key must be rejected for aes-256")
	}
	if _, err := buildAccountMessage(InboundUser{Protocol: "shadowsocks", Password: "AAAAAAAAAAAAAAAAAAAAAA==", Method: "2022-blake3-aes-128-gcm"}); err != nil {
		t.Fatalf("a 16-byte key must be accepted for aes-128: %v", err)
	}
}

func TestBuildProtocolUserAccounts(t *testing.T) {
	tests := []struct {
		name     string
		user     InboundUser
		expected proto.Message
	}{
		{
			name: "vmess",
			user: InboundUser{
				Protocol: "vmess",
				Email:    "1.test",
				ID:       "11111111-1111-1111-1111-111111111111",
			},
			expected: &vmess.Account{},
		},
		{
			name: "vless vision",
			user: InboundUser{
				Protocol:   "vless",
				Email:      "1.test",
				ID:         "22222222-2222-2222-2222-222222222222",
				Flow:       "xtls-rprx-vision",
				ReverseTag: "reverse-out",
			},
			expected: &vless.Account{},
		},
		{
			name: "trojan",
			user: InboundUser{
				Protocol: "trojan",
				Email:    "1.test",
				Password: "secret",
			},
			expected: &trojan.Account{},
		},
		{
			name: "shadowsocks",
			user: InboundUser{
				Protocol: "shadowsocks",
				Email:    "1.test",
				Password: "secret",
				Method:   "aes-256-gcm",
				IVCheck:  true,
			},
			expected: &shadowsocks.Account{},
		},
		{
			name: "hysteria",
			user: InboundUser{
				Protocol: "hysteria",
				Email:    "1.test",
				Auth:     "secret-auth",
			},
			expected: &hysteriaAccount.Account{},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			user, err := buildProtocolUser(tt.user)
			if err != nil {
				t.Fatalf("buildProtocolUser failed: %v", err)
			}
			if user.Email != tt.user.Email {
				t.Fatalf("unexpected email: %q", user.Email)
			}
			account, err := user.Account.GetInstance()
			if err != nil {
				t.Fatalf("failed to decode account typed message: %v", err)
			}
			if serial.GetMessageType(account) != serial.GetMessageType(tt.expected) {
				t.Fatalf("unexpected account type: got %T want %T", account, tt.expected)
			}
			if tt.user.Flow != "" {
				vlessAccount, ok := account.(*vless.Account)
				if !ok || vlessAccount.Flow != tt.user.Flow {
					t.Fatalf("unexpected vless flow: %#v", account)
				}
				if vlessAccount.Reverse == nil || vlessAccount.Reverse.Tag != tt.user.ReverseTag {
					t.Fatalf("unexpected vless reverse config: %#v", account)
				}
			}
			if tt.user.Method == "aes-256-gcm" {
				ssAccount, ok := account.(*shadowsocks.Account)
				if !ok {
					t.Fatalf("expected shadowsocks account, got %T", account)
				}
				if ssAccount.CipherType != shadowsocks.CipherType_AES_256_GCM || !ssAccount.IvCheck {
					t.Fatalf("unexpected shadowsocks account: %#v", ssAccount)
				}
			}
		})
	}
}

func TestBuildProtocolUserRejectsInvalidAccounts(t *testing.T) {
	tests := []InboundUser{
		{Protocol: "vmess", Email: "1.test"},
		{Protocol: "vless", Email: "1.test"},
		{Protocol: "trojan", Email: "1.test"},
		{Protocol: "shadowsocks", Email: "1.test"},
		{Protocol: "hysteria", Email: "1.test"},
		{Protocol: "unknown", Email: "1.test"},
		{Protocol: "vless", ID: "22222222-2222-2222-2222-222222222222"},
	}

	for _, user := range tests {
		if _, err := buildProtocolUser(user); err == nil {
			t.Fatalf("expected error for %#v", user)
		}
	}
}
