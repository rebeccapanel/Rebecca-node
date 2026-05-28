package xray

import (
	"testing"

	"github.com/xtls/xray-core/common/serial"
	"github.com/xtls/xray-core/proxy/shadowsocks"
	"github.com/xtls/xray-core/proxy/trojan"
	"github.com/xtls/xray-core/proxy/vless"
	"github.com/xtls/xray-core/proxy/vmess"
	"google.golang.org/protobuf/proto"
)

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
				Protocol: "vless",
				Email:    "1.test",
				ID:       "22222222-2222-2222-2222-222222222222",
				Flow:     "xtls-rprx-vision",
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
		{Protocol: "unknown", Email: "1.test"},
		{Protocol: "vless", ID: "22222222-2222-2222-2222-222222222222"},
	}

	for _, user := range tests {
		if _, err := buildProtocolUser(user); err == nil {
			t.Fatalf("expected error for %#v", user)
		}
	}
}
