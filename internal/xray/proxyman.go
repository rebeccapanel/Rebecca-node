package xray

import (
	"context"
	"fmt"
	"strings"
	"time"

	proxyman "github.com/xtls/xray-core/app/proxyman/command"
	"github.com/xtls/xray-core/common/protocol"
	"github.com/xtls/xray-core/common/serial"
	"github.com/xtls/xray-core/proxy/shadowsocks"
	"github.com/xtls/xray-core/proxy/trojan"
	"github.com/xtls/xray-core/proxy/vless"
	"github.com/xtls/xray-core/proxy/vmess"
	"google.golang.org/protobuf/proto"
)

type InboundUser struct {
	Protocol   string `json:"protocol"`
	Email      string `json:"email"`
	Level      uint32 `json:"level"`
	ID         string `json:"id"`
	Password   string `json:"password"`
	Flow       string `json:"flow"`
	Method     string `json:"method"`
	CipherType int32  `json:"cipher_type"`
	IVCheck    bool   `json:"iv_check"`
}

func AddInboundUser(apiHost string, apiPort int, timeout time.Duration, inboundTag string, user InboundUser) error {
	inboundTag = strings.TrimSpace(inboundTag)
	if inboundTag == "" {
		return fmt.Errorf("inbound_tag is required")
	}

	xrayUser, err := buildProtocolUser(user)
	if err != nil {
		return err
	}

	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	conn, err := dialAPI(ctx, apiHost, apiPort)
	if err != nil {
		return fmt.Errorf("connect to Xray proxyman API: %w", err)
	}
	defer conn.Close()

	client := proxyman.NewHandlerServiceClient(conn)
	_, err = client.AlterInbound(ctx, &proxyman.AlterInboundRequest{
		Tag:       inboundTag,
		Operation: serial.ToTypedMessage(&proxyman.AddUserOperation{User: xrayUser}),
	})
	if err != nil {
		return fmt.Errorf("add inbound user: %w", err)
	}
	return nil
}

func RemoveInboundUser(apiHost string, apiPort int, timeout time.Duration, inboundTag string, email string) error {
	inboundTag = strings.TrimSpace(inboundTag)
	email = strings.TrimSpace(email)
	if inboundTag == "" {
		return fmt.Errorf("inbound_tag is required")
	}
	if email == "" {
		return fmt.Errorf("email is required")
	}

	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	conn, err := dialAPI(ctx, apiHost, apiPort)
	if err != nil {
		return fmt.Errorf("connect to Xray proxyman API: %w", err)
	}
	defer conn.Close()

	client := proxyman.NewHandlerServiceClient(conn)
	_, err = client.AlterInbound(ctx, &proxyman.AlterInboundRequest{
		Tag:       inboundTag,
		Operation: serial.ToTypedMessage(&proxyman.RemoveUserOperation{Email: email}),
	})
	if err != nil {
		return fmt.Errorf("remove inbound user: %w", err)
	}
	return nil
}

func buildProtocolUser(user InboundUser) (*protocol.User, error) {
	email := strings.TrimSpace(user.Email)
	if email == "" {
		return nil, fmt.Errorf("email is required")
	}

	account, err := buildAccountMessage(user)
	if err != nil {
		return nil, err
	}

	return &protocol.User{
		Level:   user.Level,
		Email:   email,
		Account: serial.ToTypedMessage(account),
	}, nil
}

func buildAccountMessage(user InboundUser) (proto.Message, error) {
	switch strings.ToLower(strings.TrimSpace(user.Protocol)) {
	case "vmess":
		id := strings.TrimSpace(user.ID)
		if id == "" {
			return nil, fmt.Errorf("id is required for vmess")
		}
		return &vmess.Account{Id: id}, nil
	case "vless":
		id := strings.TrimSpace(user.ID)
		if id == "" {
			return nil, fmt.Errorf("id is required for vless")
		}
		return &vless.Account{Id: id, Flow: strings.TrimSpace(user.Flow)}, nil
	case "trojan":
		password := strings.TrimSpace(user.Password)
		if password == "" {
			return nil, fmt.Errorf("password is required for trojan")
		}
		return &trojan.Account{Password: password}, nil
	case "shadowsocks":
		password := strings.TrimSpace(user.Password)
		if password == "" {
			return nil, fmt.Errorf("password is required for shadowsocks")
		}
		return &shadowsocks.Account{
			Password:   password,
			CipherType: resolveShadowsocksCipher(user),
			IvCheck:    user.IVCheck,
		}, nil
	default:
		return nil, fmt.Errorf("unsupported protocol %q", user.Protocol)
	}
}

func resolveShadowsocksCipher(user InboundUser) shadowsocks.CipherType {
	if user.CipherType != 0 {
		return shadowsocks.CipherType(user.CipherType)
	}

	switch strings.ToLower(strings.TrimSpace(user.Method)) {
	case "aes-128-gcm":
		return shadowsocks.CipherType_AES_128_GCM
	case "aes-256-gcm":
		return shadowsocks.CipherType_AES_256_GCM
	case "chacha20-ietf-poly1305", "chacha20-poly1305":
		return shadowsocks.CipherType_CHACHA20_POLY1305
	case "xchacha20-ietf-poly1305", "xchacha20-poly1305":
		return shadowsocks.CipherType_XCHACHA20_POLY1305
	case "none":
		return shadowsocks.CipherType_NONE
	case "2022-blake3-aes-128-gcm":
		return shadowsocks.CipherType(10)
	case "2022-blake3-aes-256-gcm":
		return shadowsocks.CipherType(11)
	case "2022-blake3-chacha20-poly1305":
		return shadowsocks.CipherType(12)
	default:
		return shadowsocks.CipherType_CHACHA20_POLY1305
	}
}
