package xray

import (
	"fmt"
	"strings"
	"sync"

	"github.com/xtls/xray-core/proxy/shadowsocks"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

type InboundUser struct {
	Protocol   string `json:"protocol"`
	Email      string `json:"email"`
	Level      uint32 `json:"level"`
	ID         string `json:"id"`
	Password   string `json:"password"`
	Auth       string `json:"auth"`
	Flow       string `json:"flow"`
	ReverseTag string `json:"reverse_tag"`
	Method     string `json:"method"`
	CipherType int32  `json:"cipher_type"`
	IVCheck    bool   `json:"iv_check"`
}

var (
	sharedAPIMu sync.Mutex
	sharedAPIs  = map[int]*XrayAPI{}
)

func SharedAPI(apiPort int) (*XrayAPI, error) {
	sharedAPIMu.Lock()
	defer sharedAPIMu.Unlock()
	if api, ok := sharedAPIs[apiPort]; ok {
		return api, nil
	}
	api := &XrayAPI{}
	if err := api.Init(apiPort); err != nil {
		return nil, err
	}
	sharedAPIs[apiPort] = api
	return api, nil
}

func (u InboundUser) apiUser() map[string]any {
	user := map[string]any{"email": strings.TrimSpace(u.Email)}
	switch strings.ToLower(strings.TrimSpace(u.Protocol)) {
	case "vmess":
		user["id"] = strings.TrimSpace(u.ID)
	case "vless":
		user["id"] = strings.TrimSpace(u.ID)
		user["flow"] = strings.TrimSpace(u.Flow)
		if tag := strings.TrimSpace(u.ReverseTag); tag != "" {
			user["reverse"] = map[string]any{"tag": tag}
		}
	case "trojan":
		user["password"] = strings.TrimSpace(u.Password)
	case "shadowsocks":
		user["password"] = strings.TrimSpace(u.Password)
		user["cipher"] = u.cipherName()
	case "hysteria":
		auth := strings.TrimSpace(u.Auth)
		if auth == "" {
			auth = strings.TrimSpace(u.Password)
		}
		user["auth"] = auth
	}
	return user
}

func (u InboundUser) cipherName() string {
	if method := strings.TrimSpace(u.Method); method != "" {
		return method
	}
	switch shadowsocks.CipherType(u.CipherType) {
	case shadowsocks.CipherType_AES_128_GCM:
		return "aes-128-gcm"
	case shadowsocks.CipherType_AES_256_GCM:
		return "aes-256-gcm"
	case shadowsocks.CipherType_CHACHA20_POLY1305:
		return "chacha20-poly1305"
	case shadowsocks.CipherType_XCHACHA20_POLY1305:
		return "xchacha20-poly1305"
	}
	return ""
}

func (u InboundUser) validate() error {
	if strings.TrimSpace(u.Email) == "" {
		return fmt.Errorf("email is required")
	}
	protocol := strings.ToLower(strings.TrimSpace(u.Protocol))
	switch protocol {
	case "vmess", "vless":
		if strings.TrimSpace(u.ID) == "" {
			return fmt.Errorf("id is required for %s", protocol)
		}
	case "trojan", "shadowsocks":
		if strings.TrimSpace(u.Password) == "" {
			return fmt.Errorf("password is required for %s", protocol)
		}
	case "hysteria":
		if strings.TrimSpace(u.Auth) == "" && strings.TrimSpace(u.Password) == "" {
			return fmt.Errorf("auth is required for hysteria")
		}
	default:
		return fmt.Errorf("unsupported protocol %q", u.Protocol)
	}
	return nil
}

func AddInboundUser(apiPort int, inboundTag string, user InboundUser) error {
	inboundTag = strings.TrimSpace(inboundTag)
	if inboundTag == "" {
		return fmt.Errorf("inbound_tag is required")
	}
	if err := user.validate(); err != nil {
		return err
	}
	api, err := SharedAPI(apiPort)
	if err != nil {
		return classifyAPIError(err)
	}
	return classifyAPIError(api.AddUser(strings.ToLower(strings.TrimSpace(user.Protocol)), inboundTag, user.apiUser()))
}

func RemoveInboundUser(apiPort int, inboundTag string, email string) error {
	inboundTag = strings.TrimSpace(inboundTag)
	email = strings.TrimSpace(email)
	if inboundTag == "" {
		return fmt.Errorf("inbound_tag is required")
	}
	if email == "" {
		return fmt.Errorf("email is required")
	}
	api, err := SharedAPI(apiPort)
	if err != nil {
		return err
	}
	return classifyAPIError(api.RemoveUser(inboundTag, email))
}

func classifyAPIError(err error) error {
	if err == nil {
		return nil
	}
	if status.Code(err) == codes.Unavailable {
		return fmt.Errorf("%w: %v", ErrAPIUnavailable, err)
	}
	return err
}
