package xray

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"math"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/xtls/xray-core/app/proxyman"
	"github.com/xtls/xray-core/app/proxyman/command"
	"github.com/xtls/xray-core/app/router"
	routerService "github.com/xtls/xray-core/app/router/command"
	statsService "github.com/xtls/xray-core/app/stats/command"
	xnet "github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/platform/filesystem"
	"github.com/xtls/xray-core/common/protocol"
	"github.com/xtls/xray-core/common/serial"
	"github.com/xtls/xray-core/infra/conf"
	hysteriaAccount "github.com/xtls/xray-core/proxy/hysteria/account"
	"github.com/xtls/xray-core/proxy/masque"
	"github.com/xtls/xray-core/proxy/shadowsocks"
	"github.com/xtls/xray-core/proxy/shadowsocks_2022"
	"github.com/xtls/xray-core/proxy/trojan"
	"github.com/xtls/xray-core/proxy/tun"
	"github.com/xtls/xray-core/proxy/vless"
	vlessEncryption "github.com/xtls/xray-core/proxy/vless/encryption"
	vlessOutbound "github.com/xtls/xray-core/proxy/vless/outbound"
	"github.com/xtls/xray-core/proxy/vmess"
	wireguard "github.com/xtls/xray-core/proxy/wireguard"
	"github.com/xtls/xray-core/transport/internet/splithttp"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
)

var statsFamilies = []string{"user>>>", "inbound>>>", "outbound>>>"}

const maxStatsReplyBytes = 64 << 20

type XrayAPI struct {
	HandlerServiceClient *command.HandlerServiceClient
	StatsServiceClient   *statsService.StatsServiceClient
	RoutingServiceClient *routerService.RoutingServiceClient
	grpcClient           *grpc.ClientConn
	isConnected          bool
	StatsLastValues      map[string]int64
	statsBaselined       map[string]bool
}

func getRequiredUserString(user map[string]any, key string) (string, error) {
	value, ok := user[key]
	if !ok || value == nil {
		return "", fmt.Errorf("missing required user field %q", key)
	}

	strValue, ok := value.(string)
	if !ok {
		return "", fmt.Errorf("invalid type for user field %q: %T", key, value)
	}

	return strValue, nil
}

func getOptionalUserString(user map[string]any, key string) (string, error) {
	value, ok := user[key]
	if !ok || value == nil {
		return "", nil
	}

	strValue, ok := value.(string)
	if !ok {
		return "", fmt.Errorf("invalid type for user field %q: %T", key, value)
	}

	return strValue, nil
}

func (x *XrayAPI) Init(apiPort int) error {
	if apiPort <= 0 || apiPort > math.MaxUint16 {
		return fmt.Errorf("invalid Xray API port: %d", apiPort)
	}

	addr := fmt.Sprintf("127.0.0.1:%d", apiPort)
	conn, err := grpc.NewClient(addr,
		grpc.WithTransportCredentials(insecure.NewCredentials()),
		grpc.WithDefaultCallOptions(grpc.MaxCallRecvMsgSize(maxStatsReplyBytes)),
	)
	if err != nil {
		return fmt.Errorf("failed to connect to Xray API: %w", err)
	}

	x.grpcClient = conn
	x.isConnected = true
	if x.StatsLastValues == nil {
		x.StatsLastValues = make(map[string]int64)
		x.statsBaselined = make(map[string]bool, len(statsFamilies))
	}

	hsClient := command.NewHandlerServiceClient(conn)
	ssClient := statsService.NewStatsServiceClient(conn)
	rsClient := routerService.NewRoutingServiceClient(conn)

	x.HandlerServiceClient = &hsClient
	x.StatsServiceClient = &ssClient
	x.RoutingServiceClient = &rsClient

	return nil
}

func (x *XrayAPI) Close() {
	if x.grpcClient != nil {
		x.grpcClient.Close()
	}
	x.HandlerServiceClient = nil
	x.StatsServiceClient = nil
	x.RoutingServiceClient = nil
	x.isConnected = false
}

const handlerRPCTimeout = 10 * time.Second

func (x *XrayAPI) AddInbound(inbound []byte) error {
	if x.HandlerServiceClient == nil {
		return common.NewError("xray HandlerServiceClient is not initialized")
	}
	client := *x.HandlerServiceClient

	conf := new(conf.InboundDetourConfig)
	err := json.Unmarshal(inbound, conf)
	if err != nil {
		logger.Debug("Failed to unmarshal inbound:", err)
		return err
	}
	if err := checkUntrustedBuildInput(conf.StreamSetting, inbound); err != nil {
		return err
	}
	localizeNoiseScripts(conf.StreamSetting)
	config, err := conf.Build()
	if err != nil {
		logger.Debug("Failed to build inbound Detur:", err)
		return err
	}
	inboundConfig := command.AddInboundRequest{Inbound: config}

	ctx, cancel := context.WithTimeout(context.Background(), handlerRPCTimeout)
	defer cancel()
	_, err = client.AddInbound(ctx, &inboundConfig)

	return err
}

func (x *XrayAPI) DelInbound(tag string) error {
	if x.HandlerServiceClient == nil {
		return common.NewError("xray HandlerServiceClient is not initialized")
	}
	client := *x.HandlerServiceClient
	ctx, cancel := context.WithTimeout(context.Background(), handlerRPCTimeout)
	defer cancel()
	_, err := client.RemoveInbound(ctx, &command.RemoveInboundRequest{
		Tag: tag,
	})
	return err
}

func ValidateOutboundConfig(outbound []byte) (err error) {
	ensureXrayAssetLocation()
	defer func() {
		if r := recover(); r != nil {
			err = common.NewErrorf("xray-core config loader panicked: %v", r)
		}
	}()

	detour := new(conf.OutboundDetourConfig)
	if err := json.Unmarshal(outbound, detour); err != nil {
		return err
	}
	if err := checkUntrustedBuildInput(detour.StreamSetting, outbound); err != nil {
		return err
	}
	localizeNoiseScripts(detour.StreamSetting)
	built, err := detour.Build()
	if err != nil {
		return err
	}
	if err := validateXhttpDownloadSettings(built.SenderSettings); err != nil {
		return err
	}
	return validateHandlerSettings(built.ProxySettings)
}

func ValidateTunWfpBlockLeak(values []string) error {
	_, err := tun.ExpandWfpBlockLeak(values)
	return err
}

func ValidateXDriveS3(xdriveSettings []byte) error {
	c := new(conf.XDriveConfig)
	if err := json.Unmarshal(xdriveSettings, c); err != nil {
		return err
	}
	_, err := c.Build()
	return err
}

func validateXhttpDownloadSettings(settings *serial.TypedMessage) error {
	if settings == nil {
		return nil
	}
	instance, err := settings.GetInstance()
	if err != nil {
		return nil
	}
	sender, ok := instance.(*proxyman.SenderConfig)
	if !ok {
		return nil
	}
	transport, err := sender.StreamSettings.GetEffectiveTransportSettings()
	if err != nil {
		return nil
	}
	xhttp, ok := transport.(*splithttp.Config)
	if !ok || xhttp.DownloadSettings == nil {
		return nil
	}
	if xhttp.DownloadSettings.Address == nil {
		return common.NewError("xhttp downloadSettings has no address")
	}
	transport, _ = xhttp.DownloadSettings.GetEffectiveTransportSettings()
	if _, ok := transport.(*splithttp.Config); !ok {
		return common.NewError("xhttp downloadSettings network is not xhttp")
	}
	return nil
}

func validateHandlerSettings(settings *serial.TypedMessage) error {
	if settings == nil {
		return nil
	}
	instance, err := settings.GetInstance()
	if err != nil {
		return nil
	}
	switch config := instance.(type) {
	case *wireguard.DeviceConfig:
		return validateWireguardClient(config)
	case *vlessOutbound.Config:
		return validateVlessEncryption(config)
	case *shadowsocks_2022.ClientConfig:
		return validateShadowsocks2022Key(config)
	}
	return nil
}

func validateWireguardClient(device *wireguard.DeviceConfig) error {
	if !device.IsClient {
		return nil
	}
	if len(device.Peers) == 0 {
		return common.NewError("wireguard outbound has no peers")
	}
	for _, peer := range device.Peers {
		if peer.PublicKey == "" {
			return common.NewError("wireguard peer without publicKey")
		}
		if peer.Endpoint == "" {
			return common.NewError("wireguard peer without endpoint")
		}
	}
	for _, local := range device.Endpoint {
		if _, err := netip.ParseAddr(local); err == nil {
			continue
		}
		if _, err := netip.ParsePrefix(local); err != nil {
			return common.NewErrorf("wireguard address entry %q is neither an IP nor a prefix", local)
		}
	}
	for _, server := range device.DNS {
		if _, err := netip.ParseAddr(server); err != nil {
			return common.NewErrorf("wireguard remoteDNS entry %q is not an IP address", server)
		}
	}
	return nil
}

func validateVlessEncryption(config *vlessOutbound.Config) error {
	if config.Vnext == nil || config.Vnext.User == nil {
		return nil
	}
	user, err := config.Vnext.User.ToMemoryUser()
	if err != nil {
		return err
	}
	account, ok := user.Account.(*vless.MemoryAccount)
	if !ok || account.Encryption == "" || account.Encryption == "none" {
		return nil
	}
	var keys [][]byte
	for part := range strings.SplitSeq(account.Encryption, ".") {
		key, _ := base64.RawURLEncoding.DecodeString(part)
		keys = append(keys, key)
	}
	if err := (&vlessEncryption.ClientInstance{}).Init(keys, account.XorMode, account.Seconds, account.Padding); err != nil {
		return common.NewErrorf("vless encryption is unusable: %v", err)
	}
	return nil
}

func validateShadowsocks2022Key(config *shadowsocks_2022.ClientConfig) error {
	method, err := shadowsocks_2022.GetCipherMethod(config.Method)
	if err != nil {
		return err
	}
	keys, err := shadowsocks_2022.ParsePSKList(config.Key, method.KeySaltLength)
	if err != nil {
		return common.NewErrorf("shadowsocks 2022 key is unusable for %s: %v", config.Method, err)
	}
	if method.IsChaCha && len(keys) > 1 {
		return common.NewError("shadowsocks 2022 chacha20-poly1305 does not support multiple keys")
	}
	return nil
}

func (x *XrayAPI) AddOutbound(outbound []byte) error {
	if x.HandlerServiceClient == nil {
		return common.NewError("xray HandlerServiceClient is not initialized")
	}
	client := *x.HandlerServiceClient

	ensureXrayAssetLocation()

	conf := new(conf.OutboundDetourConfig)
	if err := json.Unmarshal(outbound, conf); err != nil {
		logger.Debug("Failed to unmarshal outbound:", err)
		return err
	}
	if err := checkUntrustedBuildInput(conf.StreamSetting, outbound); err != nil {
		return err
	}
	localizeNoiseScripts(conf.StreamSetting)
	config, err := conf.Build()
	if err != nil {
		logger.Debug("Failed to build outbound detour:", err)
		return err
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	_, err = client.AddOutbound(ctx, &command.AddOutboundRequest{Outbound: config})
	return err
}

func (x *XrayAPI) DelOutbound(tag string) error {
	if x.HandlerServiceClient == nil {
		return common.NewError("xray HandlerServiceClient is not initialized")
	}
	client := *x.HandlerServiceClient

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	_, err := client.RemoveOutbound(ctx, &command.RemoveOutboundRequest{Tag: tag})
	return err
}

func (x *XrayAPI) ApplyRoutingConfig(routing []byte) error {
	if x.RoutingServiceClient == nil {
		return common.NewError("xray RoutingServiceClient is not initialized")
	}

	config, err := buildReloadableRouting(routing)
	if err != nil {
		logger.Debug("Failed to build routing config:", err)
		return err
	}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	_, err = (*x.RoutingServiceClient).AddRule(ctx, &routerService.AddRuleRequest{
		ShouldAppend: false,
		Config:       serial.ToTypedMessage(config),
	})
	return err
}

func buildReloadableRouting(routing []byte) (*router.Config, error) {
	ensureXrayAssetLocation()

	routerConf := new(conf.RouterConfig)
	if err := json.Unmarshal(routing, routerConf); err != nil {
		return nil, err
	}
	routerConf.Script = ""
	return routerConf.Build()
}

type BalancerInfo struct {
	Tag      string   `json:"tag"`
	Override string   `json:"override"`
	Selected []string `json:"selected"`
}

func (x *XrayAPI) GetBalancerInfo(tag string) (*BalancerInfo, error) {
	if x.RoutingServiceClient == nil {
		return nil, common.NewError("xray RoutingServiceClient is not initialized")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	resp, err := (*x.RoutingServiceClient).GetBalancerInfo(ctx, &routerService.GetBalancerInfoRequest{Tag: tag})
	if err != nil {
		return nil, err
	}

	info := &BalancerInfo{Tag: tag}
	if balancer := resp.GetBalancer(); balancer != nil {
		if balancer.Override != nil {
			info.Override = balancer.Override.Target
		}
		if balancer.PrincipleTarget != nil {
			info.Selected = balancer.PrincipleTarget.Tag
		}
	}
	return info, nil
}

func (x *XrayAPI) SetBalancerTarget(tag, target string) error {
	if x.RoutingServiceClient == nil {
		return common.NewError("xray RoutingServiceClient is not initialized")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	_, err := (*x.RoutingServiceClient).OverrideBalancerTarget(ctx, &routerService.OverrideBalancerTargetRequest{
		BalancerTag: tag,
		Target:      target,
	})
	return err
}

type RouteTestRequest struct {
	InboundTag string // optional: simulate arrival on this inbound
	Domain     string // target domain (sniffed/SOCKS-style destination)
	IP         string // target IP, used when Domain is empty or alongside it
	Port       int
	Network    string // "tcp" (default) or "udp"
	Protocol   string // optional sniffed protocol: http, tls, bittorrent, ...
	Email      string // optional user attribution for user-based rules
}

type RouteTestResult struct {
	Matched     bool     `json:"matched"`
	OutboundTag string   `json:"outboundTag"`
	GroupTags   []string `json:"groupTags,omitempty"`
}

func (x *XrayAPI) TestRoute(req RouteTestRequest) (*RouteTestResult, error) {
	if x.RoutingServiceClient == nil {
		return nil, common.NewError("xray RoutingServiceClient is not initialized")
	}

	if req.Port < 0 || req.Port > math.MaxUint16 {
		return nil, common.NewErrorf("invalid port: %d", req.Port)
	}

	network := xnet.Network_TCP
	if strings.EqualFold(req.Network, "udp") {
		network = xnet.Network_UDP
	}
	rc := &routerService.RoutingContext{
		InboundTag:   req.InboundTag,
		Network:      network,
		TargetDomain: req.Domain,
		TargetPort:   uint32(req.Port),
		Protocol:     req.Protocol,
		User:         req.Email,
	}
	if req.IP != "" {
		parsed := net.ParseIP(req.IP)
		if parsed == nil {
			return nil, common.NewErrorf("invalid IP address: %s", req.IP)
		}
		if v4 := parsed.To4(); v4 != nil {
			rc.TargetIPs = [][]byte{v4}
		} else {
			rc.TargetIPs = [][]byte{parsed.To16()}
		}
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	resp, err := (*x.RoutingServiceClient).TestRoute(ctx, &routerService.TestRouteRequest{
		RoutingContext: rc,
		PublishResult:  false,
	})
	if err != nil {
		if strings.Contains(strings.ToLower(err.Error()), "not enough information") {
			return &RouteTestResult{Matched: false}, nil
		}
		return nil, err
	}

	return &RouteTestResult{
		Matched:     true,
		OutboundTag: resp.GetOutboundTag(),
		GroupTags:   resp.GetOutboundGroupTags(),
	}, nil
}

func IsMissingHandlerErr(err error) bool {
	if err == nil {
		return false
	}
	msg := strings.ToLower(err.Error())
	return strings.Contains(msg, "not found") ||
		strings.Contains(msg, "not enough information")
}

func IsMissingUserErr(err error) bool {
	if err == nil {
		return false
	}
	msg := strings.ToLower(err.Error())
	return strings.Contains(msg, "not found") && !strings.Contains(msg, "failed to get handler")
}

func IsExistingTagErr(err error) bool {
	if err == nil {
		return false
	}
	return strings.Contains(strings.ToLower(err.Error()), "existing tag")
}

func IsUserExistsErr(err error) bool {
	if err == nil {
		return false
	}
	return strings.Contains(strings.ToLower(err.Error()), "already exists")
}

func localizeNoiseScripts(stream *conf.StreamConfig) {
	if stream == nil || stream.FinalMask == nil {
		return
	}
	for i := range stream.FinalMask.Udp {
		mask := &stream.FinalMask.Udp[i]
		if !strings.EqualFold(mask.Type, "noise") || mask.Settings == nil {
			continue
		}
		var settings map[string]any
		if json.Unmarshal(*mask.Settings, &settings) != nil {
			continue
		}
		script, _ := settings["script"].(string)
		resolved := childLuaScriptPath(script)
		if resolved == script {
			continue
		}
		settings["script"] = resolved
		if raw, err := json.Marshal(settings); err == nil {
			localized := json.RawMessage(raw)
			mask.Settings = &localized
		}
	}
}

func childLuaScriptPath(script string) string {
	if script == "" || filepath.IsAbs(script) {
		return script
	}
	if _, err := filesystem.ResolveLuaFile(script); err == nil {
		return script
	}
	binDir, err := filepath.Abs(config.GetBinFolderPath())
	if err != nil {
		return script
	}
	inBin := filepath.Join(binDir, script)
	if _, err := os.Stat(inBin); err != nil {
		return script
	}
	return inBin
}

func ensureXrayAssetLocation() {
	if os.Getenv("XRAY_LOCATION_ASSET") != "" || os.Getenv("xray.location.asset") != "" {
		return
	}
	if abs, err := filepath.Abs(config.GetBinFolderPath()); err == nil {
		os.Setenv("XRAY_LOCATION_ASSET", abs)
	}
}

func collectStringSlice(value any) []string {
	switch v := value.(type) {
	case []string:
		out := make([]string, 0, len(v))
		for _, s := range v {
			if s != "" {
				out = append(out, s)
			}
		}
		return out
	case []any:
		out := make([]string, 0, len(v))
		for _, e := range v {
			if s, ok := e.(string); ok && s != "" {
				out = append(out, s)
			}
		}
		return out
	default:
		return nil
	}
}

const legacyShadowsocksAccountType = "xray.proxy.shadowsocks.Account"

var shadowsocks2022Ciphers = map[string]struct{}{
	"2022-blake3-aes-128-gcm":       {},
	"2022-blake3-aes-256-gcm":       {},
	"2022-blake3-chacha20-poly1305": {},
}

func shadowsocksCipherName(user map[string]any) (string, error) {
	cipher, err := getOptionalUserString(user, "cipher")
	if err != nil {
		return "", err
	}
	if cipher != "" {
		return cipher, nil
	}
	return getOptionalUserString(user, "method")
}

func reverseTag(value any) string {
	if value == nil {
		return ""
	}
	raw, err := json.Marshal(value)
	if err != nil {
		return ""
	}
	var parsed struct {
		Tag string `json:"tag"`
	}
	if json.Unmarshal(raw, &parsed) != nil {
		return ""
	}
	return parsed.Tag
}

func shadowsocksCipherType(cipher string) shadowsocks.CipherType {
	switch strings.ToLower(cipher) {
	case "aes-128-gcm", "aead_aes_128_gcm":
		return shadowsocks.CipherType_AES_128_GCM
	case "aes-256-gcm", "aead_aes_256_gcm":
		return shadowsocks.CipherType_AES_256_GCM
	case "chacha20-poly1305", "aead_chacha20_poly1305", "chacha20-ietf-poly1305":
		return shadowsocks.CipherType_CHACHA20_POLY1305
	case "xchacha20-poly1305", "aead_xchacha20_poly1305", "xchacha20-ietf-poly1305":
		return shadowsocks.CipherType_XCHACHA20_POLY1305
	default:
		return shadowsocks.CipherType_UNKNOWN
	}
}

func isShadowsocks2022Cipher(cipher string) bool {
	_, ok := shadowsocks2022Ciphers[strings.ToLower(cipher)]
	return ok
}

func buildUserAccount(protocolName string, user map[string]any) (*serial.TypedMessage, error) {
	switch protocolName {
	case "vmess":
		userID, err := getRequiredUserString(user, "id")
		if err != nil {
			return nil, err
		}

		return serial.ToTypedMessage(&vmess.Account{
			Id: userID,
		}), nil
	case "vless":
		userID, err := getRequiredUserString(user, "id")
		if err != nil {
			return nil, err
		}

		userFlow, err := getOptionalUserString(user, "flow")
		if err != nil {
			return nil, err
		}

		vlessAccount := &vless.Account{
			Id:   userID,
			Flow: userFlow,
		}
		if tag := reverseTag(user["reverse"]); tag != "" {
			vlessAccount.Reverse = &vless.Reverse{Tag: tag}
		}
		if testseedVal, ok := user["testseed"]; ok {
			if testseedArr, ok := testseedVal.([]any); ok && len(testseedArr) >= 4 {
				testseed := make([]uint32, len(testseedArr))
				for i, v := range testseedArr {
					if num, ok := v.(float64); ok {
						testseed[i] = uint32(num)
					}
				}
				vlessAccount.Testseed = testseed
			} else if testseedArr, ok := testseedVal.([]uint32); ok && len(testseedArr) >= 4 {
				vlessAccount.Testseed = testseedArr
			}
		}
		if testpreVal, ok := user["testpre"]; ok {
			if testpre, ok := testpreVal.(float64); ok && testpre > 0 {
				vlessAccount.Testpre = uint32(testpre)
			} else if testpre, ok := testpreVal.(uint32); ok && testpre > 0 {
				vlessAccount.Testpre = testpre
			}
		}
		return serial.ToTypedMessage(vlessAccount), nil
	case "trojan":
		password, err := getRequiredUserString(user, "password")
		if err != nil {
			return nil, err
		}

		return serial.ToTypedMessage(&trojan.Account{
			Password: password,
		}), nil
	case "shadowsocks":
		cipher, err := shadowsocksCipherName(user)
		if err != nil {
			return nil, err
		}

		password, err := getRequiredUserString(user, "password")
		if err != nil {
			return nil, err
		}

		if isShadowsocks2022Cipher(cipher) {
			return serial.ToTypedMessage(&shadowsocks_2022.Account{
				Key: password,
			}), nil
		}

		ssCipherType := shadowsocksCipherType(cipher)
		if ssCipherType == shadowsocks.CipherType_UNKNOWN {
			return nil, common.NewErrorf("shadowsocks: unknown cipher %q, cannot build an account for the running inbound", cipher)
		}
		return serial.ToTypedMessage(&shadowsocks.Account{
			Password:   password,
			CipherType: ssCipherType,
		}), nil
	case "hysteria":
		auth, err := getRequiredUserString(user, "auth")
		if err != nil {
			return nil, err
		}

		return serial.ToTypedMessage(&hysteriaAccount.Account{
			Auth: auth,
		}), nil
	case "masque":
		pass, err := masqueUserPassword(user)
		if err != nil {
			return nil, err
		}

		return serial.ToTypedMessage(&masque.Account{
			Password: pass,
		}), nil
	case "wireguard":
		pubB64, err := getRequiredUserString(user, "publicKey")
		if err != nil {
			return nil, err
		}
		pubHex, err := wgutil.KeyToHex(pubB64)
		if err != nil {
			return nil, fmt.Errorf("wireguard publicKey: %w", err)
		}

		pskB64, err := getOptionalUserString(user, "preSharedKey")
		if err != nil {
			return nil, err
		}
		pskHex, err := wgutil.KeyToHex(pskB64)
		if err != nil {
			return nil, fmt.Errorf("wireguard preSharedKey: %w", err)
		}

		allowed := collectStringSlice(user["allowedIPs"])
		if len(allowed) == 0 {
			return nil, common.NewError("wireguard: allowedIPs required")
		}

		keepAlive, err := getOptionalUserString(user, "keepAlive")
		if err != nil {
			return nil, err
		}

		return serial.ToTypedMessage(&wireguard.PeerConfig{
			PublicKey:    pubHex,
			PreSharedKey: pskHex,
			AllowedIps:   allowed,
			KeepAlive:    keepAlive,
		}), nil
	default:
		return nil, nil
	}
}

func masqueUserPassword(user map[string]any) (string, error) {
	if pass, err := getOptionalUserString(user, "pass"); err != nil || pass != "" {
		return pass, err
	}
	return getRequiredUserString(user, "password")
}

func (x *XrayAPI) AddUser(Protocol string, inboundTag string, user map[string]any) error {
	userEmail, err := getRequiredUserString(user, "email")
	if err != nil {
		return err
	}

	account, err := buildUserAccount(Protocol, user)
	if err != nil {
		return err
	}
	if account == nil {
		return nil
	}

	if x.HandlerServiceClient == nil {
		return common.NewError("xray HandlerServiceClient is not initialized")
	}
	client := *x.HandlerServiceClient

	if account.Type == legacyShadowsocksAccountType {
		_ = x.RemoveUser(inboundTag, userEmail)
	}

	ctx, cancel := context.WithTimeout(context.Background(), handlerRPCTimeout)
	defer cancel()
	_, err = client.AlterInbound(ctx, &command.AlterInboundRequest{
		Tag: inboundTag,
		Operation: serial.ToTypedMessage(&command.AddUserOperation{
			User: &protocol.User{
				Email:   userEmail,
				Account: account,
			},
		}),
	})
	return err
}

func (x *XrayAPI) RemoveUser(inboundTag, email string) error {
	if x.HandlerServiceClient == nil {
		return common.NewError("xray HandlerServiceClient is not initialized")
	}
	client := *x.HandlerServiceClient

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	op := &command.RemoveUserOperation{Email: email}
	req := &command.AlterInboundRequest{
		Tag:       inboundTag,
		Operation: serial.ToTypedMessage(op),
	}

	_, err := client.AlterInbound(ctx, req)
	if err != nil {
		return fmt.Errorf("failed to remove user: %w", err)
	}

	return nil
}
