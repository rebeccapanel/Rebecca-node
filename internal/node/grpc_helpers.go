package node

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"strings"
	"time"

	nodev1 "github.com/rebeccapanel/rebecca-node/internal/proto/node/v1"
	"github.com/rebeccapanel/rebecca-node/internal/xray"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

func (api *grpcAPI) PublicIPs(ctx context.Context, _ *nodev1.PublicIPsRequest) (*nodev1.PublicIPsResponse, error) {
	return &nodev1.PublicIPsResponse{
		Ipv4: publicIPv4(ctx),
		Ipv6: publicIPv6(ctx),
	}, nil
}

func (api *grpcAPI) TestOutbound(ctx context.Context, req *nodev1.OutboundTestRequest) (*nodev1.OutboundTestResponse, error) {
	var allOutbounds []map[string]any
	rawOutbounds := strings.TrimSpace(req.GetAllOutboundsJson())
	if rawOutbounds == "" {
		return nil, status.Error(codes.InvalidArgument, "all_outbounds_json is required")
	}
	if err := json.Unmarshal([]byte(rawOutbounds), &allOutbounds); err != nil {
		return nil, status.Error(codes.InvalidArgument, fmt.Sprintf("invalid all_outbounds_json: %v", err))
	}
	result := api.server.core.TestOutbound(
		ctx,
		req.GetOutboundTag(),
		req.GetOutboundProtocol(),
		allOutbounds,
		req.GetTestUrl(),
		req.GetTestType(),
	)
	return &nodev1.OutboundTestResponse{
		Success:    result.Success,
		Delay:      result.Delay,
		StatusCode: int32(result.StatusCode),
		Error:      result.Error,
		TestType:   result.TestType,
		Address:    result.Address,
		Port:       int32(result.Port),
		Output:     result.Output,
	}, nil
}

func (api *grpcAPI) TestRoute(ctx context.Context, req *nodev1.RouteTestRequest) (*nodev1.RouteTestResponse, error) {
	if strings.TrimSpace(req.GetConfigJson()) == "" || strings.TrimSpace(req.GetTestUrl()) == "" {
		return nil, status.Error(codes.InvalidArgument, "config_json and test_url are required")
	}
	result := api.server.core.TestRoute(
		ctx,
		req.GetConfigJson(),
		req.GetInboundTag(),
		req.GetTestUrl(),
		xray.RouteTestRequest{
			InboundTag: req.GetInboundTag(),
			Domain:     req.GetDomain(),
			IP:         req.GetIp(),
			Port:       int(req.GetPort()),
			Network:    req.GetNetwork(),
			Protocol:   req.GetProtocol(),
			Email:      req.GetEmail(),
		},
	)
	traffic := make([]*nodev1.RouteTestTraffic, 0, len(result.OutboundTraffic))
	for _, item := range result.OutboundTraffic {
		traffic = append(traffic, &nodev1.RouteTestTraffic{Tag: item.Tag, Up: item.Up, Down: item.Down})
	}
	return &nodev1.RouteTestResponse{
		Matched:         result.Matched,
		OutboundTag:     result.OutboundTag,
		GroupTags:       result.GroupTags,
		Success:         result.Success,
		Delay:           result.Delay,
		StatusCode:      int32(result.StatusCode),
		OutboundTraffic: traffic,
		Error:           result.Error,
	}, nil
}

func publicIPv4(ctx context.Context) string {
	for _, endpoint := range []string{
		"http://api4.ipify.org/",
		"http://ipv4.icanhazip.com/",
		"https://ifconfig.io/ip",
	} {
		if ip := fetchPublicIP(ctx, endpoint, true); ip != "" {
			return ip
		}
	}
	if ip := localOutboundIPv4(); ip != "" {
		return ip
	}
	return "127.0.0.1"
}

func publicIPv6(ctx context.Context) string {
	for _, endpoint := range []string{
		"http://api6.ipify.org/",
		"http://ipv6.icanhazip.com/",
	} {
		if ip := fetchPublicIP(ctx, endpoint, false); ip != "" {
			return "[" + ip + "]"
		}
	}
	return "[::1]"
}

func fetchPublicIP(ctx context.Context, endpoint string, wantIPv4 bool) string {
	requestCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	request, err := http.NewRequestWithContext(requestCtx, http.MethodGet, endpoint, nil)
	if err != nil {
		return ""
	}
	response, err := http.DefaultClient.Do(request)
	if err != nil {
		return ""
	}
	defer response.Body.Close()
	if response.StatusCode < 200 || response.StatusCode >= 300 {
		return ""
	}
	body, err := io.ReadAll(io.LimitReader(response.Body, 128))
	if err != nil {
		return ""
	}
	candidate := strings.TrimSpace(string(body))
	if isGlobalIP(candidate, wantIPv4) {
		return strings.Trim(candidate, "[]")
	}
	return ""
}

func isGlobalIP(value string, wantIPv4 bool) bool {
	addr, err := netip.ParseAddr(strings.Trim(strings.TrimSpace(value), "[]"))
	if err != nil {
		return false
	}
	if wantIPv4 && !addr.Is4() {
		return false
	}
	if !wantIPv4 && !addr.Is6() {
		return false
	}
	return addr.IsGlobalUnicast() &&
		!addr.IsPrivate() &&
		!addr.IsLoopback() &&
		!addr.IsLinkLocalUnicast() &&
		!addr.IsMulticast() &&
		!addr.IsUnspecified()
}

func localOutboundIPv4() string {
	conn, err := net.DialTimeout("udp4", "8.8.8.8:80", 2*time.Second)
	if err != nil {
		return ""
	}
	defer conn.Close()
	addr, ok := conn.LocalAddr().(*net.UDPAddr)
	if !ok || addr.IP == nil {
		return ""
	}
	if isGlobalIP(addr.IP.String(), true) {
		return addr.IP.String()
	}
	return ""
}
