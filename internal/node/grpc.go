package node

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	appconfig "github.com/rebeccapanel/rebecca-node/internal/config"
	nodev1 "github.com/rebeccapanel/rebecca-node/internal/proto/node/v1"
	"github.com/rebeccapanel/rebecca-node/internal/xray"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/peer"
	"google.golang.org/grpc/status"
)

const grpcOperationTimeout = 60 * time.Second

type grpcAPI struct {
	nodev1.UnimplementedNodeControlServiceServer
	nodev1.UnimplementedNodeRuntimeServiceServer
	nodev1.UnimplementedNodeUsageServiceServer
	nodev1.UnimplementedNodeLogsServiceServer

	server *Server
}

func (s *Server) ListenAndServeGRPC() error {
	tlsConfig, err := loadGRPCServerTLS(s.settings)
	if err != nil {
		return err
	}

	listener, err := net.Listen("tcp", net.JoinHostPort(s.settings.ServiceHost, strconv.Itoa(s.settings.ServicePort)))
	if err != nil {
		return err
	}

	grpcServer := grpc.NewServer(
		grpc.Creds(credentials.NewTLS(tlsConfig)),
		grpc.ChainUnaryInterceptor(s.sessionUnaryInterceptor, s.operations.unaryServerInterceptor),
		grpc.MaxRecvMsgSize(64<<20),
		grpc.MaxSendMsgSize(64<<20),
	)
	s.registerGRPC(grpcServer)
	go s.notifyMasterReady()
	return grpcServer.Serve(listener)
}

func (s *Server) sessionUnaryInterceptor(ctx context.Context, req any, _ *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (any, error) {
	peerIP := grpcPeerIP(ctx)
	s.addSession("grpc:"+peerIP, peerIP)
	return handler(ctx, req)
}

func (s *Server) registerGRPC(grpcServer *grpc.Server) {
	api := &grpcAPI{server: s}
	nodev1.RegisterNodeControlServiceServer(grpcServer, api)
	nodev1.RegisterNodeRuntimeServiceServer(grpcServer, api)
	nodev1.RegisterNodeUsageServiceServer(grpcServer, api)
	nodev1.RegisterNodeLogsServiceServer(grpcServer, api)
}

func loadGRPCServerTLS(settings appconfig.Settings) (*tls.Config, error) {
	if settings.SSLCertFile == "" || settings.SSLKeyFile == "" {
		return nil, errors.New("SSL_CERT_FILE and SSL_KEY_FILE are required for gRPC")
	}
	if strings.TrimSpace(settings.SSLClientCertFile) == "" || !fileExists(settings.SSLClientCertFile) {
		return nil, errors.New("SSL_CLIENT_CERT_FILE is required for gRPC client authentication")
	}

	cert, err := tls.LoadX509KeyPair(settings.SSLCertFile, settings.SSLKeyFile)
	if err != nil {
		return nil, fmt.Errorf("load gRPC server certificate: %w", err)
	}
	config := &tls.Config{
		Certificates: []tls.Certificate{cert},
		MinVersion:   tls.VersionTLS12,
	}
	clientCAPEM, err := os.ReadFile(settings.SSLClientCertFile)
	if err != nil {
		return nil, fmt.Errorf("read gRPC client certificate: %w", err)
	}
	clientCAs := x509.NewCertPool()
	if !clientCAs.AppendCertsFromPEM(clientCAPEM) {
		return nil, errors.New("failed to load SSL_CLIENT_CERT_FILE for gRPC")
	}
	config.ClientCAs = clientCAs
	config.ClientAuth = tls.RequireAndVerifyClientCert
	return config, nil
}

func (api *grpcAPI) Hello(ctx context.Context, _ *nodev1.HelloRequest) (*nodev1.HelloResponse, error) {
	return &nodev1.HelloResponse{
		NodeName:      api.server.settings.AppName,
		NodeVersion:   api.server.nodeVersion(),
		InstallMode:   api.server.settings.InstallMode,
		UpdateChannel: api.server.updateChannel(),
		Runtime:       api.server.grpcRuntimeState("hello"),
	}, nil
}

func (api *grpcAPI) Connect(ctx context.Context, _ *nodev1.ConnectRequest) (*nodev1.ConnectResponse, error) {
	connectionID, err := newUUID()
	if err != nil {
		return nil, status.Error(codes.Internal, err.Error())
	}
	api.server.addSession(connectionID, grpcPeerIP(ctx))
	return &nodev1.ConnectResponse{
		ConnectionId: connectionID,
		Runtime:      api.server.grpcRuntimeState("connected"),
	}, nil
}

func (api *grpcAPI) Health(ctx context.Context, req *nodev1.HealthRequest) (*nodev1.HealthResponse, error) {
	res := &nodev1.HealthResponse{Runtime: api.server.grpcRuntimeState("healthy")}
	if req.GetIncludeMetrics() {
		res.Metrics = api.server.grpcMetrics("healthy")
	}
	return res, nil
}

func (api *grpcAPI) StartRuntime(ctx context.Context, req *nodev1.RuntimeConfigRequest) (*nodev1.RuntimeActionResponse, error) {
	api.server.runtimeMu.Lock()
	defer api.server.runtimeMu.Unlock()
	if err := api.server.validateDesiredRevision(req); err != nil {
		return nil, err
	}
	var response *nodev1.RuntimeActionResponse
	var err error
	if api.server.core.Started() {
		if api.server.runtimeConfigMatchesCache(req.GetConfigJson()) {
			response, err = api.server.grpcApplyRuntimeOnly(ctx, req, "runtime already started")
		} else {
			response, err = api.server.grpcRestartRuntime(ctx, req, "runtime restarted")
		}
	} else {
		response, err = api.server.grpcStartRuntime(ctx, req, false)
	}
	api.server.recordAppliedRevision(req, err)
	return response, err
}

func (api *grpcAPI) RestartRuntime(ctx context.Context, req *nodev1.RuntimeConfigRequest) (*nodev1.RuntimeActionResponse, error) {
	api.server.runtimeMu.Lock()
	defer api.server.runtimeMu.Unlock()
	if err := api.server.validateDesiredRevision(req); err != nil {
		return nil, err
	}
	response, err := api.server.grpcRestartRuntime(ctx, req, "runtime restarted")
	api.server.recordAppliedRevision(req, err)
	return response, err
}

func (api *grpcAPI) StopRuntime(ctx context.Context, req *nodev1.StopRuntimeRequest) (*nodev1.RuntimeActionResponse, error) {
	api.server.runtimeMu.Lock()
	defer api.server.runtimeMu.Unlock()
	if req.GetCollectUsageBeforeStop() {
		api.server.snapshotRunningUsage()
	}
	api.server.core.Stop()
	if err := api.server.ov.Apply(&ovRuntime{Inbounds: []ovRuntimeInbound{}}); err != nil {
		return nil, status.Error(codes.Unavailable, err.Error())
	}
	if err := api.server.l2tp.Apply(&l2tpRuntime{Inbounds: []l2tpRuntimeInbound{}}); err != nil {
		return nil, status.Error(codes.Unavailable, err.Error())
	}
	if err := api.server.pptp.Apply(&pptpRuntime{Inbounds: []pptpRuntimeInbound{}}); err != nil {
		return nil, status.Error(codes.Unavailable, err.Error())
	}
	if err := api.server.wg.Apply(&wgRuntime{Inbounds: []wgRuntimeInbound{}}); err != nil {
		log.Printf("WireGuard runtime stop failed: %v", err)
	}
	if err := api.server.remoteAccess.ApplyIKEv2(&remoteAccessRuntime{Inbounds: []remoteAccessRuntimeInbound{}}); err != nil {
		log.Printf("IKEv2 runtime stop failed: %v", err)
	}
	if err := api.server.remoteAccess.ApplyAnyConnect(&remoteAccessRuntime{Inbounds: []remoteAccessRuntimeInbound{}}); err != nil {
		log.Printf("AnyConnect runtime stop failed: %v", err)
	}
	if api.server.haproxy != nil {
		if err := api.server.haproxy.Apply(&haproxyRuntime{}); err != nil {
			log.Printf("HAProxy runtime stop failed: %v", err)
		}
	}
	if api.server.sshProxy != nil {
		if err := api.server.sshProxy.Apply(&extraRuntime{}); err != nil {
			log.Printf("SSH runtime stop failed: %v", err)
		}
	}
	if api.server.external != nil {
		if err := api.server.external.Apply(&extraRuntime{}); err != nil {
			log.Printf("external proxy runtime stop failed: %v", err)
		}
	}
	if api.server.extraVPN != nil {
		if err := api.server.extraVPN.Apply(&extraRuntime{}); err != nil {
			log.Printf("extra VPN runtime stop failed: %v", err)
		}
	}
	if err := api.server.ipBlocks.Clear(ctx); err != nil {
		log.Printf("source IP block cleanup failed: %v", err)
	}
	api.server.clearConfigCache()
	return api.server.grpcAction(req.GetOperationId(), true, "runtime stopped"), nil
}

func (api *grpcAPI) SyncConfig(ctx context.Context, req *nodev1.RuntimeConfigRequest) (*nodev1.RuntimeActionResponse, error) {
	api.server.runtimeMu.Lock()
	defer api.server.runtimeMu.Unlock()
	if err := api.server.validateDesiredRevision(req); err != nil {
		return nil, err
	}
	if err := api.server.reconcileManagedProxyServices(ctx, req.GetConfigJson()); err != nil {
		return nil, status.Error(codes.FailedPrecondition, err.Error())
	}
	var response *nodev1.RuntimeActionResponse
	var err error
	if api.server.core.Started() {
		if api.server.runtimeConfigMatchesCache(req.GetConfigJson()) || api.server.runtimeTopologyMatchesCache(req.GetConfigJson()) {
			response, err = api.server.grpcApplyRuntimeOnly(ctx, req, "runtime config synced")
		} else {
			response, err = api.server.grpcRestartRuntime(ctx, req, "runtime config synced")
		}
	} else {
		response, err = api.server.grpcStartRuntime(ctx, req, true)
	}
	api.server.recordAppliedRevision(req, err)
	return response, err
}

func (api *grpcAPI) AddUser(ctx context.Context, req *nodev1.InboundUserRequest) (*nodev1.RuntimeActionResponse, error) {
	api.server.runtimeMu.Lock()
	defer api.server.runtimeMu.Unlock()
	return api.server.grpcAddUser(req, "user added")
}

func (api *grpcAPI) UpdateUser(ctx context.Context, req *nodev1.InboundUserRequest) (*nodev1.RuntimeActionResponse, error) {
	api.server.runtimeMu.Lock()
	defer api.server.runtimeMu.Unlock()
	if !api.server.core.Started() {
		return nil, status.Error(codes.FailedPrecondition, "Xray is not started")
	}
	inboundTag := strings.TrimSpace(req.GetInboundTag())
	user, err := protoInboundUser(req.GetUser())
	if err != nil {
		return nil, status.Error(codes.InvalidArgument, err.Error())
	}
	previous, exists, cacheAvailable, err := api.server.cachedConfigUser(inboundTag, user.Email)
	if err != nil {
		return nil, status.Error(codes.Unavailable, err.Error())
	}
	if !cacheAvailable {
		return nil, status.Error(codes.FailedPrecondition, "runtime config cache is unavailable; sync config first")
	}
	diff := configUserDiffResult{}
	if exists {
		diff.update = append(diff.update, configUserUpdate{inboundTag: inboundTag, previous: previous, current: user})
	} else {
		diff.add = append(diff.add, configUserAdd{inboundTag: inboundTag, user: user})
	}
	if err := api.server.applyConfigUserDiffResult(diff); err != nil {
		return nil, status.Error(codes.Unavailable, err.Error())
	}
	if err := api.server.addUserToConfigCache(inboundTag, user); err != nil {
		return nil, status.Error(codes.Unavailable, err.Error())
	}
	return api.server.grpcAction(req.GetOperationId(), true, "user updated"), nil
}

func (api *grpcAPI) RemoveUser(ctx context.Context, req *nodev1.RemoveInboundUserRequest) (*nodev1.RuntimeActionResponse, error) {
	api.server.runtimeMu.Lock()
	defer api.server.runtimeMu.Unlock()
	if !api.server.core.Started() {
		return nil, status.Error(codes.FailedPrecondition, "Xray is not started")
	}
	inboundTag := strings.TrimSpace(req.GetInboundTag())
	email := strings.TrimSpace(req.GetEmail())
	if inboundTag == "" {
		return nil, status.Error(codes.InvalidArgument, "inbound_tag is required")
	}
	if email == "" {
		return nil, status.Error(codes.InvalidArgument, "email is required")
	}
	if err := xray.RemoveInboundUser(
		api.server.settings.XrayAPIHost,
		api.server.settings.XrayAPIPort,
		grpcOperationTimeout,
		inboundTag,
		email,
	); err != nil {
		if !isIgnorableXrayRemoveError(err) {
			return nil, status.Error(codes.Unavailable, err.Error())
		}
	}
	if err := api.server.removeUserFromConfigCache(inboundTag, email); err != nil {
		return nil, status.Error(codes.Unavailable, err.Error())
	}
	return api.server.grpcAction(req.GetOperationId(), true, "user removed"), nil
}

func (api *grpcAPI) Metrics(ctx context.Context, _ *nodev1.MetricsRequest) (*nodev1.MetricsResponse, error) {
	return api.server.grpcMetrics("metrics"), nil
}

func (api *grpcAPI) UpdateRuntime(ctx context.Context, req *nodev1.RuntimeUpdateRequest) (*nodev1.RuntimeActionResponse, error) {
	api.server.runtimeMu.Lock()
	defer api.server.runtimeMu.Unlock()
	if err := api.server.grpcUpdateRuntime(req.GetVersion()); err != nil {
		return nil, err
	}
	return api.server.grpcAction(req.GetOperationId(), true, "runtime updated"), nil
}

func (api *grpcAPI) UpdateGeo(ctx context.Context, req *nodev1.GeoUpdateRequest) (*nodev1.RuntimeActionResponse, error) {
	api.server.runtimeMu.Lock()
	defer api.server.runtimeMu.Unlock()
	files := make([]downloadFile, 0, len(req.GetFiles()))
	for _, file := range req.GetFiles() {
		files = append(files, downloadFile{Name: file.GetName(), URL: file.GetUrl()})
	}
	if err := api.server.grpcUpdateGeo(files); err != nil {
		return nil, err
	}
	return api.server.grpcAction(req.GetOperationId(), true, "geo assets updated"), nil
}

func (api *grpcAPI) RestartService(ctx context.Context, req *nodev1.ServiceRestartRequest) (*nodev1.RuntimeActionResponse, error) {
	if err := api.server.scheduleNodeCLI("restart", "-n"); err != nil {
		return nil, status.Error(codes.Internal, err.Error())
	}
	return api.server.grpcAction(req.GetOperationId(), true, "service restart scheduled"), nil
}

func (api *grpcAPI) UpdateService(ctx context.Context, req *nodev1.ServiceUpdateRequest) (*nodev1.RuntimeActionResponse, error) {
	args, err := nodeUpdateArgs(req.GetChannel(), req.GetVersion())
	if err != nil {
		return nil, status.Error(codes.InvalidArgument, err.Error())
	}
	if err := api.server.scheduleNodeCLI(args...); err != nil {
		return nil, status.Error(codes.Internal, err.Error())
	}
	return api.server.grpcAction(req.GetOperationId(), true, "service update scheduled"), nil
}

func (api *grpcAPI) RebootHost(ctx context.Context, req *nodev1.HostRebootRequest) (*nodev1.RuntimeActionResponse, error) {
	if err := scheduleHostReboot(); err != nil {
		return nil, status.Error(codes.Internal, err.Error())
	}
	return api.server.grpcAction(req.GetOperationId(), true, "host reboot scheduled"), nil
}

func (api *grpcAPI) ApplyIPBlocks(ctx context.Context, req *nodev1.IPBlockRequest) (*nodev1.RuntimeActionResponse, error) {
	if req == nil {
		req = &nodev1.IPBlockRequest{}
	}
	blocks := make([]sourceIPBlockEntry, 0, len(req.GetBlocks()))
	for _, block := range req.GetBlocks() {
		if block == nil {
			continue
		}
		blocks = append(blocks, sourceIPBlockEntry{
			IP:         block.GetIp(),
			TTLSeconds: block.GetTtlSeconds(),
			UserUID:    block.GetUserUid(),
			Reason:     block.GetReason(),
		})
	}
	var ports sourceIPBlockPorts
	if len(blocks) > 0 {
		var err error
		ports, err = api.server.sourceIPBlockPorts(req.GetTcpPorts(), req.GetUdpPorts())
		if err != nil {
			return nil, status.Error(codes.InvalidArgument, err.Error())
		}
	}
	if err := api.server.ipBlocks.Apply(ctx, blocks, ports, api.server.protectedSourceIPs()); err != nil {
		return nil, status.Error(codes.Unavailable, err.Error())
	}
	return api.server.grpcAction(req.GetOperationId(), true, "IP blocks applied"), nil
}

func (api *grpcAPI) ApplyTorProxy(ctx context.Context, req *nodev1.TorProxyRequest) (*nodev1.RuntimeActionResponse, error) {
	if req == nil {
		return nil, status.Error(codes.InvalidArgument, "tor proxy request is required")
	}
	if err := applyTorProxy(torProxyConfig{
		SocksPort:   req.GetSocksPort(),
		ExitCountry: req.GetExitCountry(),
		StrictExit:  req.GetStrictExit(),
	}); err != nil {
		if strings.Contains(strings.ToLower(err.Error()), "must be") ||
			strings.Contains(strings.ToLower(err.Error()), "required") ||
			strings.Contains(strings.ToLower(err.Error()), "supported") {
			return nil, status.Error(codes.InvalidArgument, err.Error())
		}
		return nil, status.Error(codes.Unavailable, err.Error())
	}
	return api.server.grpcAction(req.GetOperationId(), true, "Tor proxy applied"), nil
}

func (api *grpcAPI) ConfigureWindscribe(ctx context.Context, req *nodev1.WindscribeProxyRequest) (*nodev1.WindscribeProxyResponse, error) {
	if req == nil {
		return nil, status.Error(codes.InvalidArgument, "Windscribe proxy request is required")
	}
	locations, err := configureWindscribe(ctx, windscribeProxyConfig{
		Action:        req.GetAction(),
		Username:      req.GetUsername(),
		Password:      req.GetPassword(),
		Location:      req.GetLocation(),
		SocksPort:     req.GetSocksPort(),
		ProxyUsername: req.GetProxyUsername(),
		ProxyPassword: req.GetProxyPassword(),
	})
	if err != nil {
		return nil, status.Error(codes.FailedPrecondition, err.Error())
	}
	responseLocations := make([]*nodev1.WindscribeLocation, 0, len(locations))
	for _, location := range locations {
		responseLocations = append(responseLocations, &nodev1.WindscribeLocation{
			Name:      location.Name,
			Available: location.Available,
		})
	}
	message := "Windscribe locations loaded"
	if strings.EqualFold(strings.TrimSpace(req.GetAction()), "apply") {
		message = "Windscribe proxy applied"
	}
	return &nodev1.WindscribeProxyResponse{
		OperationId: req.GetOperationId(),
		Accepted:    true,
		Runtime:     api.server.grpcRuntimeState(message),
		Message:     message,
		Locations:   responseLocations,
	}, nil
}

func (api *grpcAPI) ConfigurePsiphon(ctx context.Context, req *nodev1.PsiphonProxyRequest) (*nodev1.PsiphonProxyResponse, error) {
	if req == nil {
		return nil, status.Error(codes.InvalidArgument, "Psiphon proxy request is required")
	}
	result, err := configurePsiphon(ctx, psiphonProxyConfig{
		Action:     req.GetAction(),
		ConfigJSON: req.GetConfigJson(),
		Locations:  req.GetLocations(),
		SocksPort:  req.GetSocksPort(),
	})
	if err != nil {
		return nil, status.Error(codes.FailedPrecondition, err.Error())
	}
	responseInstances := make([]*nodev1.PsiphonProxyInstance, 0, len(result.Instances))
	for _, instance := range result.Instances {
		responseInstances = append(responseInstances, &nodev1.PsiphonProxyInstance{
			Location:  instance.Location,
			SocksPort: instance.SocksPort,
		})
	}
	message := "Psiphon proxies started"
	if strings.EqualFold(strings.TrimSpace(req.GetAction()), "locations") {
		message = "Psiphon locations loaded"
	}
	return &nodev1.PsiphonProxyResponse{
		OperationId: req.GetOperationId(),
		Accepted:    true,
		Runtime:     api.server.grpcRuntimeState(message),
		Message:     message,
		Instances:   responseInstances,
		Locations:   result.Locations,
	}, nil
}

func (api *grpcAPI) CollectUserUsage(ctx context.Context, req *nodev1.CollectUsageRequest) (*nodev1.UserUsageBatch, error) {
	var stats []xray.UserStat
	var speeds []userTrafficSpeed
	var onlineUIDs []string
	var onlineIPs []xray.OnlineUserIP
	if api.server.core.Started() {
		var statsErr error
		stats, speeds, statsErr = api.server.collectXrayUserStats(30*time.Second, req.GetReset_())
		if statsErr != nil {
			// Keep the online signal independent from the expensive traffic
			// counters. A busy Xray stats service must not make every user look
			// offline until the next successful collection.
			log.Printf("failed to query user traffic stats: %v", statsErr)
		}
		var onlineErr error
		onlineUIDs, onlineIPs, onlineErr = xray.QueryOnlineUserSnapshot(
			api.server.settings.XrayAPIHost,
			api.server.settings.XrayAPIPort,
			5*time.Second,
		)
		if onlineErr != nil {
			log.Printf("failed to query online user IPs: %v", onlineErr)
		}
	}
	if OVStats := api.server.ov.CollectUsage(); len(OVStats) > 0 {
		stats = append(stats, OVStats...)
	}
	if l2tpStats := api.server.l2tp.CollectUsage(); len(l2tpStats) > 0 {
		stats = append(stats, l2tpStats...)
	}
	if pptpStats := api.server.pptp.CollectUsage(); len(pptpStats) > 0 {
		stats = append(stats, pptpStats...)
	}
	if wgStats := api.server.wg.CollectUsage(); len(wgStats) > 0 {
		stats = append(stats, wgStats...)
	}
	if ikev2Stats := api.server.remoteAccess.CollectUsage("ikev2"); len(ikev2Stats) > 0 {
		stats = append(stats, ikev2Stats...)
	}
	if anyConnectStats := api.server.remoteAccess.CollectUsage("anyconnect"); len(anyConnectStats) > 0 {
		stats = append(stats, anyConnectStats...)
	}
	if api.server.sshProxy != nil {
		if sshStats := api.server.sshProxy.CollectUsage(); len(sshStats) > 0 {
			stats = append(stats, sshStats...)
		}
		onlineUIDs = append(onlineUIDs, api.server.sshProxy.OnlineUIDs()...)
	}
	if api.server.extraVPN != nil {
		if extraStats := api.server.extraVPN.CollectUsage(); len(extraStats) > 0 {
			stats = append(stats, extraStats...)
		}
		onlineUIDs = append(onlineUIDs, api.server.extraVPN.OnlineUIDs()...)
	}
	batchID, pending := api.server.usage.addUsersAndSnapshot(stats)
	pending = appendOnlineUserMarkers(pending, onlineUIDs)
	res := &nodev1.UserUsageBatch{BatchId: batchID, OnlineIps: protoOnlineUserIPs(onlineIPs)}
	for _, speed := range speeds {
		res.Speeds = append(res.Speeds, &nodev1.UserTrafficSpeed{
			Uid:      speed.UID,
			Upload:   speed.Upload,
			Download: speed.Download,
		})
	}
	for _, stat := range pending {
		res.Stats = append(res.Stats, &nodev1.UserUsageSample{
			Uid:        stat.UID,
			Value:      uint64(maxInt64(stat.Value, 0)),
			InboundTag: stat.InboundTag,
		})
	}
	return res, nil
}

func (api *grpcAPI) CollectOnlineUsers(context.Context, *nodev1.Empty) (*nodev1.OnlineUsersResponse, error) {
	uids := []string{}
	if api.server.sshProxy != nil {
		uids = api.server.sshProxy.OnlineUIDs()
	}
	if api.server.core.Started() {
		xrayUIDs, err := xray.QueryOnlineUserUIDs(
			api.server.settings.XrayAPIHost,
			api.server.settings.XrayAPIPort,
			5*time.Second,
		)
		if err != nil {
			return nil, status.Error(codes.Unavailable, err.Error())
		}
		uids = append(uids, xrayUIDs...)
	}
	return &nodev1.OnlineUsersResponse{Uids: uids}, nil
}

func (api *grpcAPI) AckUserUsage(ctx context.Context, req *nodev1.AckUsageRequest) (*nodev1.AckUsageResponse, error) {
	acknowledged := api.server.usage.ackUsers(req.GetBatchId())
	return &nodev1.AckUsageResponse{BatchId: req.GetBatchId(), Acknowledged: acknowledged}, nil
}

func (api *grpcAPI) CollectOutboundUsage(ctx context.Context, req *nodev1.CollectUsageRequest) (*nodev1.OutboundUsageBatch, error) {
	var stats []xray.OutboundStat
	var inboundStats []xray.InboundStat
	if api.server.core.Started() {
		var err error
		stats, err = xray.QueryOutboundStats(
			api.server.settings.XrayAPIHost,
			api.server.settings.XrayAPIPort,
			10*time.Second,
			req.GetReset_(),
		)
		if err != nil {
			return nil, status.Error(codes.Unavailable, err.Error())
		}
		api.server.usage.add(stats)
		stats = nil
		inboundStats, err = xray.QueryInboundStats(
			api.server.settings.XrayAPIHost,
			api.server.settings.XrayAPIPort,
			10*time.Second,
			req.GetReset_(),
		)
		if err != nil {
			return nil, status.Error(codes.Unavailable, err.Error())
		}
	}
	batchID, pending, pendingInbounds := api.server.usage.addUsageAndSnapshot(stats, inboundStats)
	res := &nodev1.OutboundUsageBatch{BatchId: batchID}
	for _, stat := range pending {
		res.Stats = append(res.Stats, &nodev1.OutboundUsageSample{
			Tag:  stat.Tag,
			Up:   uint64(maxInt64(stat.Up, 0)),
			Down: uint64(maxInt64(stat.Down, 0)),
		})
	}
	for _, stat := range pendingInbounds {
		res.InboundStats = append(res.InboundStats, &nodev1.InboundUsageSample{
			Tag:  stat.Tag,
			Up:   uint64(maxInt64(stat.Up, 0)),
			Down: uint64(maxInt64(stat.Down, 0)),
		})
	}
	return res, nil
}

func (api *grpcAPI) AckOutboundUsage(ctx context.Context, req *nodev1.AckUsageRequest) (*nodev1.AckUsageResponse, error) {
	acknowledged := api.server.usage.ack(req.GetBatchId())
	return &nodev1.AckUsageResponse{BatchId: req.GetBatchId(), Acknowledged: acknowledged}, nil
}

func (api *grpcAPI) StreamLogs(req *nodev1.StreamLogsRequest, stream nodev1.NodeLogsService_StreamLogsServer) error {
	logs, cancel := api.server.core.Logs().Subscribe()
	defer cancel()

	for {
		select {
		case <-stream.Context().Done():
			return stream.Context().Err()
		case line, ok := <-logs:
			if !ok {
				return nil
			}
			if err := stream.Send(&nodev1.LogLine{
				StreamId:      req.GetStreamId(),
				Line:          line,
				EmittedAtUnix: time.Now().Unix(),
			}); err != nil {
				return err
			}
		}
	}
}

func (s *Server) grpcStartRuntime(ctx context.Context, req *nodev1.RuntimeConfigRequest, sync bool) (*nodev1.RuntimeActionResponse, error) {
	cfg, err := s.grpcConfig(ctx, req)
	if err != nil {
		return nil, err
	}
	runtimeConfig, l2tpRuntimeConfig, pptpRuntimeConfig, wgRuntimeConfig, ikev2RuntimeConfig, anyConnectRuntimeConfig, haproxyRuntimeConfig, extraRuntimeConfig, err := grpcVPNRuntime(req)
	if err != nil {
		return nil, err
	}
	prepareTProxyConfig(cfg)
	if err := s.core.Start(cfg); err != nil {
		return nil, status.Error(codes.Unavailable, err.Error())
	}
	s.setLastConfig(cfg)
	time.Sleep(3 * time.Second)
	if !s.core.Started() {
		return nil, status.Error(codes.Unavailable, strings.Join(s.core.Logs().Snapshot(), "\n"))
	}
	cacheRuntime := runtimeConfig
	if cacheRuntime == nil {
		cacheRuntime = s.cachedOVRuntime()
	}
	cacheL2TPRuntime := l2tpRuntimeConfig
	if cacheL2TPRuntime == nil {
		cacheL2TPRuntime = s.cachedL2TPRuntime()
	}
	cachePPTPRuntime := pptpRuntimeConfig
	if cachePPTPRuntime == nil {
		cachePPTPRuntime = s.cachedPPTPRuntime()
	}
	cacheWGRuntime := wgRuntimeConfig
	if cacheWGRuntime == nil {
		cacheWGRuntime = s.cachedWGRuntime()
	}
	cacheIKEv2Runtime := ikev2RuntimeConfig
	if cacheIKEv2Runtime == nil {
		cacheIKEv2Runtime = s.cachedIKEv2Runtime()
	}
	cacheAnyConnectRuntime := anyConnectRuntimeConfig
	if cacheAnyConnectRuntime == nil {
		cacheAnyConnectRuntime = s.cachedAnyConnectRuntime()
	}
	cacheHAProxyRuntime := haproxyRuntimeConfig
	if cacheHAProxyRuntime == nil {
		cacheHAProxyRuntime = s.cachedHAProxyRuntime()
	}
	cacheExtraRuntime := extraRuntimeConfig
	if cacheExtraRuntime == nil {
		cacheExtraRuntime = s.cachedExtraRuntime()
	}
	if err := s.ov.Apply(cacheRuntime); err != nil {
		return nil, status.Error(codes.Unavailable, err.Error())
	}
	ikev2PrepareWarning := s.prepareIKEv2Runtime(cacheIKEv2Runtime)
	l2tpWarning := s.applyL2TPRuntime(cacheL2TPRuntime)
	pptpWarning := s.applyPPTPRuntime(cachePPTPRuntime)
	wgWarning := s.applyWGRuntime(cacheWGRuntime)
	ikev2Warning := s.applyIKEv2Runtime(cacheIKEv2Runtime)
	anyConnectWarning := s.applyAnyConnectRuntime(cacheAnyConnectRuntime)
	haproxyWarning := s.applyHAProxyRuntime(cacheHAProxyRuntime)
	extraWarning := s.applyExtraRuntime(cacheExtraRuntime)
	s.saveConfigCacheWithHAProxy(req.GetConfigJson(), grpcPeerIP(ctx), cacheRuntime, cacheL2TPRuntime, cachePPTPRuntime, cacheWGRuntime, cacheHAProxyRuntime, cacheExtraRuntime, cacheIKEv2Runtime, cacheAnyConnectRuntime)
	message := "runtime started"
	if sync {
		message = "runtime config synced"
	}
	if warning := joinedWarnings(ikev2PrepareWarning, l2tpWarning, pptpWarning, wgWarning, ikev2Warning, anyConnectWarning, haproxyWarning, extraWarning); warning != "" {
		message += "; " + warning
	}
	return s.grpcAction(req.GetOperationId(), true, message), nil
}

func (s *Server) grpcRestartRuntime(ctx context.Context, req *nodev1.RuntimeConfigRequest, message string) (*nodev1.RuntimeActionResponse, error) {
	cfg, err := s.grpcConfig(ctx, req)
	if err != nil {
		return nil, err
	}
	runtimeConfig, l2tpRuntimeConfig, pptpRuntimeConfig, wgRuntimeConfig, ikev2RuntimeConfig, anyConnectRuntimeConfig, haproxyRuntimeConfig, extraRuntimeConfig, err := grpcVPNRuntime(req)
	if err != nil {
		return nil, err
	}
	prepareTProxyConfig(cfg)
	if err := s.core.Restart(cfg); err != nil {
		return nil, status.Error(codes.Unavailable, err.Error())
	}
	s.setLastConfig(cfg)
	time.Sleep(3 * time.Second)
	if !s.core.Started() {
		return nil, status.Error(codes.Unavailable, strings.Join(s.core.Logs().Snapshot(), "\n"))
	}
	cacheRuntime := runtimeConfig
	if cacheRuntime == nil {
		cacheRuntime = s.cachedOVRuntime()
	}
	cacheL2TPRuntime := l2tpRuntimeConfig
	if cacheL2TPRuntime == nil {
		cacheL2TPRuntime = s.cachedL2TPRuntime()
	}
	cachePPTPRuntime := pptpRuntimeConfig
	if cachePPTPRuntime == nil {
		cachePPTPRuntime = s.cachedPPTPRuntime()
	}
	cacheWGRuntime := wgRuntimeConfig
	if cacheWGRuntime == nil {
		cacheWGRuntime = s.cachedWGRuntime()
	}
	cacheIKEv2Runtime := ikev2RuntimeConfig
	if cacheIKEv2Runtime == nil {
		cacheIKEv2Runtime = s.cachedIKEv2Runtime()
	}
	cacheAnyConnectRuntime := anyConnectRuntimeConfig
	if cacheAnyConnectRuntime == nil {
		cacheAnyConnectRuntime = s.cachedAnyConnectRuntime()
	}
	cacheHAProxyRuntime := haproxyRuntimeConfig
	if cacheHAProxyRuntime == nil {
		cacheHAProxyRuntime = s.cachedHAProxyRuntime()
	}
	cacheExtraRuntime := extraRuntimeConfig
	if cacheExtraRuntime == nil {
		cacheExtraRuntime = s.cachedExtraRuntime()
	}
	if err := s.ov.Apply(cacheRuntime); err != nil {
		return nil, status.Error(codes.Unavailable, err.Error())
	}
	ikev2PrepareWarning := s.prepareIKEv2Runtime(cacheIKEv2Runtime)
	l2tpWarning := s.applyL2TPRuntime(cacheL2TPRuntime)
	pptpWarning := s.applyPPTPRuntime(cachePPTPRuntime)
	wgWarning := s.applyWGRuntime(cacheWGRuntime)
	ikev2Warning := s.applyIKEv2Runtime(cacheIKEv2Runtime)
	anyConnectWarning := s.applyAnyConnectRuntime(cacheAnyConnectRuntime)
	haproxyWarning := s.applyHAProxyRuntime(cacheHAProxyRuntime)
	extraWarning := s.applyExtraRuntime(cacheExtraRuntime)
	s.saveConfigCacheWithHAProxy(req.GetConfigJson(), grpcPeerIP(ctx), cacheRuntime, cacheL2TPRuntime, cachePPTPRuntime, cacheWGRuntime, cacheHAProxyRuntime, cacheExtraRuntime, cacheIKEv2Runtime, cacheAnyConnectRuntime)
	if warning := joinedWarnings(ikev2PrepareWarning, l2tpWarning, pptpWarning, wgWarning, ikev2Warning, anyConnectWarning, haproxyWarning, extraWarning); warning != "" {
		message += "; " + warning
	}
	return s.grpcAction(req.GetOperationId(), true, message), nil
}

func (s *Server) grpcApplyRuntimeOnly(ctx context.Context, req *nodev1.RuntimeConfigRequest, message string) (*nodev1.RuntimeActionResponse, error) {
	runtimeConfig, l2tpRuntimeConfig, pptpRuntimeConfig, wgRuntimeConfig, ikev2RuntimeConfig, anyConnectRuntimeConfig, haproxyRuntimeConfig, extraRuntimeConfig, err := grpcVPNRuntime(req)
	if err != nil {
		return nil, err
	}
	if err := s.applyConfigCacheUserDiff(req.GetConfigJson()); err != nil {
		return nil, status.Error(codes.Unavailable, err.Error())
	}
	cacheRuntime := runtimeConfig
	if cacheRuntime == nil {
		cacheRuntime = s.cachedOVRuntime()
	}
	cacheL2TPRuntime := l2tpRuntimeConfig
	if cacheL2TPRuntime == nil {
		cacheL2TPRuntime = s.cachedL2TPRuntime()
	}
	cachePPTPRuntime := pptpRuntimeConfig
	if cachePPTPRuntime == nil {
		cachePPTPRuntime = s.cachedPPTPRuntime()
	}
	cacheWGRuntime := wgRuntimeConfig
	if cacheWGRuntime == nil {
		cacheWGRuntime = s.cachedWGRuntime()
	}
	cacheIKEv2Runtime := ikev2RuntimeConfig
	if cacheIKEv2Runtime == nil {
		cacheIKEv2Runtime = s.cachedIKEv2Runtime()
	}
	cacheAnyConnectRuntime := anyConnectRuntimeConfig
	if cacheAnyConnectRuntime == nil {
		cacheAnyConnectRuntime = s.cachedAnyConnectRuntime()
	}
	cacheHAProxyRuntime := haproxyRuntimeConfig
	if cacheHAProxyRuntime == nil {
		cacheHAProxyRuntime = s.cachedHAProxyRuntime()
	}
	cacheExtraRuntime := extraRuntimeConfig
	if cacheExtraRuntime == nil {
		cacheExtraRuntime = s.cachedExtraRuntime()
	}
	if err := s.ov.Apply(cacheRuntime); err != nil {
		return nil, status.Error(codes.Unavailable, err.Error())
	}
	ikev2PrepareWarning := s.prepareIKEv2Runtime(cacheIKEv2Runtime)
	l2tpWarning := s.applyL2TPRuntime(cacheL2TPRuntime)
	pptpWarning := s.applyPPTPRuntime(cachePPTPRuntime)
	wgWarning := s.applyWGRuntime(cacheWGRuntime)
	ikev2Warning := s.applyIKEv2Runtime(cacheIKEv2Runtime)
	anyConnectWarning := s.applyAnyConnectRuntime(cacheAnyConnectRuntime)
	haproxyWarning := s.applyHAProxyRuntime(cacheHAProxyRuntime)
	extraWarning := s.applyExtraRuntime(cacheExtraRuntime)
	s.saveConfigCacheWithHAProxy(req.GetConfigJson(), grpcPeerIP(ctx), cacheRuntime, cacheL2TPRuntime, cachePPTPRuntime, cacheWGRuntime, cacheHAProxyRuntime, cacheExtraRuntime, cacheIKEv2Runtime, cacheAnyConnectRuntime)
	if warning := joinedWarnings(ikev2PrepareWarning, l2tpWarning, pptpWarning, wgWarning, ikev2Warning, anyConnectWarning, haproxyWarning, extraWarning); warning != "" {
		message += "; " + warning
	}
	return s.grpcAction(req.GetOperationId(), true, message), nil
}

func (s *Server) runtimeConfigMatchesCache(configJSON string) bool {
	incoming, ok := canonicalConfigJSON(configJSON)
	if !ok {
		return false
	}
	payload, ok := s.loadConfigCache()
	if !ok {
		return false
	}
	cached, ok := canonicalConfigJSON(payload.Config)
	return ok && cached == incoming
}

func canonicalConfigJSON(raw string) (string, bool) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return "", false
	}
	var value any
	decoder := json.NewDecoder(strings.NewReader(raw))
	decoder.UseNumber()
	if err := decoder.Decode(&value); err != nil {
		return "", false
	}
	encoded, err := json.Marshal(value)
	if err != nil {
		return "", false
	}
	return string(encoded), true
}

func (s *Server) runtimeTopologyMatchesCache(configJSON string) bool {
	incoming, ok := canonicalConfigTopologyJSON(configJSON)
	if !ok {
		return false
	}
	payload, ok := s.loadConfigCache()
	if !ok {
		return false
	}
	cached, ok := canonicalConfigTopologyJSON(payload.Config)
	return ok && cached == incoming
}

func canonicalConfigTopologyJSON(raw string) (string, bool) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return "", false
	}
	var value any
	decoder := json.NewDecoder(strings.NewReader(raw))
	decoder.UseNumber()
	if err := decoder.Decode(&value); err != nil {
		return "", false
	}
	stripRuntimeUsers(value)
	encoded, err := json.Marshal(value)
	if err != nil {
		return "", false
	}
	return string(encoded), true
}

func stripRuntimeUsers(value any) {
	root, ok := value.(map[string]any)
	if !ok {
		return
	}
	inbounds, _ := root["inbounds"].([]any)
	for _, item := range inbounds {
		inbound, ok := item.(map[string]any)
		if !ok {
			continue
		}
		settings, ok := inbound["settings"].(map[string]any)
		if !ok {
			continue
		}
		clients, _ := settings["clients"].([]any)
		reverseClients := make([]any, 0, len(clients))
		for _, item := range clients {
			client, _ := item.(map[string]any)
			reverse, _ := client["reverse"].(map[string]any)
			if strings.TrimSpace(asString(reverse["tag"])) != "" {
				reverseClients = append(reverseClients, client)
			}
		}
		if len(reverseClients) == 0 {
			delete(settings, "clients")
		} else {
			settings["clients"] = reverseClients
		}
	}
}

func (s *Server) grpcConfig(ctx context.Context, req *nodev1.RuntimeConfigRequest) (*xray.Config, error) {
	configJSON := strings.TrimSpace(req.GetConfigJson())
	if configJSON == "" {
		return nil, status.Error(codes.InvalidArgument, "config_json is required")
	}
	cfg, err := xray.NewConfig(configJSON, grpcPeerIP(ctx), s.settings)
	if err != nil {
		return nil, status.Error(codes.InvalidArgument, "failed to decode config: "+err.Error())
	}
	return cfg, nil
}

func prepareTProxyConfig(cfg *xray.Config) {
	if xrayConfigUsesTProxy(cfg) {
		enableVPNTProxyHostNetworking()
	}
}

func xrayConfigUsesTProxy(cfg *xray.Config) bool {
	raw, err := cfg.JSON()
	return err == nil && strings.Contains(string(raw), `"tproxy":"tproxy"`)
}

func grpcVPNRuntime(req *nodev1.RuntimeConfigRequest) (*ovRuntime, *l2tpRuntime, *pptpRuntime, *wgRuntime, *remoteAccessRuntime, *remoteAccessRuntime, *haproxyRuntime, *extraRuntime, error) {
	raw := strings.TrimSpace(req.GetOvRuntimeJson())
	if raw == "" {
		return &ovRuntime{Inbounds: []ovRuntimeInbound{}},
			&l2tpRuntime{Inbounds: []l2tpRuntimeInbound{}},
			&pptpRuntime{Inbounds: []pptpRuntimeInbound{}},
			&wgRuntime{Inbounds: []wgRuntimeInbound{}},
			&remoteAccessRuntime{Inbounds: []remoteAccessRuntimeInbound{}},
			&remoteAccessRuntime{Inbounds: []remoteAccessRuntimeInbound{}},
			&haproxyRuntime{}, &extraRuntime{Inbounds: []extraRuntimeInbound{}}, nil
	}
	var envelope struct {
		GeneratedAt         string                       `json:"generated_at"`
		Target              string                       `json:"target,omitempty"`
		SessionCallback     *vpnSessionCallback          `json:"session_callback,omitempty"`
		Inbounds            []ovRuntimeInbound           `json:"inbounds"`
		L2TPInbounds        []l2tpRuntimeInbound         `json:"l2tp_inbounds"`
		L2TPGenerated       string                       `json:"l2tp_generated,omitempty"`
		PPTPInbounds        []pptpRuntimeInbound         `json:"pptp_inbounds"`
		PPTPGenerated       string                       `json:"pptp_generated,omitempty"`
		WGInbounds          []wgRuntimeInbound           `json:"wg_inbounds"`
		WGGenerated         string                       `json:"wg_generated,omitempty"`
		IKEv2Inbounds       []remoteAccessRuntimeInbound `json:"ikev2_inbounds"`
		IKEv2Generated      string                       `json:"ikev2_generated,omitempty"`
		AnyConnectInbounds  []remoteAccessRuntimeInbound `json:"anyconnect_inbounds"`
		AnyConnectGenerated string                       `json:"anyconnect_generated,omitempty"`
		HAProxy             *haproxyRuntime              `json:"haproxy,omitempty"`
		Extra               *extraRuntime                `json:"extra,omitempty"`
	}
	if err := json.Unmarshal([]byte(raw), &envelope); err != nil {
		return nil, nil, nil, nil, nil, nil, nil, nil, status.Error(codes.InvalidArgument, "failed to decode ov_runtime_json: "+err.Error())
	}
	ovRuntimeConfig := &ovRuntime{GeneratedAt: envelope.GeneratedAt, Target: envelope.Target, SessionCallback: envelope.SessionCallback, Inbounds: envelope.Inbounds}
	if ovRuntimeConfig.Inbounds == nil {
		ovRuntimeConfig.Inbounds = []ovRuntimeInbound{}
	}
	l2tpRuntimeConfig := &l2tpRuntime{GeneratedAt: envelope.L2TPGenerated, Target: envelope.Target, SessionCallback: envelope.SessionCallback, Inbounds: envelope.L2TPInbounds}
	if l2tpRuntimeConfig.Inbounds == nil {
		l2tpRuntimeConfig.Inbounds = []l2tpRuntimeInbound{}
	}
	pptpRuntimeConfig := &pptpRuntime{GeneratedAt: envelope.PPTPGenerated, Target: envelope.Target, Inbounds: envelope.PPTPInbounds}
	if pptpRuntimeConfig.Inbounds == nil {
		pptpRuntimeConfig.Inbounds = []pptpRuntimeInbound{}
	}
	wgRuntimeConfig := &wgRuntime{GeneratedAt: envelope.WGGenerated, Target: envelope.Target, SessionCallback: envelope.SessionCallback, Inbounds: envelope.WGInbounds}
	if wgRuntimeConfig.Inbounds == nil {
		wgRuntimeConfig.Inbounds = []wgRuntimeInbound{}
	}
	ikev2RuntimeConfig := &remoteAccessRuntime{GeneratedAt: envelope.IKEv2Generated, Target: envelope.Target, SessionCallback: envelope.SessionCallback, Inbounds: envelope.IKEv2Inbounds}
	if ikev2RuntimeConfig.Inbounds == nil {
		ikev2RuntimeConfig.Inbounds = []remoteAccessRuntimeInbound{}
	}
	anyConnectRuntimeConfig := &remoteAccessRuntime{GeneratedAt: envelope.AnyConnectGenerated, Target: envelope.Target, SessionCallback: envelope.SessionCallback, Inbounds: envelope.AnyConnectInbounds}
	if anyConnectRuntimeConfig.Inbounds == nil {
		anyConnectRuntimeConfig.Inbounds = []remoteAccessRuntimeInbound{}
	}
	return ovRuntimeConfig, l2tpRuntimeConfig, pptpRuntimeConfig, wgRuntimeConfig, ikev2RuntimeConfig, anyConnectRuntimeConfig, envelope.HAProxy, envelope.Extra, nil
}

func (s *Server) grpcAddUser(req *nodev1.InboundUserRequest, message string) (*nodev1.RuntimeActionResponse, error) {
	if !s.core.Started() {
		return nil, status.Error(codes.FailedPrecondition, "Xray is not started")
	}
	inboundTag := strings.TrimSpace(req.GetInboundTag())
	if inboundTag == "" {
		return nil, status.Error(codes.InvalidArgument, "inbound_tag is required")
	}
	user, err := protoInboundUser(req.GetUser())
	if err != nil {
		return nil, status.Error(codes.InvalidArgument, err.Error())
	}
	if err := xray.AddInboundUser(
		s.settings.XrayAPIHost,
		s.settings.XrayAPIPort,
		grpcOperationTimeout,
		inboundTag,
		user,
	); err != nil {
		if !isIgnorableXrayAddError(err) {
			return nil, status.Error(codes.Unavailable, err.Error())
		}
	}
	if err := s.addUserToConfigCache(inboundTag, user); err != nil {
		return nil, status.Error(codes.Unavailable, err.Error())
	}
	return s.grpcAction(req.GetOperationId(), true, message), nil
}

func (s *Server) grpcUpdateRuntime(version string) error {
	version = normalizeXrayVersion(version)
	if version == "" {
		return status.Error(codes.InvalidArgument, "version is required")
	}
	if !validXrayVersion(version) {
		return status.Error(codes.InvalidArgument, "invalid version")
	}
	asset, err := detectXrayAsset()
	if err != nil {
		return status.Error(codes.FailedPrecondition, err.Error())
	}
	body, err := downloadXrayCoreArchive(version, asset, 120*time.Second)
	if err != nil {
		return status.Error(codes.Unavailable, "download failed: "+err.Error())
	}
	baseDir := filepath.Join(s.settings.RebeccaDataDir, "xray-core")
	if err := os.MkdirAll(baseDir, 0o755); err != nil {
		return status.Error(codes.Internal, err.Error())
	}
	wasStarted := s.core.Started()
	if wasStarted {
		s.snapshotRunningUsage()
		s.core.Stop()
	}
	restore := func() {
		if !wasStarted {
			return
		}
		if restoreErr := s.startCachedConfig(false); restoreErr != nil {
			log.Printf("failed to restore Xray after core update error: %v", restoreErr)
		}
	}
	extracted, err := installZipTo(body, baseDir)
	if err != nil {
		restore()
		return status.Error(codes.Internal, err.Error())
	}
	finalExe := filepath.Join(baseDir, executableName("xray"))
	if extracted != finalExe {
		_ = os.Remove(finalExe)
		if err := os.Rename(extracted, finalExe); err != nil {
			if copyErr := copyFile(extracted, finalExe); copyErr != nil {
				restore()
				return status.Error(codes.Internal, copyErr.Error())
			}
		}
	}
	_ = os.Chmod(finalExe, 0o755)
	if err := s.core.SetExecutablePath(finalExe); err != nil {
		restore()
		return status.Error(codes.Internal, err.Error())
	}
	if wasStarted {
		if err := s.startCachedConfig(false); err != nil {
			return status.Error(codes.Unavailable, "Xray core updated but runtime restart failed: "+err.Error())
		}
	}
	return nil
}

func (s *Server) grpcUpdateGeo(files []downloadFile) error {
	if len(files) == 0 {
		return status.Error(codes.InvalidArgument, "'files' must be a non-empty list of {name,url}")
	}
	assetsDir := filepath.Join(s.settings.RebeccaDataDir, "assets")
	if err := os.MkdirAll(assetsDir, 0o755); err != nil {
		return status.Error(codes.Internal, err.Error())
	}
	for _, file := range files {
		name := safeGeoFilename(file.Name)
		url := strings.TrimSpace(file.URL)
		if name == "" || url == "" {
			return status.Error(codes.InvalidArgument, "each file must include non-empty name and url")
		}
		if err := validatePublicHTTPURL(url); err != nil {
			return status.Error(codes.InvalidArgument, err.Error())
		}
		body, err := download(url, 120*time.Second)
		if err != nil {
			return status.Error(codes.Unavailable, "failed to download "+name+": "+err.Error())
		}
		if err := os.WriteFile(filepath.Join(assetsDir, name), body, 0o644); err != nil {
			return status.Error(codes.Internal, "failed to save "+name+": "+err.Error())
		}
	}
	s.core.SetAssetsPath(assetsDir)
	if s.core.Started() {
		s.snapshotRunningUsage()
		if err := s.startCachedConfig(true); err != nil {
			return status.Error(codes.Unavailable, "Geo assets updated but runtime restart failed: "+err.Error())
		}
	}
	return nil
}

func (s *Server) setLastConfig(cfg *xray.Config) {
	s.mu.Lock()
	s.lastConfig = cfg
	s.mu.Unlock()
}

func (s *Server) grpcAction(operationID string, accepted bool, message string) *nodev1.RuntimeActionResponse {
	return &nodev1.RuntimeActionResponse{
		OperationId: operationID,
		Accepted:    accepted,
		Runtime:     s.grpcRuntimeState(message),
		Message:     message,
	}
}

func (s *Server) grpcRuntimeState(message string) *nodev1.RuntimeState {
	s.mu.Lock()
	s.pruneSessionsLocked(time.Now())
	connected := s.connected && len(s.sessions) > 0
	s.mu.Unlock()

	return &nodev1.RuntimeState{
		Connected:     connected,
		Started:       s.core.Started(),
		CoreVersion:   s.core.Version(),
		NodeVersion:   s.nodeVersion(),
		InstallMode:   s.settings.InstallMode,
		UpdateChannel: s.updateChannel(),
		Message:       message,
		Capabilities: []string{
			"safe_user_reconciliation",
			"targeted_user_update",
			"haproxy_runtime",
			"grpc_control_port",
			"mutual_tls_required",
			"operation_deduplication",
			"config_revision",
			"host_actions",
			"protocol_statuses",
			"xray_process_metrics",
			"tor_proxy",
			"windscribe_proxy",
			"psiphon_proxy",
		},
		AppliedRevision:  s.appliedRevision(),
		ProtocolStatuses: s.protocolStatuses(),
	}
}

func (s *Server) grpcMetrics(message string) *nodev1.MetricsResponse {
	var snapshot systemSnapshot
	if s.system != nil {
		snapshot = s.system.Snapshot()
	}
	pid, xrayUptime := s.core.Process()
	xraySnapshot := processSnapshot{PID: pid, UptimeSec: xrayUptime}
	if s.system != nil {
		xraySnapshot = s.system.ProcessSnapshot(pid, xrayUptime)
	}
	return &nodev1.MetricsResponse{
		Runtime: s.grpcRuntimeState(message),
		System: &nodev1.SystemMetrics{
			CpuCores:           int32(snapshot.CPU.Cores),
			CpuFrequencyHz:     snapshot.CPU.FrequencyHz,
			CpuUsagePercent:    snapshot.CPU.UsagePct,
			MemoryUsed:         snapshot.Memory.UsedBytes,
			MemoryTotal:        snapshot.Memory.TotalBytes,
			MemoryUsagePercent: snapshot.Memory.UsagePct,
			UptimeSeconds:      snapshot.UptimeSec,
		},
		Transfer: &nodev1.TransferMetrics{
			UploadSpeed:   snapshot.Bandwidth.UploadBytesPerSecond,
			DownloadSpeed: snapshot.Bandwidth.DownloadBytesPerSecond,
		},
		Xray: &nodev1.XrayMetrics{
			Pid: int32(xraySnapshot.PID), CpuUsagePercent: xraySnapshot.CPUUsagePct,
			MemoryUsed: xraySnapshot.MemoryUsed, UptimeSeconds: xraySnapshot.UptimeSec,
		},
		SampledAtUnix: time.Now().Unix(),
	}
}

func (s *Server) updateChannel() string {
	if metadata := s.binaryMetadata(); metadata != nil {
		if tag, ok := metadata["tag"].(string); ok && strings.TrimSpace(tag) != "" {
			return updateChannelForTag(tag)
		}
	}
	return s.settings.InstallMode
}

func protoInboundUser(user *nodev1.InboundUser) (xray.InboundUser, error) {
	if user == nil {
		return xray.InboundUser{}, errors.New("user is required")
	}
	fields := user.GetFields()
	level, err := parseUint32Field(fields, "level")
	if err != nil {
		return xray.InboundUser{}, err
	}
	cipherType, err := parseInt32Field(fields, "cipher_type")
	if err != nil {
		return xray.InboundUser{}, err
	}
	ivCheck, err := parseBoolField(fields, "iv_check")
	if err != nil {
		return xray.InboundUser{}, err
	}
	auth := strings.TrimSpace(fields["auth"])
	if auth == "" {
		auth = strings.TrimSpace(fields["password"])
	}
	return xray.InboundUser{
		Email:      strings.TrimSpace(user.GetEmail()),
		Protocol:   strings.TrimSpace(user.GetProtocol()),
		Level:      level,
		ID:         strings.TrimSpace(fields["id"]),
		Password:   strings.TrimSpace(fields["password"]),
		Auth:       auth,
		Flow:       strings.TrimSpace(fields["flow"]),
		Method:     strings.TrimSpace(fields["method"]),
		CipherType: cipherType,
		IVCheck:    ivCheck,
	}, nil
}

func parseUint32Field(fields map[string]string, key string) (uint32, error) {
	value := strings.TrimSpace(fields[key])
	if value == "" {
		return 0, nil
	}
	parsed, err := strconv.ParseUint(value, 10, 32)
	if err != nil {
		return 0, fmt.Errorf("%s must be a uint32", key)
	}
	return uint32(parsed), nil
}

func parseInt32Field(fields map[string]string, key string) (int32, error) {
	value := strings.TrimSpace(fields[key])
	if value == "" {
		return 0, nil
	}
	parsed, err := strconv.ParseInt(value, 10, 32)
	if err != nil {
		return 0, fmt.Errorf("%s must be an int32", key)
	}
	return int32(parsed), nil
}

func parseBoolField(fields map[string]string, key string) (bool, error) {
	value := strings.TrimSpace(fields[key])
	if value == "" {
		return false, nil
	}
	parsed, err := appconfig.ParseBool(value)
	if err != nil {
		return false, fmt.Errorf("%s must be a bool", key)
	}
	return parsed, nil
}

func grpcPeerIP(ctx context.Context) string {
	info, ok := peer.FromContext(ctx)
	if !ok || info.Addr == nil {
		return "127.0.0.1"
	}
	host, _, err := net.SplitHostPort(info.Addr.String())
	if err != nil {
		return info.Addr.String()
	}
	return host
}

func maxInt64(value int64, minimum int64) int64 {
	if value < minimum {
		return minimum
	}
	return value
}

func protoOnlineUserIPs(users []xray.OnlineUserIP) []*nodev1.OnlineUserIP {
	result := make([]*nodev1.OnlineUserIP, 0, len(users))
	for _, user := range users {
		item := &nodev1.OnlineUserIP{Uid: user.UID, Email: user.Email}
		for _, ip := range user.IPs {
			item.Ips = append(item.Ips, &nodev1.OnlineIP{Ip: ip.IP, LastSeenUnix: ip.LastSeenUnix})
		}
		result = append(result, item)
	}
	return result
}

func init() {
	log.SetFlags(log.Flags())
}
