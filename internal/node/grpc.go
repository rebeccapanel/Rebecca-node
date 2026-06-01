package node

import (
	"context"
	"crypto/tls"
	"crypto/x509"
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

	listener, err := net.Listen("tcp", net.JoinHostPort(s.settings.GRPCServiceHost, strconv.Itoa(s.settings.GRPCServicePort)))
	if err != nil {
		return err
	}

	grpcServer := grpc.NewServer(grpc.Creds(credentials.NewTLS(tlsConfig)))
	s.registerGRPC(grpcServer)
	return grpcServer.Serve(listener)
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
	if settings.SSLClientCertFile == "" || !fileExists(settings.SSLClientCertFile) {
		return nil, errors.New("SSL_CLIENT_CERT_FILE is required for gRPC")
	}

	cert, err := tls.LoadX509KeyPair(settings.SSLCertFile, settings.SSLKeyFile)
	if err != nil {
		return nil, fmt.Errorf("load gRPC server certificate: %w", err)
	}
	clientCAPEM, err := os.ReadFile(settings.SSLClientCertFile)
	if err != nil {
		return nil, fmt.Errorf("read gRPC client certificate: %w", err)
	}
	clientCAs := x509.NewCertPool()
	if !clientCAs.AppendCertsFromPEM(clientCAPEM) {
		return nil, errors.New("failed to load SSL_CLIENT_CERT_FILE for gRPC")
	}

	return &tls.Config{
		Certificates: []tls.Certificate{cert},
		ClientCAs:    clientCAs,
		ClientAuth:   tls.RequireAndVerifyClientCert,
		MinVersion:   tls.VersionTLS12,
	}, nil
}

func (api *grpcAPI) Hello(ctx context.Context, _ *nodev1.HelloRequest) (*nodev1.HelloResponse, error) {
	return &nodev1.HelloResponse{
		NodeName:      api.server.settings.AppName,
		NodeVersion:   api.server.settings.NodeVersion,
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
	return api.server.grpcStartRuntime(ctx, req, false)
}

func (api *grpcAPI) RestartRuntime(ctx context.Context, req *nodev1.RuntimeConfigRequest) (*nodev1.RuntimeActionResponse, error) {
	return api.server.grpcRestartRuntime(ctx, req, "runtime restarted")
}

func (api *grpcAPI) StopRuntime(ctx context.Context, req *nodev1.StopRuntimeRequest) (*nodev1.RuntimeActionResponse, error) {
	if req.GetCollectUsageBeforeStop() {
		api.server.snapshotRunningUsage()
	}
	api.server.core.Stop()
	api.server.clearConfigCache()
	return api.server.grpcAction(req.GetOperationId(), true, "runtime stopped"), nil
}

func (api *grpcAPI) SyncConfig(ctx context.Context, req *nodev1.RuntimeConfigRequest) (*nodev1.RuntimeActionResponse, error) {
	if api.server.core.Started() {
		return api.server.grpcRestartRuntime(ctx, req, "runtime config synced")
	}
	return api.server.grpcStartRuntime(ctx, req, true)
}

func (api *grpcAPI) AddUser(ctx context.Context, req *nodev1.InboundUserRequest) (*nodev1.RuntimeActionResponse, error) {
	return api.server.grpcAddUser(req, "user added")
}

func (api *grpcAPI) UpdateUser(ctx context.Context, req *nodev1.InboundUserRequest) (*nodev1.RuntimeActionResponse, error) {
	if !api.server.core.Started() {
		return nil, status.Error(codes.FailedPrecondition, "Xray is not started")
	}
	inboundTag := strings.TrimSpace(req.GetInboundTag())
	user, err := protoInboundUser(req.GetUser())
	if err != nil {
		return nil, status.Error(codes.InvalidArgument, err.Error())
	}
	_ = xray.RemoveInboundUser(
		api.server.settings.XrayAPIHost,
		api.server.settings.XrayAPIPort,
		grpcOperationTimeout,
		inboundTag,
		user.Email,
	)
	if err := xray.AddInboundUser(
		api.server.settings.XrayAPIHost,
		api.server.settings.XrayAPIPort,
		grpcOperationTimeout,
		inboundTag,
		user,
	); err != nil {
		return nil, status.Error(codes.Unavailable, err.Error())
	}
	return api.server.grpcAction(req.GetOperationId(), true, "user updated"), nil
}

func (api *grpcAPI) RemoveUser(ctx context.Context, req *nodev1.RemoveInboundUserRequest) (*nodev1.RuntimeActionResponse, error) {
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
		return nil, status.Error(codes.Unavailable, err.Error())
	}
	return api.server.grpcAction(req.GetOperationId(), true, "user removed"), nil
}

func (api *grpcAPI) Metrics(ctx context.Context, _ *nodev1.MetricsRequest) (*nodev1.MetricsResponse, error) {
	return api.server.grpcMetrics("metrics"), nil
}

func (api *grpcAPI) UpdateRuntime(ctx context.Context, req *nodev1.RuntimeUpdateRequest) (*nodev1.RuntimeActionResponse, error) {
	if err := api.server.grpcUpdateRuntime(req.GetVersion()); err != nil {
		return nil, err
	}
	return api.server.grpcAction(req.GetOperationId(), true, "runtime updated"), nil
}

func (api *grpcAPI) UpdateGeo(ctx context.Context, req *nodev1.GeoUpdateRequest) (*nodev1.RuntimeActionResponse, error) {
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

func (api *grpcAPI) CollectUserUsage(ctx context.Context, req *nodev1.CollectUsageRequest) (*nodev1.UserUsageBatch, error) {
	var stats []xray.UserStat
	if api.server.core.Started() {
		var err error
		stats, err = xray.QueryUserStats(
			api.server.settings.XrayAPIHost,
			api.server.settings.XrayAPIPort,
			30*time.Second,
			req.GetReset_(),
		)
		if err != nil {
			return nil, status.Error(codes.Unavailable, err.Error())
		}
	}
	batchID, pending := api.server.usage.addUsersAndSnapshot(stats)
	res := &nodev1.UserUsageBatch{BatchId: batchID}
	for _, stat := range pending {
		res.Stats = append(res.Stats, &nodev1.UserUsageSample{
			Uid:   stat.UID,
			Value: uint64(maxInt64(stat.Value, 0)),
		})
	}
	return res, nil
}

func (api *grpcAPI) AckUserUsage(ctx context.Context, req *nodev1.AckUsageRequest) (*nodev1.AckUsageResponse, error) {
	acknowledged := api.server.usage.ackUsers(req.GetBatchId())
	return &nodev1.AckUsageResponse{BatchId: req.GetBatchId(), Acknowledged: acknowledged}, nil
}

func (api *grpcAPI) CollectOutboundUsage(ctx context.Context, req *nodev1.CollectUsageRequest) (*nodev1.OutboundUsageBatch, error) {
	var stats []xray.OutboundStat
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
	}
	batchID, pending := api.server.usage.addAndSnapshot(stats)
	res := &nodev1.OutboundUsageBatch{BatchId: batchID}
	for _, stat := range pending {
		res.Stats = append(res.Stats, &nodev1.OutboundUsageSample{
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
	if err := s.core.Start(cfg); err != nil {
		return nil, status.Error(codes.Unavailable, err.Error())
	}
	s.setLastConfig(cfg)
	time.Sleep(3 * time.Second)
	if !s.core.Started() {
		return nil, status.Error(codes.Unavailable, strings.Join(s.core.Logs().Snapshot(), "\n"))
	}
	s.saveConfigCache(req.GetConfigJson(), grpcPeerIP(ctx))
	message := "runtime started"
	if sync {
		message = "runtime config synced"
	}
	return s.grpcAction(req.GetOperationId(), true, message), nil
}

func (s *Server) grpcRestartRuntime(ctx context.Context, req *nodev1.RuntimeConfigRequest, message string) (*nodev1.RuntimeActionResponse, error) {
	cfg, err := s.grpcConfig(ctx, req)
	if err != nil {
		return nil, err
	}
	if err := s.core.Restart(cfg); err != nil {
		return nil, status.Error(codes.Unavailable, err.Error())
	}
	s.setLastConfig(cfg)
	time.Sleep(3 * time.Second)
	if !s.core.Started() {
		return nil, status.Error(codes.Unavailable, strings.Join(s.core.Logs().Snapshot(), "\n"))
	}
	s.saveConfigCache(req.GetConfigJson(), grpcPeerIP(ctx))
	return s.grpcAction(req.GetOperationId(), true, message), nil
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
		return nil, status.Error(codes.Unavailable, err.Error())
	}
	return s.grpcAction(req.GetOperationId(), true, message), nil
}

func (s *Server) grpcUpdateRuntime(version string) error {
	version = strings.TrimSpace(version)
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
	url := fmt.Sprintf("https://github.com/XTLS/Xray-core/releases/download/%s/%s", version, asset)
	if err := validatePublicHTTPURL(url); err != nil {
		return status.Error(codes.InvalidArgument, err.Error())
	}
	body, err := download(url, 120*time.Second)
	if err != nil {
		return status.Error(codes.Unavailable, "download failed: "+err.Error())
	}
	baseDir := filepath.Join(s.settings.RebeccaDataDir, "xray-core")
	if err := os.MkdirAll(baseDir, 0o755); err != nil {
		return status.Error(codes.Internal, err.Error())
	}
	if s.core.Started() {
		s.snapshotRunningUsage()
		s.core.Stop()
	}
	extracted, err := installZipTo(body, baseDir)
	if err != nil {
		return status.Error(codes.Internal, err.Error())
	}
	finalExe := filepath.Join(baseDir, executableName("xray"))
	if extracted != finalExe {
		_ = os.Remove(finalExe)
		if err := os.Rename(extracted, finalExe); err != nil {
			if copyErr := copyFile(extracted, finalExe); copyErr != nil {
				return status.Error(codes.Internal, copyErr.Error())
			}
		}
	}
	_ = os.Chmod(finalExe, 0o755)
	if err := s.core.SetExecutablePath(finalExe); err != nil {
		return status.Error(codes.Internal, err.Error())
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
		NodeVersion:   s.settings.NodeVersion,
		InstallMode:   s.settings.InstallMode,
		UpdateChannel: s.updateChannel(),
		Message:       message,
	}
}

func (s *Server) grpcMetrics(message string) *nodev1.MetricsResponse {
	var snapshot systemSnapshot
	if s.system != nil {
		snapshot = s.system.Snapshot()
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
		},
		Transfer: &nodev1.TransferMetrics{
			UploadSpeed:   snapshot.Bandwidth.UploadBytesPerSecond,
			DownloadSpeed: snapshot.Bandwidth.DownloadBytesPerSecond,
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
	return xray.InboundUser{
		Email:      strings.TrimSpace(user.GetEmail()),
		Protocol:   strings.TrimSpace(user.GetProtocol()),
		Level:      level,
		ID:         strings.TrimSpace(fields["id"]),
		Password:   strings.TrimSpace(fields["password"]),
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

func init() {
	log.SetFlags(log.Flags())
}
