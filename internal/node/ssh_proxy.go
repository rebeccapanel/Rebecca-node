package node

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/subtle"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/rebeccapanel/rebecca-node/internal/xray"
	"golang.org/x/crypto/ssh"
)

const (
	maxSSHConnections = 1024
	maxSSHChannels    = 64
)

type sshProxyManager struct {
	mu          sync.Mutex
	dir         string
	listeners   map[string]net.Listener
	connections map[net.Conn]struct{}
	generation  uint64
	runtime     *extraRuntime
	usage       map[string]xray.UserStat
	online      map[string]int
	sessions    map[string]map[string]int
	resolve     func(context.Context, string) ([]net.IP, error)
	dial        func(context.Context, string) (net.Conn, error)
}

func newSSHProxyManager(dataDir string) *sshProxyManager {
	return &sshProxyManager{
		dir:         filepath.Join(dataDir, "ssh-proxy"),
		listeners:   map[string]net.Listener{},
		connections: map[net.Conn]struct{}{},
		usage:       map[string]xray.UserStat{},
		online:      map[string]int{},
		sessions:    map[string]map[string]int{},
		resolve: func(ctx context.Context, host string) ([]net.IP, error) {
			return net.DefaultResolver.LookupIP(ctx, "ip", host)
		},
		dial: func(ctx context.Context, address string) (net.Conn, error) {
			return (&net.Dialer{Timeout: 15 * time.Second, KeepAlive: 30 * time.Second}).DialContext(ctx, "tcp", address)
		},
	}
}

func (m *sshProxyManager) Apply(runtimeConfig *extraRuntime) error {
	if runtimeConfig == nil {
		runtimeConfig = &extraRuntime{Inbounds: []extraRuntimeInbound{}}
	}
	hasSSH := false
	for _, inbound := range runtimeConfig.Inbounds {
		if strings.EqualFold(strings.TrimSpace(inbound.Protocol), "ssh") {
			hasSSH = true
			break
		}
	}
	if !hasSSH {
		m.mu.Lock()
		defer m.mu.Unlock()
		m.generation++
		m.stopLocked()
		m.runtime = runtimeConfig
		return nil
	}
	signer, err := m.hostSigner()
	if err != nil {
		return err
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	m.generation++
	generation := m.generation
	m.stopLocked()
	for _, inbound := range runtimeConfig.Inbounds {
		if strings.ToLower(strings.TrimSpace(inbound.Protocol)) != "ssh" {
			continue
		}
		listener, err := net.Listen("tcp", net.JoinHostPort(inbound.Listen, strconv.Itoa(inbound.Port)))
		if err != nil {
			m.stopLocked()
			return fmt.Errorf("SSH inbound %q: %w", inbound.Tag, err)
		}
		m.listeners[inbound.Tag] = listener
		go m.serve(listener, inbound, signer, generation)
	}
	m.runtime = runtimeConfig
	return nil
}

func (m *sshProxyManager) stopLocked() {
	for tag, listener := range m.listeners {
		_ = listener.Close()
		delete(m.listeners, tag)
	}
	for connection := range m.connections {
		_ = connection.Close()
		delete(m.connections, connection)
	}
}

func (m *sshProxyManager) hostSigner() (ssh.Signer, error) {
	if err := os.MkdirAll(m.dir, 0o700); err != nil {
		return nil, err
	}
	path := filepath.Join(m.dir, "host_key")
	if raw, err := os.ReadFile(path); err == nil {
		return ssh.ParsePrivateKey(raw)
	} else if !errors.Is(err, os.ErrNotExist) {
		return nil, err
	}
	_, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}
	encoded, err := x509.MarshalPKCS8PrivateKey(privateKey)
	if err != nil {
		return nil, err
	}
	raw := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: encoded})
	if err := writeFileAtomic(path, raw, 0o600); err != nil {
		return nil, err
	}
	return ssh.ParsePrivateKey(raw)
}

func (m *sshProxyManager) serve(listener net.Listener, inbound extraRuntimeInbound, signer ssh.Signer, generation uint64) {
	users := make(map[string]extraRuntimeUser, len(inbound.Users))
	for _, user := range inbound.Users {
		if user.UserID > 0 && strings.TrimSpace(user.Username) != "" && user.Password != "" {
			users[user.Username] = user
		}
	}
	config := &ssh.ServerConfig{
		MaxAuthTries: 4,
		PasswordCallback: func(metadata ssh.ConnMetadata, password []byte) (*ssh.Permissions, error) {
			user, ok := users[metadata.User()]
			if !ok || subtle.ConstantTimeCompare(password, []byte(user.Password)) != 1 {
				return nil, errors.New("authentication failed")
			}
			return &ssh.Permissions{Extensions: map[string]string{"uid": "ssh:" + strconv.FormatInt(user.UserID, 10)}}, nil
		},
	}
	config.AddHostKey(signer)
	for {
		conn, err := listener.Accept()
		if err != nil {
			return
		}
		m.mu.Lock()
		if generation != m.generation || len(m.connections) >= maxSSHConnections {
			m.mu.Unlock()
			_ = conn.Close()
			continue
		}
		m.connections[conn] = struct{}{}
		m.mu.Unlock()
		go m.handleConnection(conn, inbound, users, config)
	}
}

func (m *sshProxyManager) handleConnection(raw net.Conn, inbound extraRuntimeInbound, users map[string]extraRuntimeUser, config *ssh.ServerConfig) {
	defer func() {
		_ = raw.Close()
		m.mu.Lock()
		delete(m.connections, raw)
		m.mu.Unlock()
	}()
	_ = raw.SetDeadline(time.Now().Add(15 * time.Second))
	serverConn, channels, requests, err := ssh.NewServerConn(raw, config)
	if err != nil {
		return
	}
	defer serverConn.Close()
	user, ok := users[serverConn.User()]
	if !ok {
		return
	}
	limit := user.DeviceLimit
	if configured := intSetting(inbound.Settings, "user_limit", 0); configured > 0 && (limit <= 0 || int64(configured) < limit) {
		limit = int64(configured)
	}
	uid := "ssh:" + strconv.FormatInt(user.UserID, 10)
	clientIP := remoteHost(raw.RemoteAddr())
	if !m.acquire(uid, clientIP, int(limit)) {
		return
	}
	defer m.release(uid, clientIP)
	idle := time.Duration(intSetting(inbound.Settings, "idle_timeout", 300)) * time.Second
	_ = raw.SetDeadline(time.Now().Add(idle))
	go ssh.DiscardRequests(requests)
	channelSlots := make(chan struct{}, maxSSHChannels)
	for newChannel := range channels {
		if newChannel.ChannelType() != "direct-tcpip" {
			_ = newChannel.Reject(ssh.Prohibited, "only direct-tcpip is allowed")
			continue
		}
		select {
		case channelSlots <- struct{}{}:
			go func() {
				defer func() { <-channelSlots }()
				m.forward(newChannel, uid, inbound.Tag, idle, raw)
			}()
		default:
			_ = newChannel.Reject(ssh.ResourceShortage, "too many open channels")
		}
	}
}

type sshDirectTCPIP struct {
	DestinationHost string
	DestinationPort uint32
	OriginHost      string
	OriginPort      uint32
}

func (m *sshProxyManager) forward(newChannel ssh.NewChannel, uid, tag string, idle time.Duration, raw net.Conn) {
	var request sshDirectTCPIP
	if err := ssh.Unmarshal(newChannel.ExtraData(), &request); err != nil || request.DestinationPort == 0 || request.DestinationPort > 65535 {
		_ = newChannel.Reject(ssh.ConnectionFailed, "invalid destination")
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	address, err := m.publicDestination(ctx, request.DestinationHost, int(request.DestinationPort))
	if err != nil {
		_ = newChannel.Reject(ssh.Prohibited, "destination is not allowed")
		return
	}
	remote, err := m.dial(ctx, address)
	if err != nil {
		_ = newChannel.Reject(ssh.ConnectionFailed, "destination is unavailable")
		return
	}
	channel, requests, err := newChannel.Accept()
	if err != nil {
		_ = remote.Close()
		return
	}
	go ssh.DiscardRequests(requests)
	defer channel.Close()
	defer remote.Close()
	client := &activityConn{ReadWriteCloser: channel, connections: []net.Conn{raw, remote}, timeout: idle}
	server := &activityConn{ReadWriteCloser: remote, connections: []net.Conn{raw, remote}, timeout: idle}
	counts := make(chan struct {
		up    bool
		bytes int64
	}, 2)
	go func() {
		n, _ := io.Copy(userSpeedWriter{Writer: server, uid: sshSpeedUserID(uid), upload: true}, client)
		counts <- struct {
			up    bool
			bytes int64
		}{true, n}
	}()
	go func() {
		n, _ := io.Copy(userSpeedWriter{Writer: client, uid: sshSpeedUserID(uid), upload: false}, server)
		counts <- struct {
			up    bool
			bytes int64
		}{false, n}
	}()
	first := <-counts
	_ = channel.Close()
	_ = remote.Close()
	second := <-counts
	m.addUsage(uid, tag, first.up, first.bytes)
	m.addUsage(uid, tag, second.up, second.bytes)
}

type activityConn struct {
	io.ReadWriteCloser
	connections []net.Conn
	timeout     time.Duration
}

func (c *activityConn) Read(value []byte) (int, error) {
	c.refreshDeadline()
	return c.ReadWriteCloser.Read(value)
}

func (c *activityConn) Write(value []byte) (int, error) {
	c.refreshDeadline()
	return c.ReadWriteCloser.Write(value)
}

func (c *activityConn) refreshDeadline() {
	deadline := time.Now().Add(c.timeout)
	for _, connection := range c.connections {
		if connection != nil {
			_ = connection.SetDeadline(deadline)
		}
	}
}

func (m *sshProxyManager) publicDestination(ctx context.Context, host string, port int) (string, error) {
	host = strings.TrimSpace(host)
	if host == "" || port < 1 || port > 65535 {
		return "", errors.New("invalid destination")
	}
	addresses, err := m.resolve(ctx, host)
	if err != nil || len(addresses) == 0 {
		return "", errors.New("destination does not resolve")
	}
	for _, ip := range addresses {
		if !isPublicProxyIP(ip) {
			return "", errors.New("private destination")
		}
	}
	return net.JoinHostPort(addresses[0].String(), strconv.Itoa(port)), nil
}

func isPublicProxyIP(ip net.IP) bool {
	return ip != nil && ip.IsGlobalUnicast() && !ip.IsPrivate() && !ip.IsLoopback() && !ip.IsLinkLocalUnicast() && !ip.IsUnspecified()
}

func (m *sshProxyManager) acquire(uid, clientIP string, limit int) bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	if clientIP == "" {
		return false
	}
	ips := m.sessions[uid]
	if ips == nil {
		ips = map[string]int{}
		m.sessions[uid] = ips
	}
	if limit > 0 && ips[clientIP] == 0 && len(ips) >= limit {
		return false
	}
	ips[clientIP]++
	m.online[uid]++
	return true
}

func (m *sshProxyManager) release(uid, clientIP string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if ips := m.sessions[uid]; ips != nil {
		if ips[clientIP] > 1 {
			ips[clientIP]--
		} else {
			delete(ips, clientIP)
		}
		if len(ips) == 0 {
			delete(m.sessions, uid)
		}
	}
	if m.online[uid] > 1 {
		m.online[uid]--
	} else {
		delete(m.online, uid)
	}
}

func remoteHost(address net.Addr) string {
	if address == nil {
		return ""
	}
	host, _, err := net.SplitHostPort(address.String())
	if err != nil {
		return ""
	}
	ip := net.ParseIP(strings.TrimSpace(host))
	if ip == nil {
		return ""
	}
	return ip.String()
}

func (m *sshProxyManager) addUsage(uid, tag string, upload bool, value int64) {
	if value <= 0 {
		return
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	key := uid + "\x00" + tag
	item := m.usage[key]
	item.UID, item.InboundTag, item.Value = uid, tag, item.Value+value
	if upload {
		item.Up += value
	} else {
		item.Down += value
	}
	m.usage[key] = item
}

func (m *sshProxyManager) CollectUsage() []xray.UserStat {
	m.mu.Lock()
	defer m.mu.Unlock()
	result := make([]xray.UserStat, 0, len(m.usage))
	for key, item := range m.usage {
		result = append(result, item)
		delete(m.usage, key)
	}
	return result
}

func (m *sshProxyManager) OnlineUIDs() []string {
	m.mu.Lock()
	defer m.mu.Unlock()
	result := make([]string, 0, len(m.online))
	for uid := range m.online {
		result = append(result, uid)
	}
	return result
}

func (m *sshProxyManager) State() (configured, running int) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.runtime != nil {
		for _, inbound := range m.runtime.Inbounds {
			if strings.EqualFold(inbound.Protocol, "ssh") {
				configured++
			}
		}
	}
	return configured, len(m.listeners)
}

func intSetting(settings map[string]any, key string, fallback int) int {
	if value, ok := settings[key].(float64); ok {
		return int(value)
	}
	if value, ok := settings[key].(int); ok {
		return value
	}
	return fallback
}
