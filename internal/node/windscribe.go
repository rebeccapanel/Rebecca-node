package node

import (
	"bufio"
	"context"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"regexp"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

const (
	windscribeAccount       = "rebecca-windscribe"
	windscribeHome          = "/var/lib/rebecca-windscribe"
	windscribeAccountMarker = windscribeHome + "/.rebecca-account"
	windscribeConfigPath    = windscribeHome + "/.config/Windscribe/windscribe_cli.conf"
	windscribeServiceName   = "rebecca-windscribe.service"
	windscribeRelayUnitName = "rebecca-windscribe-proxy.service"
)

var (
	windscribeLocationPattern = regexp.MustCompile(`^[a-zA-Z]{2}$`)
	windscribeSetupMu         sync.Mutex
)

type windscribeProxyConfig struct {
	Action        string
	Username      string
	Password      string
	Location      string
	SocksPort     uint32
	ProxyUsername string
	ProxyPassword string
}

type windscribeLocation struct {
	Name      string
	Available bool
}

func configureWindscribe(ctx context.Context, config windscribeProxyConfig) ([]windscribeLocation, error) {
	windscribeSetupMu.Lock()
	defer windscribeSetupMu.Unlock()

	if runtime.GOOS != "linux" {
		return nil, fmt.Errorf("Windscribe setup is supported on Linux nodes only")
	}
	if os.Geteuid() != 0 {
		return nil, fmt.Errorf("Windscribe automatic setup requires root")
	}
	action := strings.ToLower(strings.TrimSpace(config.Action))
	if action != "locations" && action != "apply" {
		return nil, fmt.Errorf("Windscribe action must be locations or apply")
	}
	if action == "locations" && (!validWindscribeLoginValue(config.Username, 3, 128) || !validWindscribeLoginValue(config.Password, 8, 256)) {
		return nil, fmt.Errorf("Windscribe username or password is invalid")
	}
	if action == "apply" {
		if config.SocksPort < 1024 || config.SocksPort > 65535 {
			return nil, fmt.Errorf("Windscribe SOCKS port must be between 1024 and 65535")
		}
		location := strings.ToLower(strings.TrimSpace(config.Location))
		if !windscribeLocationPattern.MatchString(location) {
			return nil, fmt.Errorf("Windscribe location must be a two-letter ISO code")
		}
		if !validWindscribeProxyCredential(config.ProxyUsername) || !validWindscribeProxyCredential(config.ProxyPassword) {
			return nil, fmt.Errorf("Windscribe proxy credentials must be 8-64 letters or digits")
		}
	}
	if err := ensureWindscribeInstalled(ctx); err != nil {
		return nil, err
	}
	if err := ensureWindscribeService(ctx); err != nil {
		return nil, err
	}

	if action == "locations" {
		if err := windscribeLogin(ctx, config.Username, config.Password); err != nil {
			return nil, err
		}
		output, err := runWindscribeCLI(ctx, "locations")
		if err != nil {
			return nil, err
		}
		locations := parseWindscribeLocations(output)
		if len(locations) == 0 {
			return nil, fmt.Errorf("Windscribe returned no locations for this account")
		}
		return locations, nil
	}

	location := strings.ToLower(strings.TrimSpace(config.Location))

	bindIP, err := primaryIPv4()
	if err != nil {
		return nil, err
	}
	_, _ = runWindscribeCLI(ctx, "disconnect")
	if err := writeWindscribeConfig(config); err != nil {
		return nil, err
	}
	if _, err := runWindscribeCLI(ctx, "preferences", "reload"); err != nil {
		return nil, err
	}
	_, _ = runWindscribeCLI(ctx, "firewall", "off")
	_, _ = runWindscribeCLI(ctx, "keylimit", "delete")
	if _, err := runWindscribeCLI(ctx, "connect", location, "wireguard"); err != nil {
		return nil, err
	}
	if err := waitForTCPAddress(net.JoinHostPort(bindIP, strconv.Itoa(int(config.SocksPort))), 30*time.Second); err != nil {
		return nil, fmt.Errorf("Windscribe Proxy Gateway did not start: %w", err)
	}
	if err := applyWindscribeRelay(bindIP, config.SocksPort); err != nil {
		return nil, err
	}
	if err := waitForAuthenticatedSocks(
		int(config.SocksPort),
		config.ProxyUsername,
		config.ProxyPassword,
		90*time.Second,
	); err != nil {
		return nil, err
	}
	return nil, nil
}

func ensureWindscribeInstalled(ctx context.Context) error {
	if commandExists("windscribe-cli") && fileExists("/opt/windscribe/Windscribe") {
		return ensureWindscribeSupportPackages()
	}
	url, extension, err := windscribePackageURL(ctx)
	if err != nil {
		return err
	}
	var path string
	var lastErr error
	for attempt := 0; attempt < 3; attempt++ {
		body, downloadErr := download(url, 5*time.Minute)
		if downloadErr != nil {
			lastErr = downloadErr
			continue
		}
		file, createErr := os.CreateTemp("", "rebecca-windscribe-*"+extension)
		if createErr != nil {
			return createErr
		}
		path = file.Name()
		if _, writeErr := file.Write(body); writeErr != nil {
			_ = file.Close()
			_ = os.Remove(path)
			return writeErr
		}
		if closeErr := file.Close(); closeErr != nil {
			_ = os.Remove(path)
			return closeErr
		}
		if extension != ".deb" || !commandExists("dpkg-deb") || commandSucceeds("dpkg-deb", "--info", path) {
			break
		}
		lastErr = fmt.Errorf("downloaded Windscribe package is not a valid Debian archive")
		_ = os.Remove(path)
		path = ""
	}
	if path == "" {
		return fmt.Errorf("download Windscribe CLI: %w", lastErr)
	}
	defer os.Remove(path)

	switch {
	case extension == ".deb":
		if !commandExists("dpkg-deb") {
			return fmt.Errorf("dpkg-deb is required to install Windscribe CLI")
		}
		if err = runCommandContext(ctx, nil, "dpkg-deb", "--info", path); err != nil {
			return fmt.Errorf("downloaded Windscribe package is not a valid Debian archive: %w", err)
		}
		if commandExists("dpkg") {
			_ = runCommandContext(ctx, []string{"DEBIAN_FRONTEND=noninteractive"}, "dpkg", "--configure", "-a")
		}
		err = runCommandContext(ctx, []string{"DEBIAN_FRONTEND=noninteractive"}, "apt-get", "install", "-y", "--no-install-recommends", path)
	case extension == ".rpm" && commandExists("zypper"):
		if err = runCommandContext(ctx, nil, "rpm", "--import", "https://windscribe.com/windscribe_linux_signing_key.pub"); err != nil {
			break
		}
		err = runCommandContext(ctx, nil, "zypper", "--non-interactive", "install", "-y", path)
	case extension == ".rpm":
		manager := "dnf"
		if !commandExists(manager) {
			manager = "yum"
		}
		err = runCommandContext(ctx, nil, manager, "install", "-y", path)
	case extension == ".zst":
		err = runCommandContext(ctx, nil, "pacman", "-U", "--noconfirm", path)
	}
	if err != nil {
		return fmt.Errorf("install Windscribe CLI: %w", err)
	}
	if !commandExists("windscribe-cli") {
		return fmt.Errorf("Windscribe CLI installation completed without installing windscribe-cli")
	}
	return ensureWindscribeSupportPackages()
}

func windscribePackageURL(ctx context.Context) (string, string, error) {
	arch := runtime.GOARCH
	var pattern string
	switch {
	case commandExists("apt-get") && (arch == "amd64" || arch == "arm64"):
		pattern = "windscribe-cli_*_" + arch + ".deb"
	case commandExists("zypper") && arch == "amd64":
		pattern = "windscribe-cli_*_amd64_opensuse.rpm"
	case (commandExists("dnf") || commandExists("yum")) && (arch == "amd64" || arch == "arm64"):
		pattern = "windscribe-cli_*_" + arch + "_fedora.rpm"
	case commandExists("pacman") && arch == "amd64":
		pattern = "windscribe-cli_*_amd64.pkg.tar.zst"
	default:
		return "", "", fmt.Errorf("Windscribe CLI does not publish a package for this distribution and architecture")
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, "https://api.github.com/repos/Windscribe/Desktop-App/releases/latest", nil)
	if err != nil {
		return "", "", err
	}
	request.Header.Set("Accept", "application/vnd.github+json")
	request.Header.Set("User-Agent", "Rebecca-node")
	response, err := (&http.Client{Timeout: 30 * time.Second}).Do(request)
	if err != nil {
		return "", "", fmt.Errorf("resolve Windscribe release: %w", err)
	}
	defer response.Body.Close()
	if response.StatusCode < 200 || response.StatusCode >= 300 {
		return "", "", fmt.Errorf("resolve Windscribe release: HTTP %d", response.StatusCode)
	}
	var release struct {
		Assets []struct {
			Name string `json:"name"`
			URL  string `json:"browser_download_url"`
		} `json:"assets"`
	}
	if err := json.NewDecoder(io.LimitReader(response.Body, 4<<20)).Decode(&release); err != nil {
		return "", "", fmt.Errorf("decode Windscribe release: %w", err)
	}
	for _, asset := range release.Assets {
		matched, _ := filepath.Match(pattern, asset.Name)
		if matched && asset.URL != "" {
			extension := ".rpm"
			if strings.HasSuffix(asset.Name, ".deb") {
				extension = ".deb"
			} else if strings.HasSuffix(asset.Name, ".zst") {
				extension = ".zst"
			}
			return asset.URL, extension, nil
		}
	}
	return "", "", fmt.Errorf("Windscribe release has no CLI asset for %s", arch)
}

func ensureWindscribeSupportPackages() error {
	if commandExists("socat") && commandExists("runuser") && commandExists("script") {
		return nil
	}
	switch {
	case commandExists("apt-get"):
		return runInstallCommand([]string{"DEBIAN_FRONTEND=noninteractive"}, "apt-get", "install", "-y", "--no-install-recommends", "socat", "util-linux")
	case commandExists("dnf"):
		return runInstallCommand(nil, "dnf", "install", "-y", "socat", "util-linux")
	case commandExists("yum"):
		return runInstallCommand(nil, "yum", "install", "-y", "socat", "util-linux")
	case commandExists("zypper"):
		return runInstallCommand(nil, "zypper", "--non-interactive", "install", "-y", "socat", "util-linux")
	case commandExists("pacman"):
		return runInstallCommand(nil, "pacman", "-S", "--noconfirm", "socat", "util-linux")
	default:
		return fmt.Errorf("socat and util-linux are required for Windscribe setup")
	}
}

func ensureWindscribeService(ctx context.Context) error {
	if !commandExists("systemctl") {
		return fmt.Errorf("Windscribe setup requires systemd")
	}
	account, err := user.Lookup(windscribeAccount)
	if err != nil {
		if err := runCommandContext(ctx, nil, "useradd", "--system", "--create-home", "--home-dir", windscribeHome, "--shell", "/usr/sbin/nologin", windscribeAccount); err != nil {
			return fmt.Errorf("create Windscribe service account: %w", err)
		}
		account, err = user.Lookup(windscribeAccount)
		if err != nil {
			return err
		}
	}
	if err := runCommandContext(ctx, nil, "usermod", "-a", "-G", "windscribe", windscribeAccount); err != nil {
		return fmt.Errorf("grant Windscribe helper access: %w", err)
	}
	uid, err := strconv.Atoi(account.Uid)
	if err != nil {
		return err
	}
	gid, err := strconv.Atoi(account.Gid)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(windscribeConfigPath), 0o700); err != nil {
		return err
	}
	if err := os.Chown(windscribeHome, uid, gid); err != nil {
		return err
	}
	if err := os.Chown(filepath.Dir(filepath.Dir(windscribeConfigPath)), uid, gid); err != nil {
		return err
	}
	if err := os.Chown(filepath.Dir(windscribeConfigPath), uid, gid); err != nil {
		return err
	}

	unitPath := filepath.Join("/etc/systemd/system", windscribeServiceName)
	if err := os.WriteFile(unitPath, []byte(windscribeSystemdUnit()), 0o644); err != nil {
		return err
	}
	if err := runCommandContext(ctx, nil, "systemctl", "daemon-reload"); err != nil {
		return err
	}
	if commandSucceeds("systemctl", "is-active", "--quiet", windscribeServiceName) {
		return nil
	}
	_ = exec.Command("pkill", "-TERM", "-x", "Windscribe").Run()
	if err := runCommandContext(ctx, nil, "systemctl", "enable", "--now", windscribeServiceName); err != nil {
		return fmt.Errorf("start Windscribe service: %w", err)
	}
	deadline := time.Now().Add(30 * time.Second)
	for time.Now().Before(deadline) {
		if _, err := runWindscribeCLI(ctx, "status"); err == nil {
			return nil
		}
		time.Sleep(time.Second)
	}
	return fmt.Errorf("Windscribe CLI could not connect to its service")
}

func windscribeSystemdUnit() string {
	return `[Unit]
Description=Rebecca Windscribe client
After=network-online.target windscribe-helper.service
Wants=network-online.target

[Service]
Type=simple
User=rebecca-windscribe
Group=rebecca-windscribe
SupplementaryGroups=windscribe
Environment=HOME=/var/lib/rebecca-windscribe
Environment=XDG_CONFIG_HOME=/var/lib/rebecca-windscribe/.config
Environment=XDG_RUNTIME_DIR=/run/rebecca-windscribe
RuntimeDirectory=rebecca-windscribe
RuntimeDirectoryMode=0700
ExecStart=/opt/windscribe/Windscribe
Restart=on-failure
RestartSec=3
NoNewPrivileges=true
PrivateTmp=true
ProtectHome=true
ProtectSystem=strict
ReadWritePaths=/var/lib/rebecca-windscribe /run/rebecca-windscribe

[Install]
WantedBy=multi-user.target
`
}

func windscribeLogin(ctx context.Context, username, password string) error {
	username = strings.TrimSpace(username)
	status, statusErr := runWindscribeCLI(ctx, "status")
	marker, markerErr := os.ReadFile(windscribeAccountMarker)
	if statusErr == nil && markerErr == nil && strings.Contains(strings.ToLower(status), "login state: logged in") && strings.TrimSpace(string(marker)) == username {
		return nil
	}
	_, _ = runWindscribeCLI(ctx, "logout")
	command := exec.CommandContext(
		ctx,
		"runuser", "-u", windscribeAccount, "--",
		"env",
		"HOME="+windscribeHome,
		"XDG_CONFIG_HOME="+windscribeHome+"/.config",
		"XDG_RUNTIME_DIR=/run/rebecca-windscribe",
		"script", "-qec", "/usr/bin/windscribe-cli login", "/dev/null",
	)
	command.Stdin = strings.NewReader(username + "\n" + password + "\n")
	output, err := command.CombinedOutput()
	if err != nil {
		return fmt.Errorf("Windscribe login failed: %s", truncateWindscribeOutput(sanitizeWindscribeOutput(string(output), username, password)))
	}
	status, err = runWindscribeCLI(ctx, "status")
	if err != nil {
		return err
	}
	if !strings.Contains(strings.ToLower(status), "login state: logged in") {
		return fmt.Errorf("Windscribe login did not complete")
	}
	return writeWindscribeAccountMarker(username)
}

func writeWindscribeAccountMarker(username string) error {
	if err := os.WriteFile(windscribeAccountMarker, []byte(strings.TrimSpace(username)+"\n"), 0o600); err != nil {
		return fmt.Errorf("remember Windscribe account: %w", err)
	}
	account, err := user.Lookup(windscribeAccount)
	if err != nil {
		return err
	}
	uid, err := strconv.Atoi(account.Uid)
	if err != nil {
		return err
	}
	gid, err := strconv.Atoi(account.Gid)
	if err != nil {
		return err
	}
	return os.Chown(windscribeAccountMarker, uid, gid)
}

func runWindscribeCLI(ctx context.Context, args ...string) (string, error) {
	commandArgs := []string{
		"-u", windscribeAccount, "--", "env",
		"HOME=" + windscribeHome,
		"XDG_CONFIG_HOME=" + windscribeHome + "/.config",
		"XDG_RUNTIME_DIR=/run/rebecca-windscribe",
		"/usr/bin/windscribe-cli",
	}
	commandArgs = append(commandArgs, args...)
	output, err := exec.CommandContext(ctx, "runuser", commandArgs...).CombinedOutput()
	clean := sanitizeWindscribeOutput(string(output))
	if err != nil {
		return "", fmt.Errorf("windscribe-cli %s failed: %s", strings.Join(args, " "), truncateWindscribeOutput(clean))
	}
	return clean, nil
}

func sanitizeWindscribeOutput(output string, secrets ...string) string {
	clean := strings.ReplaceAll(output, "\x1b", "")
	clean = strings.Map(func(r rune) rune {
		if r == '\n' || r == '\r' || r == '\t' || r >= 32 {
			return r
		}
		return -1
	}, clean)
	for _, secret := range secrets {
		if secret != "" {
			clean = strings.ReplaceAll(clean, secret, "[redacted]")
		}
	}
	clean = strings.TrimSpace(clean)
	return clean
}

func truncateWindscribeOutput(output string) string {
	if len(output) > 600 {
		return output[:600]
	}
	return output
}

func parseWindscribeLocations(output string) []windscribeLocation {
	byName := make(map[string]windscribeLocation)
	for _, raw := range strings.Split(strings.ReplaceAll(output, "\r\n", "\n"), "\n") {
		line := strings.TrimSpace(raw)
		parts := strings.Split(line, " - ")
		if len(parts) < 2 {
			continue
		}
		name := windscribeCountryName(parts[0])
		if name == "" || strings.EqualFold(name, "Best Location") {
			continue
		}
		key := strings.ToLower(name)
		available := !strings.Contains(line, "(Pro)") && !strings.Contains(line, "(Disabled)")
		current, exists := byName[key]
		if !exists || available {
			byName[key] = windscribeLocation{Name: name, Available: current.Available || available}
		}
	}
	locations := make([]windscribeLocation, 0, len(byName))
	for _, location := range byName {
		locations = append(locations, location)
	}
	sort.Slice(locations, func(i, j int) bool { return locations[i].Name < locations[j].Name })
	return locations
}

func windscribeCountryName(name string) string {
	name = strings.TrimSpace(name)
	switch {
	case strings.HasPrefix(name, "US "):
		return "United States"
	case strings.HasPrefix(name, "Canada "):
		return "Canada"
	default:
		return name
	}
}

func validWindscribeProxyCredential(value string) bool {
	if len(value) < 8 || len(value) > 64 {
		return false
	}
	for _, r := range value {
		if (r < 'a' || r > 'z') && (r < 'A' || r > 'Z') && (r < '0' || r > '9') {
			return false
		}
	}
	return true
}

func validWindscribeLoginValue(value string, minLength, maxLength int) bool {
	if len(value) < minLength || len(value) > maxLength {
		return false
	}
	return !strings.ContainsAny(value, "\x00\r\n")
}

func writeWindscribeConfig(config windscribeProxyConfig) error {
	if err := os.WriteFile(windscribeConfigPath, []byte(windscribeConfigContents(config)), 0o600); err != nil {
		return fmt.Errorf("write Windscribe config: %w", err)
	}
	account, err := user.Lookup(windscribeAccount)
	if err != nil {
		return err
	}
	uid, err := strconv.Atoi(account.Uid)
	if err != nil {
		return err
	}
	gid, err := strconv.Atoi(account.Gid)
	if err != nil {
		return err
	}
	return os.Chown(windscribeConfigPath, uid, gid)
}

func windscribeConfigContents(config windscribeProxyConfig) string {
	return fmt.Sprintf(`[Connection]
AllowLANTraffic=true
Autoconnect=true
ShareProxyGatewayEnabled=true
ShareProxyGatewayMode=SOCKS
ShareProxyGatewayPort=%d
ShareProxyGatewayWhileConnected=true
ShareProxyGatewayRequireAuth=true
ShareProxyGatewayUsername=%s
ShareProxyGatewayPassword=%s
SplitTunnelingEnabled=true
SplitTunnelingMode=Include
SplitTunnelingApps=/opt/windscribe/Windscribe
`, config.SocksPort, config.ProxyUsername, config.ProxyPassword)
}

func primaryIPv4() (string, error) {
	if routeFile, err := os.Open("/proc/net/route"); err == nil {
		interfaceName, routeErr := defaultIPv4Interface(routeFile)
		_ = routeFile.Close()
		if routeErr == nil {
			if address, addressErr := interfaceIPv4(interfaceName); addressErr == nil {
				return address, nil
			}
		}
	}
	conn, err := net.Dial("udp4", "1.1.1.1:53")
	if err != nil {
		return "", fmt.Errorf("detect Windscribe bind address: %w", err)
	}
	defer conn.Close()
	address, ok := conn.LocalAddr().(*net.UDPAddr)
	if !ok || address.IP == nil || address.IP.To4() == nil {
		return "", fmt.Errorf("Windscribe requires a primary IPv4 address")
	}
	return address.IP.String(), nil
}

func defaultIPv4Interface(reader io.Reader) (string, error) {
	scanner := bufio.NewScanner(reader)
	bestInterface := ""
	bestMetric := int(^uint(0) >> 1)
	for scanner.Scan() {
		fields := strings.Fields(scanner.Text())
		if len(fields) < 8 || fields[1] != "00000000" {
			continue
		}
		flags, err := strconv.ParseUint(fields[3], 16, 32)
		if err != nil || flags&1 == 0 {
			continue
		}
		metric, err := strconv.Atoi(fields[6])
		if err != nil || metric >= bestMetric {
			continue
		}
		bestInterface = fields[0]
		bestMetric = metric
	}
	if err := scanner.Err(); err != nil {
		return "", err
	}
	if bestInterface == "" {
		return "", fmt.Errorf("default IPv4 interface was not found")
	}
	return bestInterface, nil
}

func interfaceIPv4(name string) (string, error) {
	device, err := net.InterfaceByName(name)
	if err != nil {
		return "", err
	}
	addresses, err := device.Addrs()
	if err != nil {
		return "", err
	}
	for _, address := range addresses {
		ip, _, err := net.ParseCIDR(address.String())
		if err == nil && ip.To4() != nil && !ip.IsLoopback() {
			return ip.String(), nil
		}
	}
	return "", fmt.Errorf("interface %s has no IPv4 address", name)
}

func applyWindscribeRelay(targetIP string, port uint32) error {
	unit := fmt.Sprintf(`[Unit]
Description=Rebecca Windscribe loopback proxy
After=%s
Requires=%s

[Service]
Type=simple
ExecStart=/usr/bin/socat TCP4-LISTEN:%d,bind=127.0.0.1,reuseaddr,fork TCP4:%s:%d,connect-timeout=10
Restart=always
RestartSec=2
NoNewPrivileges=true
PrivateTmp=true
ProtectHome=true
ProtectSystem=strict

[Install]
WantedBy=multi-user.target
`, windscribeServiceName, windscribeServiceName, port, targetIP, port)
	path := filepath.Join("/etc/systemd/system", windscribeRelayUnitName)
	if err := os.WriteFile(path, []byte(unit), 0o644); err != nil {
		return fmt.Errorf("write Windscribe relay service: %w", err)
	}
	if output, err := exec.Command("systemctl", "daemon-reload").CombinedOutput(); err != nil {
		return fmt.Errorf("reload Windscribe relay service: %v: %s", err, strings.TrimSpace(string(output)))
	}
	if output, err := exec.Command("systemctl", "enable", "--now", windscribeRelayUnitName).CombinedOutput(); err != nil {
		return fmt.Errorf("start Windscribe relay service: %v: %s", err, strings.TrimSpace(string(output)))
	}
	if output, err := exec.Command("systemctl", "restart", windscribeRelayUnitName).CombinedOutput(); err != nil {
		return fmt.Errorf("restart Windscribe relay service: %v: %s", err, strings.TrimSpace(string(output)))
	}
	return nil
}

func waitForTCPAddress(address string, timeout time.Duration) error {
	deadline := time.Now().Add(timeout)
	var lastErr error
	for time.Now().Before(deadline) {
		conn, err := net.DialTimeout("tcp4", address, time.Second)
		if err == nil {
			_ = conn.Close()
			return nil
		}
		lastErr = err
		time.Sleep(500 * time.Millisecond)
	}
	return fmt.Errorf("%s did not accept connections: %v", address, lastErr)
}

func waitForAuthenticatedSocks(port int, username, password string, timeout time.Duration) error {
	deadline := time.Now().Add(timeout)
	var lastErr error
	for time.Now().Before(deadline) {
		if err := testAuthenticatedSocks5Connect(port, username, password, "example.com", 80); err == nil {
			return nil
		} else {
			lastErr = err
		}
		time.Sleep(time.Second)
	}
	return fmt.Errorf("Windscribe SOCKS proxy is not ready on 127.0.0.1:%d: %v", port, lastErr)
}

func testAuthenticatedSocks5Connect(port int, username, password, host string, targetPort uint16) error {
	conn, err := net.DialTimeout("tcp4", net.JoinHostPort("127.0.0.1", strconv.Itoa(port)), 5*time.Second)
	if err != nil {
		return err
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(10 * time.Second))
	reader := bufio.NewReader(conn)
	if _, err := conn.Write([]byte{0x05, 0x01, 0x02}); err != nil {
		return err
	}
	greeting := make([]byte, 2)
	if _, err := io.ReadFull(reader, greeting); err != nil {
		return err
	}
	if greeting[0] != 0x05 || greeting[1] != 0x02 {
		return fmt.Errorf("SOCKS username/password authentication was not accepted")
	}
	if len(username) > 255 || len(password) > 255 {
		return fmt.Errorf("SOCKS credentials are too long")
	}
	auth := []byte{0x01, byte(len(username))}
	auth = append(auth, username...)
	auth = append(auth, byte(len(password)))
	auth = append(auth, password...)
	if _, err := conn.Write(auth); err != nil {
		return err
	}
	authResponse := make([]byte, 2)
	if _, err := io.ReadFull(reader, authResponse); err != nil {
		return err
	}
	if authResponse[1] != 0x00 {
		return fmt.Errorf("SOCKS authentication failed")
	}
	hostBytes := []byte(host)
	request := []byte{0x05, 0x01, 0x00, 0x03, byte(len(hostBytes))}
	request = append(request, hostBytes...)
	portBytes := make([]byte, 2)
	binary.BigEndian.PutUint16(portBytes, targetPort)
	request = append(request, portBytes...)
	if _, err := conn.Write(request); err != nil {
		return err
	}
	response := make([]byte, 4)
	if _, err := io.ReadFull(reader, response); err != nil {
		return err
	}
	if response[1] != 0x00 {
		return fmt.Errorf("SOCKS connect failed with code %d", response[1])
	}
	switch response[3] {
	case 0x01:
		_, err = io.CopyN(io.Discard, reader, 6)
	case 0x03:
		length, readErr := reader.ReadByte()
		if readErr != nil {
			return readErr
		}
		_, err = io.CopyN(io.Discard, reader, int64(length)+2)
	case 0x04:
		_, err = io.CopyN(io.Discard, reader, 18)
	default:
		err = fmt.Errorf("SOCKS response has invalid address type %d", response[3])
	}
	return err
}

func runCommandContext(ctx context.Context, env []string, name string, args ...string) error {
	command, err := exec.LookPath(name)
	if err != nil {
		return err
	}
	cmd := exec.CommandContext(ctx, command, args...)
	if len(env) > 0 {
		cmd.Env = append(os.Environ(), env...)
	}
	output, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("%s %s: %v: %s", name, strings.Join(args, " "), err, strings.TrimSpace(string(output)))
	}
	return nil
}

func commandSucceeds(name string, args ...string) bool {
	return exec.Command(name, args...).Run() == nil
}
