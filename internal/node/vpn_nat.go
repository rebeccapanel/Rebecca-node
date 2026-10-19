package node

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"runtime"
	"strings"
	"time"
)

const vpnNATCommandTimeout = 15 * time.Second

type vpnIPTRule struct {
	table string
	chain string
	spec  []string
}

func vpnNATComment(tag string) string {
	return "rebecca-vpn:" + safeName(tag)
}

func vpnApplyDirectNAT(tag string, iface string, pool string) error {
	ctx, cancel := context.WithTimeout(context.Background(), vpnNATCommandTimeout)
	defer cancel()
	if strings.TrimSpace(pool) == "" {
		return fmt.Errorf("direct NAT pool is empty")
	}
	egress, err := vpnDefaultRouteIface(ctx)
	if err != nil {
		return fmt.Errorf("detect default-route interface: %w", err)
	}
	enableVPNForwarding()
	for _, rule := range vpnDirectNATRules(tag, iface, pool, egress) {
		if err := vpnEnsureIPTRule(ctx, rule); err != nil {
			return err
		}
	}
	return nil
}

func vpnRemoveDirectNAT(tag string) error {
	ctx, cancel := context.WithTimeout(context.Background(), vpnNATCommandTimeout)
	defer cancel()
	comment := vpnNATComment(tag)
	for _, tableChain := range []struct {
		table string
		chain string
	}{
		{"nat", "POSTROUTING"},
		{"filter", "FORWARD"},
	} {
		out, err := vpnRunIPT(ctx, "-t", tableChain.table, "-S", tableChain.chain)
		if err != nil {
			continue
		}
		for _, lineText := range strings.Split(out, "\n") {
			lineText = strings.TrimSpace(lineText)
			if lineText == "" || !strings.Contains(lineText, comment) {
				continue
			}
			fields := splitRuleLine(lineText)
			if len(fields) < 2 || fields[0] != "-A" {
				continue
			}
			fields[0] = "-D"
			args := append([]string{"-t", tableChain.table}, fields...)
			if output, err := vpnRunIPT(ctx, args...); err != nil {
				return fmt.Errorf("iptables %s: %v: %s", strings.Join(args, " "), err, strings.TrimSpace(output))
			}
		}
	}
	return nil
}

func vpnDirectNATRules(tag string, iface string, pool string, egress string) []vpnIPTRule {
	comment := []string{"-m", "comment", "--comment", vpnNATComment(tag)}
	rules := []vpnIPTRule{}
	blockedV4, _ := ovBlockedDestinations()
	for _, blocked := range blockedV4 {
		rules = append(rules, vpnIPTRule{"filter", "FORWARD", append([]string{
			"-i", iface, "-d", blocked, "-j", "REJECT",
		}, comment...)})
	}
	rules = append(rules,
		vpnIPTRule{"nat", "POSTROUTING", append([]string{
			"-s", pool, "-o", egress, "-j", "MASQUERADE",
		}, comment...)},
		vpnIPTRule{"filter", "FORWARD", append([]string{
			"-i", iface, "-o", egress, "-s", pool, "-j", "ACCEPT",
		}, comment...)},
		vpnIPTRule{"filter", "FORWARD", append([]string{
			"-i", egress, "-o", iface,
			"-m", "conntrack", "--ctstate", "RELATED,ESTABLISHED", "-j", "ACCEPT",
		}, comment...)},
		vpnIPTRule{"filter", "FORWARD", append([]string{
			"-o", iface, "-p", "tcp", "--tcp-flags", "SYN,RST", "SYN",
			"-j", "TCPMSS", "--clamp-mss-to-pmtu",
		}, comment...)},
	)
	return rules
}

func vpnEnsureIPTRule(ctx context.Context, rule vpnIPTRule) error {
	if vpnIPTRuleExists(ctx, rule) {
		return nil
	}
	args := append([]string{"-t", rule.table, "-A", rule.chain}, rule.spec...)
	out, err := vpnRunIPT(ctx, args...)
	if err != nil {
		return fmt.Errorf("iptables %s: %v: %s", strings.Join(args, " "), err, strings.TrimSpace(out))
	}
	return nil
}

func vpnIPTRuleExists(ctx context.Context, rule vpnIPTRule) bool {
	args := append([]string{"-t", rule.table, "-C", rule.chain}, rule.spec...)
	_, err := vpnRunIPT(ctx, args...)
	return err == nil
}

func vpnRunIPT(ctx context.Context, args ...string) (string, error) {
	out, err := exec.CommandContext(ctx, "iptables", args...).CombinedOutput()
	return string(out), err
}

func vpnDefaultRouteIface(ctx context.Context) (string, error) {
	out, err := exec.CommandContext(ctx, "ip", "-o", "route", "get", "1.1.1.1").CombinedOutput()
	if err != nil {
		return "", fmt.Errorf("ip route get: %v: %s", err, strings.TrimSpace(string(out)))
	}
	fields := strings.Fields(string(out))
	for i, field := range fields {
		if field == "dev" && i+1 < len(fields) {
			return fields[i+1], nil
		}
	}
	return "", fmt.Errorf("could not parse egress interface from %q", strings.TrimSpace(string(out)))
}

func splitRuleLine(line string) []string {
	raw := strings.Fields(line)
	out := make([]string, 0, len(raw))
	for _, field := range raw {
		if len(field) >= 2 && field[0] == '"' && field[len(field)-1] == '"' {
			field = field[1 : len(field)-1]
		}
		out = append(out, field)
	}
	return out
}

func enableVPNForwarding() {
	if runtime.GOOS == "windows" {
		return
	}
	_ = os.WriteFile("/proc/sys/net/ipv4/ip_forward", []byte("1\n"), 0o644)
	_ = os.WriteFile("/proc/sys/net/ipv6/conf/all/forwarding", []byte("1\n"), 0o644)
	_ = os.WriteFile("/proc/sys/net/ipv4/conf/all/rp_filter", []byte("2\n"), 0o644)
	_ = os.WriteFile("/proc/sys/net/ipv4/conf/default/rp_filter", []byte("2\n"), 0o644)
	body := "net.ipv4.ip_forward=1\n" +
		"net.ipv6.conf.all.forwarding=1\n" +
		"net.ipv4.conf.all.rp_filter=2\n" +
		"net.ipv4.conf.default.rp_filter=2\n"
	if err := os.WriteFile("/etc/sysctl.d/99-rebecca-vpn.conf", []byte(body), 0o644); err == nil {
		_ = exec.Command("sysctl", "--system").Run()
	}
}

func enableVPNTProxyHostNetworking(pools ...string) {
	if runtime.GOOS == "windows" {
		return
	}
	enableVPNForwarding()
	if _, err := os.Stat("/proc/sys/net/mptcp/enabled"); err == nil {
		_ = os.WriteFile("/proc/sys/net/mptcp/enabled", []byte("0\n"), 0o644)
		_ = os.WriteFile("/etc/sysctl.d/99-rebecca-vpn-tproxy.conf", []byte("net.mptcp.enabled=0\n"), 0o644)
	}
	if modprobe, err := exec.LookPath("modprobe"); err == nil {
		for _, module := range []string{"nf_tproxy_ipv4", "nf_conntrack"} {
			_ = exec.Command(modprobe, module).Run()
		}
	}
	trustFirewallSources(pools...)
}

func trustFirewallSources(pools ...string) {
	if !firewalldRunning() {
		return
	}
	for _, pool := range pools {
		pool = strings.TrimSpace(pool)
		if pool == "" {
			continue
		}
		out, _ := exec.Command("firewall-cmd", "--zone=trusted", "--query-source="+pool).CombinedOutput()
		if strings.TrimSpace(string(out)) == "yes" {
			continue
		}
		_ = exec.Command("firewall-cmd", "--zone=trusted", "--add-source="+pool).Run()
		_ = exec.Command("firewall-cmd", "--permanent", "--zone=trusted", "--add-source="+pool).Run()
	}
}

func firewalldRunning() bool {
	if !commandExists("firewall-cmd") {
		return false
	}
	out, err := exec.Command("firewall-cmd", "--state").CombinedOutput()
	return err == nil && strings.TrimSpace(string(out)) == "running"
}
