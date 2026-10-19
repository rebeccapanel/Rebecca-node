package node

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

// This file installs the forwarding + NAT rules that make a WireGuard inbound
// actually route client traffic to the internet. Enabling ip_forward alone is
// not enough: forwarded packets still leave with their private tunnel source
// (10.70.x.y), so replies have no route back and the client sees "handshake OK,
// bytes sent, zero received". Per interface we install:
//
//  1. MASQUERADE (source NAT) on POSTROUTING for the pool, out the host's
//     default-route interface, so replies come back to the node.
//  2. FORWARD ACCEPT both directions for the wg interface, so traffic survives a
//     default DROP policy (common under Docker or a hardened host).
//  3. TCP MSS clamping on forwarded SYNs, to avoid the classic "ping works but
//     web pages hang" PMTU black-hole over the tunnel.
//
// Every rule carries an iptables comment unique to the interface. Apply and
// Remove share the exact rule specs (one source of truth), and Apply is
// check-before-insert so it is safe to re-run on every reconcile.

func wgCommentTag(iface string) string { return "rebecca-wg:" + iface }

type wgRule struct {
	table string
	chain string
	spec  []string
}

func wgRulesFor(iface, pool, egress string) []wgRule {
	comment := []string{"-m", "comment", "--comment", wgCommentTag(iface)}
	return []wgRule{
		{"nat", "POSTROUTING", append([]string{
			"-s", pool, "-o", egress, "-j", "MASQUERADE",
		}, comment...)},
		{"filter", "FORWARD", append([]string{
			"-i", iface, "-o", egress, "-j", "ACCEPT",
		}, comment...)},
		{"filter", "FORWARD", append([]string{
			"-i", egress, "-o", iface,
			"-m", "conntrack", "--ctstate", "RELATED,ESTABLISHED", "-j", "ACCEPT",
		}, comment...)},
		{"filter", "FORWARD", append([]string{
			"-o", iface, "-p", "tcp", "--tcp-flags", "SYN,RST", "SYN",
			"-j", "TCPMSS", "--clamp-mss-to-pmtu",
		}, comment...)},
	}
}

func wgApplyNAT(ctx context.Context, iface, pool string) error {
	egress, err := wgDefaultRouteIface(ctx)
	if err != nil {
		return fmt.Errorf("detect default-route interface: %w", err)
	}
	for _, rule := range wgRulesFor(iface, pool, egress) {
		if err := wgEnsureRule(ctx, rule); err != nil {
			return err
		}
	}
	return nil
}

// wgRemoveNAT deletes every rule this file installed for the interface. It works
// by the interface's unique comment tag rather than rebuilding exact specs, so a
// rule installed when the egress interface was eth0 is still removed even if the
// default route later changed. Best-effort and idempotent.
func wgRemoveNAT(ctx context.Context, iface string) error {
	tag := wgCommentTag(iface)
	for _, tc := range []struct{ table, chain string }{
		{"nat", "POSTROUTING"},
		{"filter", "FORWARD"},
	} {
		out, err := wgRunIPT(ctx, "-t", tc.table, "-S", tc.chain)
		if err != nil {
			continue
		}
		for _, lineText := range strings.Split(out, "\n") {
			lineText = strings.TrimSpace(lineText)
			if lineText == "" || !strings.Contains(lineText, tag) {
				continue
			}
			fields := splitRuleLine(lineText)
			if len(fields) < 2 || fields[0] != "-A" {
				continue
			}
			fields[0] = "-D"
			args := append([]string{"-t", tc.table}, fields...)
			if delOut, delErr := wgRunIPT(ctx, args...); delErr != nil {
				return fmt.Errorf("iptables %s: %v: %s", strings.Join(args, " "), delErr, strings.TrimSpace(delOut))
			}
		}
	}
	return nil
}

func wgEnsureRule(ctx context.Context, rule wgRule) error {
	if wgRuleExists(ctx, rule) {
		return nil
	}
	args := append([]string{"-t", rule.table, "-A", rule.chain}, rule.spec...)
	out, err := wgRunIPT(ctx, args...)
	if err != nil {
		return fmt.Errorf("iptables %s: %v: %s", strings.Join(args, " "), err, strings.TrimSpace(out))
	}
	return nil
}

func wgRuleExists(ctx context.Context, rule wgRule) bool {
	args := append([]string{"-t", rule.table, "-C", rule.chain}, rule.spec...)
	_, err := wgRunIPT(ctx, args...)
	return err == nil
}

// splitRuleLine tokenises an `iptables -S` line, stripping the double quotes
// iptables wraps the --comment value in so the replayed -D spec matches what was
// installed.
// wgDefaultRouteIface returns the interface the host uses to reach the internet,
// read from the kernel route to a public address. This is the interface we
// MASQUERADE out of.
func wgDefaultRouteIface(ctx context.Context) (string, error) {
	out, err := wgRunIP(ctx, "-o", "route", "get", "1.1.1.1")
	if err != nil {
		return "", fmt.Errorf("ip route get: %v: %s", err, strings.TrimSpace(out))
	}
	fields := strings.Fields(out)
	for i, field := range fields {
		if field == "dev" && i+1 < len(fields) {
			return fields[i+1], nil
		}
	}
	return "", fmt.Errorf("could not parse egress interface from %q", strings.TrimSpace(out))
}

func wgRunIPT(ctx context.Context, args ...string) (string, error) {
	out, err := exec.CommandContext(ctx, "iptables", args...).CombinedOutput()
	return string(out), err
}

func wgApplyTProxy(ctx context.Context, baseDir string, inbound wgRuntimeInbound, iface string) error {
	nft, err := exec.LookPath("nft")
	if err != nil {
		return fmt.Errorf("nft executable not found")
	}
	pool := firstString(inbound.Settings["address_pool"], inbound.Settings["ipv4_pool_cidr"], wgDefaultPool)
	enableVPNTProxyHostNetworking(pool)
	dir := filepath.Join(baseDir, iface)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	path := filepath.Join(dir, "nftables.nft")
	if err := os.WriteFile(path, []byte(wgTProxyScript(inbound, iface)), 0o600); err != nil {
		return err
	}
	_ = exec.CommandContext(ctx, nft, "delete", "table", "inet", wgTProxyTableName(iface)).Run()
	if output, err := exec.CommandContext(ctx, nft, "-f", path).CombinedOutput(); err != nil {
		return fmt.Errorf("apply WireGuard nftables %s: %v: %s", inbound.Tag, err, strings.TrimSpace(string(output)))
	}
	if err := applyTProxyRouting(); err != nil {
		return err
	}
	return nil
}

func wgRemoveTProxy(ctx context.Context, iface string) error {
	nft, err := exec.LookPath("nft")
	if err != nil {
		return nil
	}
	output, err := exec.CommandContext(ctx, nft, "delete", "table", "inet", wgTProxyTableName(iface)).CombinedOutput()
	if err != nil && !strings.Contains(strings.ToLower(string(output)), "no such file or directory") {
		return fmt.Errorf("delete WireGuard nftables table %s: %v: %s", iface, err, strings.TrimSpace(string(output)))
	}
	return nil
}

func wgTProxyTableName(iface string) string {
	return "rebecca_wireguard_" + iface
}

func wgTProxyScript(inbound wgRuntimeInbound, iface string) string {
	pool := firstString(inbound.Settings["address_pool"], inbound.Settings["ipv4_pool_cidr"], wgDefaultPool)
	blockedV4, blockedV6 := ovBlockedDestinations()
	var rules strings.Builder
	if len(blockedV4) > 0 {
		line(&rules, fmt.Sprintf(`    iifname "%s" ip daddr { %s } drop`, iface, strings.Join(blockedV4, ", ")))
	}
	if len(blockedV6) > 0 {
		line(&rules, fmt.Sprintf(`    iifname "%s" ip6 daddr { %s } drop`, iface, strings.Join(blockedV6, ", ")))
	}
	return fmt.Sprintf(`table inet %s {
  chain prerouting {
    type filter hook prerouting priority mangle; policy accept;
%s
    iifname "%s" meta mark != 0xff meta l4proto { tcp, udp } tproxy ip to 127.0.0.1:%d meta mark set 1 accept
  }
  chain postrouting {
    type nat hook postrouting priority srcnat; policy accept;
    ip saddr %s oifname != "%s" meta l4proto icmp masquerade
  }
}
`, wgTProxyTableName(iface), strings.TrimRight(rules.String(), "\n"), iface, inbound.TunnelPort, pool, iface)
}
