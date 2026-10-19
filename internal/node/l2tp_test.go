package node

import (
	"slices"
	"strings"
	"testing"
	"time"
)

func TestNoninteractivePackageArgsPreserveExistingConfig(t *testing.T) {
	if got := noninteractivePackageArgs("apt-get", []string{"install", "-y", "strongswan"}); !slices.Equal(got, []string{"-o", "Dpkg::Options::=--force-confold", "install", "-y", "strongswan"}) {
		t.Fatalf("unexpected apt args: %#v", got)
	}
	if got := noninteractivePackageArgs("dpkg", []string{"--configure", "-a"}); !slices.Equal(got, []string{"--force-confold", "--configure", "-a"}) {
		t.Fatalf("unexpected dpkg args: %#v", got)
	}
}

func TestL2TPPoolRangeUsesCIDRCapacity(t *testing.T) {
	local, pool := l2tpPoolRange("10.67.0.0/16")
	if local != "10.67.0.1" {
		t.Fatalf("unexpected local IP: %s", local)
	}
	if pool != "10.67.0.10-10.67.255.254" {
		t.Fatalf("unexpected pool range: %s", pool)
	}
}

func TestL2TPPoolRangeHandlesSmallCIDR(t *testing.T) {
	local, pool := l2tpPoolRange("10.67.0.0/30")
	if local != "10.67.0.1" {
		t.Fatalf("unexpected local IP: %s", local)
	}
	if pool != "10.67.0.2-10.67.0.2" {
		t.Fatalf("unexpected pool range: %s", pool)
	}
}

func TestNormalizeL2TPRuntimeInboundLocksPorts(t *testing.T) {
	inbound := normalizeL2TPRuntimeInbound(l2tpRuntimeInbound{
		Port:       3974,
		TunnelPort: 41941,
		Settings: map[string]any{
			"l2tp_port":        3974,
			"ipsec_ike_port":   1500,
			"ipsec_nat_port":   14500,
			"xray_tunnel_port": 41941,
			"tproxy_port":      41941,
		},
	})

	if inbound.Port != 1701 || inbound.TunnelPort != 1702 {
		t.Fatalf("unexpected ports: public=%d tunnel=%d", inbound.Port, inbound.TunnelPort)
	}
	if inbound.Settings["l2tp_port"] != 1701 || inbound.Settings["ipsec_ike_port"] != 500 || inbound.Settings["ipsec_nat_port"] != 4500 || inbound.Settings["tunnel_port"] != 1702 {
		t.Fatalf("fixed settings were not enforced: %#v", inbound.Settings)
	}
	if _, ok := inbound.Settings["xray_tunnel_port"]; ok {
		t.Fatalf("legacy xray_tunnel_port should be removed")
	}
	if _, ok := inbound.Settings["tproxy_port"]; ok {
		t.Fatalf("legacy tproxy_port should be removed")
	}
}

func TestL2TPLibreswanConfigSupportsNATClients(t *testing.T) {
	config := l2tpLibreswanConfig(l2tpFixedPort)
	for _, expected := range []string{
		"conn rebecca-l2tp-nat",
		"rightsubnet=vhost:%no,%priv",
		"also=rebecca-l2tp",
		"encapsulation=yes",
	} {
		if !strings.Contains(config, expected) {
			t.Fatalf("Libreswan config is missing %q:\n%s", expected, config)
		}
	}
}

func TestL2TPChapSecretsExcludeExpiredAndLimitedUsers(t *testing.T) {
	limit, expired := int64(100), time.Now().Unix()-1
	secrets := l2tpChapSecrets([]vpnRuntimeUser{
		{VPNUsername: "allowed", Password: "secret", Status: "active", UsedTraffic: 99, DataLimit: &limit, IPv4Address: "10.67.0.10"},
		{VPNUsername: "limited", Password: "secret", Status: "active", UsedTraffic: 100, DataLimit: &limit, IPv4Address: "10.67.0.11"},
		{VPNUsername: "expired", Password: "secret", Status: "active", Expire: &expired, IPv4Address: "10.67.0.12"},
	})
	if !strings.Contains(secrets, `"allowed" rebecca-l2tp "secret" 10.67.0.10`) {
		t.Fatalf("eligible user missing from chap-secrets:\n%s", secrets)
	}
	if strings.Contains(secrets, "limited") || strings.Contains(secrets, "expired") {
		t.Fatalf("ineligible users remained in chap-secrets:\n%s", secrets)
	}
}
