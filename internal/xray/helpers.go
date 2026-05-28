package xray

import (
	"errors"
	"os"
	"os/exec"
	"regexp"
	"strings"
)

type X25519KeyPair struct {
	PrivateKey string `json:"private_key"`
	PublicKey  string `json:"public_key"`
}

type MLDSA65KeyPair struct {
	Seed   string `json:"seed"`
	Verify string `json:"verify"`
}

type ECHCertificate struct {
	ECHServerKeys string `json:"echServerKeys"`
	ECHConfigList string `json:"echConfigList"`
}

func (c *Core) GetX25519(privateKey string) (X25519KeyPair, error) {
	args := []string{"x25519"}
	privateKey = strings.TrimSpace(privateKey)
	if privateKey != "" {
		args = append(args, "-i", privateKey)
	}
	output, err := c.runCommand(args...)
	if err != nil {
		return X25519KeyPair{}, err
	}
	return parseX25519Output(output)
}

func (c *Core) GetMLDSA65() (MLDSA65KeyPair, error) {
	output, err := c.runCommand("mldsa65")
	if err != nil {
		return MLDSA65KeyPair{}, err
	}
	return parseMLDSA65Output(output)
}

func (c *Core) GetECHCert(serverName string) (ECHCertificate, error) {
	serverName = strings.TrimSpace(serverName)
	if serverName == "" {
		return ECHCertificate{}, errors.New("server_name is required")
	}
	output, err := c.runCommand("tls", "ech", "--serverName", serverName)
	if err != nil {
		return ECHCertificate{}, err
	}
	return parseECHOutput(output)
}

func (c *Core) runCommand(args ...string) (string, error) {
	c.mu.Lock()
	executable := c.executablePath
	assets := c.assetsPath
	c.mu.Unlock()

	cmd := exec.Command(executable, args...)
	cmd.Env = append(os.Environ(), "XRAY_LOCATION_ASSET="+assets)
	output, err := cmd.CombinedOutput()
	if err != nil {
		detail := strings.TrimSpace(string(output))
		if detail != "" {
			return "", errors.New(detail)
		}
		return "", err
	}
	return string(output), nil
}

func parseX25519Output(output string) (X25519KeyPair, error) {
	match := regexp.MustCompile(`(?m)^Private key:\s*(\S+)\s*\r?\nPublic key:\s*(\S+)`).FindStringSubmatch(output)
	if len(match) < 3 {
		return X25519KeyPair{}, errors.New("invalid x25519 output")
	}
	return X25519KeyPair{PrivateKey: match[1], PublicKey: match[2]}, nil
}

func parseMLDSA65Output(output string) (MLDSA65KeyPair, error) {
	lines := nonEmptyLines(output)
	if len(lines) < 2 {
		return MLDSA65KeyPair{}, errors.New("invalid mldsa65 output")
	}
	seed := valueAfterColon(lines[0])
	verify := valueAfterColon(lines[1])
	if seed == "" || verify == "" {
		return MLDSA65KeyPair{}, errors.New("invalid mldsa65 output")
	}
	return MLDSA65KeyPair{Seed: seed, Verify: verify}, nil
}

func parseECHOutput(output string) (ECHCertificate, error) {
	lines := nonEmptyLines(output)
	if len(lines) < 4 {
		return ECHCertificate{}, errors.New("invalid ECH output")
	}
	return ECHCertificate{
		ECHConfigList: lines[1],
		ECHServerKeys: lines[3],
	}, nil
}

func nonEmptyLines(output string) []string {
	rawLines := strings.Split(output, "\n")
	lines := make([]string, 0, len(rawLines))
	for _, line := range rawLines {
		line = strings.TrimSpace(line)
		if line != "" {
			lines = append(lines, line)
		}
	}
	return lines
}

func valueAfterColon(line string) string {
	_, value, ok := strings.Cut(line, ":")
	if !ok {
		return ""
	}
	return strings.TrimSpace(value)
}
