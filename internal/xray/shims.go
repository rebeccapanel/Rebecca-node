package xray

import (
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"log"
	"strings"
)

type commonErrors struct{}

func (commonErrors) NewError(message ...any) error { return errors.New(fmt.Sprint(message...)) }

func (commonErrors) NewErrorf(format string, args ...any) error { return fmt.Errorf(format, args...) }

var common commonErrors

type apiLogger struct{}

func (apiLogger) Debug(args ...any) {}

func (apiLogger) Info(args ...any) { log.Println(args...) }

func (apiLogger) Warning(args ...any) { log.Println(args...) }

var logger apiLogger

type binFolderConfig struct{ path string }

func (c binFolderConfig) GetBinFolderPath() string {
	if c.path != "" {
		return c.path
	}
	return "."
}

func SetBinFolderPath(path string) { config.path = strings.TrimSpace(path) }

var config binFolderConfig

type wireguardKeys struct{}

func (wireguardKeys) KeyToHex(key string) (string, error) {
	if key == "" {
		return "", nil
	}
	raw, err := decodeWireguardKey(key)
	if err != nil {
		return "", err
	}
	return hex.EncodeToString(raw[:]), nil
}

var wgutil wireguardKeys

func decodeWireguardKey(key string) ([32]byte, error) {
	var out [32]byte
	if key == "" {
		return out, errors.New("wireguard: empty key")
	}

	if len(key) == 64 {
		if raw, err := hex.DecodeString(key); err == nil {
			if len(raw) != 32 {
				return out, errors.New("wireguard: key must decode to 32 bytes")
			}
			copy(out[:], raw)
			return out, nil
		}
	}

	trimmed := strings.TrimRight(key, "=")
	var raw []byte
	var err error
	if strings.ContainsAny(trimmed, "+/") {
		raw, err = base64.RawStdEncoding.DecodeString(trimmed)
	} else {
		raw, err = base64.RawURLEncoding.DecodeString(trimmed)
	}
	if err != nil {
		return out, err
	}
	if len(raw) != 32 {
		return out, errors.New("wireguard: key must decode to 32 bytes")
	}
	copy(out[:], raw)
	return out, nil
}
