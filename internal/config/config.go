// Package config decodes vgc:// VPN configuration links.
//
// A vgc link carries the whole configuration inline: the payload after the
// "vgc://" marker is Base58 (bitcoin alphabet) which decodes to gzip-compressed
// JSON. No network request is needed to resolve it.
package config

import (
	"bytes"
	"compress/gzip"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/big"
	"strings"
)

// base58Alphabet is the bitcoin Base58 alphabet: no 0, O, I or l.
const base58Alphabet = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"

// marker separates the wrapping URL from the Base58 payload.
const marker = "vgc://"

// maxDecompressed caps the gunzip output to avoid a decompression bomb.
const maxDecompressed = 1 << 20

// ErrNoMarker is returned when the input carries no vgc:// payload.
var ErrNoMarker = errors.New("config: no vgc:// marker in input")

// Config is the decoded vgc payload.
type Config struct {
	Config      Meta        `json:"config"`
	WireGuard   WireGuard   `json:"wireguard"`
	Cloak       Cloak       `json:"cloak"`
	Shadowsocks Shadowsocks `json:"shadowsocks"`
	Protocol0   Protocol0   `json:"protocol0"`
}

// Meta describes the configuration itself.
type Meta struct {
	Version  int    `json:"version"`
	Name     string `json:"name"`
	Domain   string `json:"domain"`
	Extended int    `json:"extended"`
}

// WireGuard holds a wg-quick style tunnel definition.
type WireGuard struct {
	Interface WGInterface `json:"Interface"`
	Peer      WGPeer      `json:"Peer"`
}

// WGInterface is the local side of a WireGuard tunnel.
type WGInterface struct {
	PrivateKey string `json:"PrivateKey"`
	Address    string `json:"Address"`
	DNS        string `json:"DNS"`
}

// WGPeer is the remote side of a WireGuard tunnel.
type WGPeer struct {
	PublicKey    string `json:"PublicKey"`
	PresharedKey string `json:"PresharedKey"`
	AllowedIPs   string `json:"AllowedIPs"`
	Endpoint     string `json:"Endpoint"`
}

// Cloak holds the Cloak pluggable-transport settings.
type Cloak struct {
	RemoteHost string    `json:"RemoteHost"`
	RemotePort int       `json:"RemotePort"`
	UID        string    `json:"UID"`
	PublicKey  string    `json:"PublicKey"`
	ProxyBook  ProxyBook `json:"ProxyBook"`
	ServerName string    `json:"ServerName"`
}

// ProxyBook maps a proxy method name to its settings.
type ProxyBook struct {
	Shadowsocks Shadowsocks `json:"shadowsocks"`
}

// Shadowsocks holds an ss:// endpoint. Host and Port are absent in the
// Cloak ProxyBook variant, where Cloak itself supplies the transport.
type Shadowsocks struct {
	Host     string  `json:"host"`
	Port     int     `json:"port"`
	Cipher   string  `json:"cipher"`
	Password string  `json:"password"`
	Outline  Outline `json:"outline"`
}

// Outline carries Outline-specific options.
type Outline struct {
	// Prefix is a raw byte string prepended to the first packet to make it
	// look like a TLS ClientHello.
	Prefix string `json:"prefix"`
}

// Protocol0 is a VLESS + Reality endpoint.
type Protocol0 struct {
	PublicKey  string `json:"publicKey"`
	ID         string `json:"id"`
	ShortID    string `json:"shortId"`
	Address    string `json:"address"`
	Port       int    `json:"port"`
	ServerName string `json:"serverName"`
}

// Parse extracts, decodes and unmarshals a vgc:// link. The input may be a bare
// payload, a vgc:// link, or an https:// URL wrapping one.
func Parse(input string) (*Config, error) {
	payload, err := extractPayload(input)
	if err != nil {
		return nil, err
	}

	raw, err := base58Decode(payload)
	if err != nil {
		return nil, err
	}

	plain, err := gunzip(raw)
	if err != nil {
		return nil, err
	}

	var cfg Config
	if err := json.Unmarshal(plain, &cfg); err != nil {
		return nil, fmt.Errorf("config: parse json: %w", err)
	}
	return &cfg, nil
}

// extractPayload strips any wrapping URL and returns the Base58 payload.
func extractPayload(input string) (string, error) {
	s := strings.TrimSpace(input)
	if s == "" {
		return "", ErrNoMarker
	}
	// Ссылка приходит как https://host/vgc://<payload> — берём всё после маркера.
	if i := strings.LastIndex(s, marker); i >= 0 {
		s = s[i+len(marker):]
	} else if strings.Contains(s, "://") {
		return "", ErrNoMarker
	}
	s = strings.TrimSpace(s)
	if s == "" {
		return "", ErrNoMarker
	}
	return s, nil
}

// base58Decode decodes a bitcoin-alphabet Base58 string.
func base58Decode(s string) ([]byte, error) {
	n := new(big.Int)
	radix := big.NewInt(58)
	for _, r := range s {
		idx := strings.IndexRune(base58Alphabet, r)
		if idx < 0 {
			return nil, fmt.Errorf("config: invalid base58 character %q", r)
		}
		n.Mul(n, radix)
		n.Add(n, big.NewInt(int64(idx)))
	}

	body := n.Bytes()

	// Ведущие '1' в base58 кодируют ведущие нулевые байты.
	var zeros int
	for _, r := range s {
		if r != rune(base58Alphabet[0]) {
			break
		}
		zeros++
	}

	out := make([]byte, zeros+len(body))
	copy(out[zeros:], body)
	return out, nil
}

// gunzip decompresses a gzip stream with a size cap.
func gunzip(b []byte) ([]byte, error) {
	zr, err := gzip.NewReader(bytes.NewReader(b))
	if err != nil {
		return nil, fmt.Errorf("config: gzip: %w", err)
	}
	defer func() { _ = zr.Close() }()

	plain, err := io.ReadAll(io.LimitReader(zr, maxDecompressed))
	if err != nil {
		return nil, fmt.Errorf("config: gzip read: %w", err)
	}
	if len(plain) == int(maxDecompressed) {
		return nil, errors.New("config: decompressed payload too large")
	}
	return plain, nil
}
