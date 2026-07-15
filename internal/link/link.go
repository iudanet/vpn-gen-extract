// Package link renders decoded VPN configs as client-facing links.
package link

import (
	"encoding/base64"
	"fmt"
	"net"
	"net/url"
	"strconv"
	"strings"

	"github.com/iudanet/vpn_gen_extract/internal/config"
)

// Shadowsocks renders an ss:// link in SIP002 form, usable by Outline.
//
// The userinfo is base64url(cipher:password) without padding; the Outline
// prefix, when present, travels as a ?prefix= query parameter.
func Shadowsocks(cfg *config.Config) (string, error) {
	ss := cfg.Shadowsocks
	if ss.Host == "" || ss.Port == 0 {
		return "", fmt.Errorf("link: shadowsocks endpoint is missing")
	}

	userInfo := base64.RawURLEncoding.EncodeToString([]byte(ss.Cipher + ":" + ss.Password))
	host := net.JoinHostPort(ss.Host, strconv.Itoa(ss.Port))

	u := &url.URL{
		Scheme:   "ss",
		User:     url.User(userInfo),
		Host:     host,
		Fragment: cfg.Config.Name,
	}
	if p := ss.Outline.Prefix; p != "" {
		u.RawQuery = "prefix=" + escapePrefixBytes(p)
	}
	return u.String(), nil
}

// escapePrefixBytes percent-encodes an Outline prefix.
//
// The prefix is a byte string that the JSON decoder widened into runes: each
// rune is one byte of the wire prefix (latin-1), so 0xA8 must travel as %A8.
// Encoding the string as UTF-8 would emit %C2%A8 and corrupt the handshake.
func escapePrefixBytes(prefix string) string {
	var b strings.Builder
	for _, r := range prefix {
		if r < 0 || r > 0xFF {
			// Руна вне latin-1 не может быть частью байтового префикса.
			continue
		}
		// Проверка выше гарантирует 0..0xFF, поэтому конверсия безопасна.
		c := byte(r) // #nosec G115
		if shouldEscapePrefixByte(c) {
			fmt.Fprintf(&b, "%%%02X", c)
			continue
		}
		b.WriteByte(c)
	}
	return b.String()
}

// shouldEscapePrefixByte reports whether c must be percent-encoded in a query
// value. Unreserved characters (RFC 3986 §2.3) travel as-is.
func shouldEscapePrefixByte(c byte) bool {
	switch {
	case c >= 'a' && c <= 'z', c >= 'A' && c <= 'Z', c >= '0' && c <= '9':
		return false
	case c == '-', c == '_', c == '.', c == '~':
		return false
	default:
		return true
	}
}

// VLESS renders a vless:// link for the Reality endpoint (protocol0).
func VLESS(cfg *config.Config) (string, error) {
	p := cfg.Protocol0
	if p.Address == "" || p.Port == 0 || p.ID == "" {
		return "", fmt.Errorf("link: vless endpoint is missing")
	}

	q := url.Values{}
	q.Set("type", "tcp")
	q.Set("security", "reality")
	q.Set("encryption", "none")
	q.Set("flow", "xtls-rprx-vision")
	q.Set("pbk", p.PublicKey)
	q.Set("fp", "chrome")
	if p.ServerName != "" {
		q.Set("sni", p.ServerName)
	}
	if p.ShortID != "" {
		q.Set("sid", p.ShortID)
	}

	u := &url.URL{
		Scheme:   "vless",
		User:     url.User(p.ID),
		Host:     net.JoinHostPort(p.Address, strconv.Itoa(p.Port)),
		RawQuery: q.Encode(),
		Fragment: cfg.Config.Name,
	}
	return u.String(), nil
}

// WireGuard renders a wg-quick compatible .conf file body.
func WireGuard(cfg *config.Config) (string, error) {
	wg := cfg.WireGuard
	if wg.Interface.PrivateKey == "" || wg.Peer.Endpoint == "" {
		return "", fmt.Errorf("link: wireguard config is missing")
	}

	var b strings.Builder
	b.WriteString("[Interface]\n")
	fmt.Fprintf(&b, "PrivateKey = %s\n", wg.Interface.PrivateKey)
	fmt.Fprintf(&b, "Address = %s\n", wg.Interface.Address)
	if wg.Interface.DNS != "" {
		fmt.Fprintf(&b, "DNS = %s\n", wg.Interface.DNS)
	}
	b.WriteString("\n[Peer]\n")
	fmt.Fprintf(&b, "PublicKey = %s\n", wg.Peer.PublicKey)
	if wg.Peer.PresharedKey != "" {
		fmt.Fprintf(&b, "PresharedKey = %s\n", wg.Peer.PresharedKey)
	}
	fmt.Fprintf(&b, "AllowedIPs = %s\n", wg.Peer.AllowedIPs)
	fmt.Fprintf(&b, "Endpoint = %s\n", wg.Peer.Endpoint)
	b.WriteString("PersistentKeepalive = 25\n")
	return b.String(), nil
}

// Cloak renders a Cloak client JSON configuration.
func Cloak(cfg *config.Config) (string, error) {
	c := cfg.Cloak
	if c.RemoteHost == "" || c.UID == "" {
		return "", fmt.Errorf("link: cloak config is missing")
	}

	// Собираем JSON вручную, чтобы сохранить порядок полей как в клиенте Cloak.
	var b strings.Builder
	b.WriteString("{\n")
	fmt.Fprintf(&b, "  %q: %q,\n", "Transport", "direct")
	fmt.Fprintf(&b, "  %q: %q,\n", "ProxyMethod", "shadowsocks")
	fmt.Fprintf(&b, "  %q: %q,\n", "EncryptionMethod", "plain")
	fmt.Fprintf(&b, "  %q: %q,\n", "UID", c.UID)
	fmt.Fprintf(&b, "  %q: %q,\n", "PublicKey", c.PublicKey)
	fmt.Fprintf(&b, "  %q: %q,\n", "ServerName", c.ServerName)
	fmt.Fprintf(&b, "  %q: %d,\n", "NumConn", 4)
	fmt.Fprintf(&b, "  %q: %q,\n", "RemoteHost", c.RemoteHost)
	fmt.Fprintf(&b, "  %q: %q\n", "RemotePort", strconv.Itoa(c.RemotePort))
	b.WriteString("}\n")
	return b.String(), nil
}
