package link

import (
	"encoding/base64"
	"net/url"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/iudanet/vpn_gen_extract/internal/config"
)

func sampleConfig() *config.Config {
	return &config.Config{
		Config: config.Meta{Name: "test cfg", Domain: "example.com"},
		WireGuard: config.WireGuard{
			Interface: config.WGInterface{PrivateKey: "privkey", Address: "10.0.0.2/32", DNS: "1.1.1.1"},
			Peer: config.WGPeer{
				PublicKey: "pubkey", PresharedKey: "psk",
				AllowedIPs: "0.0.0.0/0", Endpoint: "example.com:51820",
			},
		},
		Cloak: config.Cloak{
			RemoteHost: "example.com", RemotePort: 443,
			UID: "dWlkCg==", PublicKey: "pubkey", ServerName: "sni.example.com",
		},
		Shadowsocks: config.Shadowsocks{
			Host: "example.com", Port: 8388,
			Cipher: "chacha20-ietf-poly1305", Password: "pw",
			Outline: config.Outline{Prefix: "\x16\x03\x01"},
		},
		Protocol0: config.Protocol0{
			PublicKey: "rpk", ID: "uuid-1", ShortID: "abcd",
			Address: "example.com", Port: 443, ServerName: "www.example.org",
		},
	}
}

func TestShadowsocks(t *testing.T) {
	got, err := Shadowsocks(sampleConfig())
	require.NoError(t, err)

	u, err := url.Parse(got)
	require.NoError(t, err)
	assert.Equal(t, "ss", u.Scheme)
	assert.Equal(t, "example.com:8388", u.Host)
	assert.Equal(t, "test cfg", u.Fragment)

	// userinfo — base64url(cipher:password) без паддинга.
	raw, err := base64.RawURLEncoding.DecodeString(u.User.Username())
	require.NoError(t, err)
	assert.Equal(t, "chacha20-ietf-poly1305:pw", string(raw))

	// Префикс обязан пережить кодирование в URL без потерь.
	assert.Equal(t, "\x16\x03\x01", u.Query().Get("prefix"))
}

// Байт 0xA8 из префикса Outline должен ехать как %A8, а не как UTF-8 %C2%A8:
// иначе подделка TLS ClientHello ломается.
func TestShadowsocksPrefixHighByteIsNotUTF8Encoded(t *testing.T) {
	cfg := sampleConfig()
	// Реальный префикс: 16 03 01 00 a8 01 01.
	cfg.Shadowsocks.Outline.Prefix = "\x16\x03\x01\x00¨\x01\x01"

	got, err := Shadowsocks(cfg)
	require.NoError(t, err)

	assert.Contains(t, got, "prefix=%16%03%01%00%A8%01%01")
	assert.NotContains(t, got, "%C2%A8")
}

func TestEscapePrefixBytes(t *testing.T) {
	tests := []struct {
		name   string
		prefix string
		want   string
	}{
		{"tls client hello", "\x16\x03\x01\x00¨\x01\x01", "%16%03%01%00%A8%01%01"},
		{"all high bytes", "\u00ff\u00fe", "%FF%FE"},
		{"unreserved pass through", "aZ9-_.~", "aZ9-_.~"},
		{"reserved escaped", "a b&c", "a%20b%26c"},
		{"empty", "", ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, escapePrefixBytes(tt.prefix))
		})
	}
}

// Клиент читает prefix как байты, поэтому декодирование должно вернуть
// ровно исходные 7 байт, а не 8.
func TestShadowsocksPrefixDecodesToOriginalBytes(t *testing.T) {
	cfg := sampleConfig()
	cfg.Shadowsocks.Outline.Prefix = "\x16\x03\x01\x00¨\x01\x01"

	got, err := Shadowsocks(cfg)
	require.NoError(t, err)

	u, err := url.Parse(got)
	require.NoError(t, err)

	decoded := u.Query().Get("prefix")
	assert.Equal(t, []byte{0x16, 0x03, 0x01, 0x00, 0xa8, 0x01, 0x01}, []byte(decoded))
	assert.Len(t, []byte(decoded), 7)
}

func TestShadowsocksWithoutPrefix(t *testing.T) {
	cfg := sampleConfig()
	cfg.Shadowsocks.Outline.Prefix = ""

	got, err := Shadowsocks(cfg)
	require.NoError(t, err)
	assert.NotContains(t, got, "prefix=")
}

func TestShadowsocksMissingEndpoint(t *testing.T) {
	cfg := sampleConfig()
	cfg.Shadowsocks.Host = ""

	_, err := Shadowsocks(cfg)
	assert.Error(t, err)
}

func TestVLESS(t *testing.T) {
	got, err := VLESS(sampleConfig())
	require.NoError(t, err)

	u, err := url.Parse(got)
	require.NoError(t, err)
	assert.Equal(t, "vless", u.Scheme)
	assert.Equal(t, "uuid-1", u.User.Username())
	assert.Equal(t, "example.com:443", u.Host)
	assert.Equal(t, "test cfg", u.Fragment)

	q := u.Query()
	assert.Equal(t, "reality", q.Get("security"))
	assert.Equal(t, "none", q.Get("encryption"))
	assert.Equal(t, "rpk", q.Get("pbk"))
	assert.Equal(t, "abcd", q.Get("sid"))
	assert.Equal(t, "www.example.org", q.Get("sni"))
}

func TestVLESSMissingID(t *testing.T) {
	cfg := sampleConfig()
	cfg.Protocol0.ID = ""

	_, err := VLESS(cfg)
	assert.Error(t, err)
}

func TestWireGuard(t *testing.T) {
	got, err := WireGuard(sampleConfig())
	require.NoError(t, err)

	assert.Contains(t, got, "[Interface]")
	assert.Contains(t, got, "PrivateKey = privkey")
	assert.Contains(t, got, "Address = 10.0.0.2/32")
	assert.Contains(t, got, "DNS = 1.1.1.1")
	assert.Contains(t, got, "[Peer]")
	assert.Contains(t, got, "PublicKey = pubkey")
	assert.Contains(t, got, "PresharedKey = psk")
	assert.Contains(t, got, "Endpoint = example.com:51820")
	// Секция Interface должна идти раньше Peer.
	assert.Less(t, strings.Index(got, "[Interface]"), strings.Index(got, "[Peer]"))
}

func TestWireGuardOmitsEmptyPresharedKey(t *testing.T) {
	cfg := sampleConfig()
	cfg.WireGuard.Peer.PresharedKey = ""

	got, err := WireGuard(cfg)
	require.NoError(t, err)
	assert.NotContains(t, got, "PresharedKey")
}

func TestWireGuardMissingKey(t *testing.T) {
	cfg := sampleConfig()
	cfg.WireGuard.Interface.PrivateKey = ""

	_, err := WireGuard(cfg)
	assert.Error(t, err)
}

func TestCloak(t *testing.T) {
	got, err := Cloak(sampleConfig())
	require.NoError(t, err)

	assert.Contains(t, got, `"UID": "dWlkCg=="`)
	assert.Contains(t, got, `"ServerName": "sni.example.com"`)
	assert.Contains(t, got, `"RemoteHost": "example.com"`)
	assert.Contains(t, got, `"RemotePort": "443"`)
}

func TestCloakMissingUID(t *testing.T) {
	cfg := sampleConfig()
	cfg.Cloak.UID = ""

	_, err := Cloak(cfg)
	assert.Error(t, err)
}
