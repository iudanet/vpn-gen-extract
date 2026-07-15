package config

import (
	"bytes"
	"compress/gzip"
	"math/big"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// base58Encode is a test-only helper mirroring base58Decode.
func base58Encode(b []byte) string {
	n := new(big.Int).SetBytes(b)
	radix := big.NewInt(58)
	mod := new(big.Int)

	var out []byte
	for n.Sign() > 0 {
		n.DivMod(n, radix, mod)
		out = append(out, base58Alphabet[mod.Int64()])
	}
	for _, c := range b {
		if c != 0 {
			break
		}
		out = append(out, base58Alphabet[0])
	}
	// Разворачиваем: цифры собирались от младшей к старшей.
	for i, j := 0, len(out)-1; i < j; i, j = i+1, j-1 {
		out[i], out[j] = out[j], out[i]
	}
	return string(out)
}

func gzipBytes(t *testing.T, s string) []byte {
	t.Helper()
	var buf bytes.Buffer
	zw := gzip.NewWriter(&buf)
	_, err := zw.Write([]byte(s))
	require.NoError(t, err)
	require.NoError(t, zw.Close())
	return buf.Bytes()
}

const sampleJSON = `{
  "config": {"version":1,"name":"test cfg","domain":"example.com","extended":0},
  "wireguard": {
    "Interface": {"PrivateKey":"privkey","Address":"10.0.0.2/32","DNS":"1.1.1.1"},
    "Peer": {"PublicKey":"pubkey","PresharedKey":"psk","AllowedIPs":"0.0.0.0/0","Endpoint":"example.com:51820"}
  },
  "cloak": {
    "RemoteHost":"example.com","RemotePort":443,"UID":"dWlkCg==","PublicKey":"pubkey",
    "ProxyBook":{"shadowsocks":{"cipher":"chacha20-ietf-poly1305","password":"pw","outline":{"prefix":""}}},
    "ServerName":"sni.example.com"
  },
  "shadowsocks": {"host":"example.com","port":8388,"cipher":"chacha20-ietf-poly1305","password":"pw","outline":{"prefix":"\u0016\u0003\u0001"}},
  "protocol0": {"publicKey":"rpk","id":"uuid-1","shortId":"abcd","address":"example.com","port":443,"serverName":"www.example.org"}
}`

func sampleLink(t *testing.T) string {
	t.Helper()
	return "https://host.example/vgc://" + base58Encode(gzipBytes(t, sampleJSON))
}

func TestBase58RoundTrip(t *testing.T) {
	cases := [][]byte{
		{},
		{0x00},
		{0x00, 0x00, 0x01},
		{0xff, 0xfe, 0xfd},
		[]byte("hello base58 round trip"),
	}
	for _, in := range cases {
		got, err := base58Decode(base58Encode(in))
		require.NoError(t, err)
		assert.Equal(t, in, got)
	}
}

func TestBase58DecodeInvalidChar(t *testing.T) {
	// 0, O, I и l не входят в алфавит bitcoin base58.
	for _, s := range []string{"0", "O", "I", "l", "abc!"} {
		_, err := base58Decode(s)
		assert.Error(t, err, "expected error for %q", s)
	}
}

func TestParseSuccess(t *testing.T) {
	cfg, err := Parse(sampleLink(t))
	require.NoError(t, err)

	assert.Equal(t, "test cfg", cfg.Config.Name)
	assert.Equal(t, "example.com", cfg.Config.Domain)
	assert.Equal(t, 8388, cfg.Shadowsocks.Port)
	assert.Equal(t, "chacha20-ietf-poly1305", cfg.Shadowsocks.Cipher)
	assert.Equal(t, "\x16\x03\x01", cfg.Shadowsocks.Outline.Prefix)
	assert.Equal(t, "uuid-1", cfg.Protocol0.ID)
	assert.Equal(t, "example.com:51820", cfg.WireGuard.Peer.Endpoint)
	assert.Equal(t, 443, cfg.Cloak.RemotePort)
}

func TestParseBarePayload(t *testing.T) {
	// Полезная нагрузка без обёртки URL тоже должна приниматься.
	cfg, err := Parse(base58Encode(gzipBytes(t, sampleJSON)))
	require.NoError(t, err)
	assert.Equal(t, "test cfg", cfg.Config.Name)
}

func TestParseTrimsWhitespace(t *testing.T) {
	cfg, err := Parse("  " + sampleLink(t) + "\n")
	require.NoError(t, err)
	assert.Equal(t, "test cfg", cfg.Config.Name)
}

func TestParseErrors(t *testing.T) {
	tests := []struct {
		name  string
		input string
	}{
		{"empty", ""},
		{"whitespace only", "   \n"},
		{"url without marker", "https://example.com/nothing-here"},
		{"marker but empty payload", "https://example.com/vgc://"},
		{"invalid base58", "vgc://0OIl"},
		{"valid base58 but not gzip", "vgc://" + base58Encode([]byte("plain text, not gzip"))},
		{"gzip but not json", "vgc://" + base58Encode(gzipBytes(t, "not json at all"))},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := Parse(tt.input)
			assert.Error(t, err)
		})
	}
}
