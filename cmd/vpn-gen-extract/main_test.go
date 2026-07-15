package main

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// sampleLinkPath holds a vgc link built from throwaway keys. Никаких живых
// секретов в репозитории — реальная ссылка живёт только локально.
const sampleLinkPath = "../../testdata/url.txt"

// realLink reads the sample link used across the CLI tests.
func realLink(t *testing.T) string {
	t.Helper()
	b, err := os.ReadFile(sampleLinkPath)
	require.NoError(t, err)
	return strings.TrimSpace(string(b))
}

// version подменяется на тег через -ldflags, но по умолчанию должна быть непустой.
func TestVersionDefault(t *testing.T) {
	assert.NotEmpty(t, version)
}

func TestRunAllProtocols(t *testing.T) {
	var buf bytes.Buffer
	require.NoError(t, run("", "", []string{realLink(t)}, &buf))

	out := buf.String()
	assert.Contains(t, out, "## Shadowsocks / Outline")
	assert.Contains(t, out, "ss://")
	assert.Contains(t, out, "## VLESS / Reality")
	assert.Contains(t, out, "vless://")
	assert.Contains(t, out, "## WireGuard")
	assert.Contains(t, out, "[Interface]")
	assert.Contains(t, out, "## Cloak")
	assert.Contains(t, out, "RemoteHost")
}

func TestRunOnlySS(t *testing.T) {
	var buf bytes.Buffer
	require.NoError(t, run("", "ss", []string{realLink(t)}, &buf))

	out := buf.String()
	// -only печатает голую ссылку, без заголовков — удобно для пайпов.
	assert.Contains(t, out, "ss://")
	assert.NotContains(t, out, "##")
	assert.NotContains(t, out, "vless://")
}

func TestRunOnlyAliases(t *testing.T) {
	for _, key := range []string{"ss", "outline", "vless", "wireguard", "wg", "cloak"} {
		t.Run(key, func(t *testing.T) {
			var buf bytes.Buffer
			require.NoError(t, run("", key, []string{realLink(t)}, &buf))
			assert.NotEmpty(t, buf.String())
		})
	}
}

func TestRunFromFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "url.txt")
	require.NoError(t, os.WriteFile(path, []byte(realLink(t)+"\n"), 0o600))

	var buf bytes.Buffer
	require.NoError(t, run(path, "", nil, &buf))
	assert.Contains(t, buf.String(), "ss://")
}

func TestExecuteWritesFile(t *testing.T) {
	out := filepath.Join(t.TempDir(), "wg0.conf")
	require.NoError(t, execute("", "wireguard", out, []string{realLink(t)}))

	b, err := os.ReadFile(out)
	require.NoError(t, err)
	assert.Contains(t, string(b), "[Interface]")
	assert.Contains(t, string(b), "Endpoint = example.com:51820")
}

// В файле приватные ключи, поэтому он должен быть доступен только владельцу.
func TestExecuteFilePermissions(t *testing.T) {
	out := filepath.Join(t.TempDir(), "secret.conf")
	require.NoError(t, execute("", "wireguard", out, []string{realLink(t)}))

	fi, err := os.Stat(out)
	require.NoError(t, err)
	assert.Equal(t, os.FileMode(0o600), fi.Mode().Perm())
}

func TestExecuteOverwritesExistingFile(t *testing.T) {
	out := filepath.Join(t.TempDir(), "wg0.conf")
	require.NoError(t, os.WriteFile(out, []byte("stale content"), 0o600))

	require.NoError(t, execute("", "wireguard", out, []string{realLink(t)}))

	b, err := os.ReadFile(out)
	require.NoError(t, err)
	assert.NotContains(t, string(b), "stale")
}

// Битая ссылка не должна обнулять уже существующий конфиг.
func TestExecuteKeepsFileOnError(t *testing.T) {
	out := filepath.Join(t.TempDir(), "wg0.conf")
	require.NoError(t, os.WriteFile(out, []byte("previous config"), 0o600))

	assert.Error(t, execute("", "", out, []string{"https://example.com/no-marker"}))

	b, err := os.ReadFile(out)
	require.NoError(t, err)
	assert.Equal(t, "previous config", string(b))
}

func TestExecuteUnwritablePath(t *testing.T) {
	out := filepath.Join(t.TempDir(), "no-such-dir", "wg0.conf")
	assert.Error(t, execute("", "wireguard", out, []string{realLink(t)}))
}

func TestRunErrors(t *testing.T) {
	tests := []struct {
		name string
		file string
		only string
		args []string
	}{
		{"no input", "", "", nil},
		{"file and arg together", "some.txt", "", []string{realLink(t)}},
		{"missing file", "/nonexistent/nope.txt", "", nil},
		{"unknown protocol", "", "telepathy", []string{realLink(t)}},
		{"bad url", "", "", []string{"https://example.com/no-marker"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var buf bytes.Buffer
			assert.Error(t, run(tt.file, tt.only, tt.args, &buf))
		})
	}
}
