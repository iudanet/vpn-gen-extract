// Command vpn-gen-extract decodes a vgc:// link and prints client VPN configs.
package main

import (
	"bytes"
	"errors"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"os"
	"strings"

	"github.com/iudanet/vpn_gen_extract/internal/config"
	"github.com/iudanet/vpn_gen_extract/internal/link"
)

// version is set at build time via -ldflags "-X main.version=...".
var version = "dev"

const usage = `vpn-gen-extract decodes a vgc:// link into client VPN configurations.

Usage:
  vpn-gen-extract [flags] <vgc-url>
  vpn-gen-extract [flags] -file <path>
  vpn-gen-extract -only wireguard -file url.txt -out wg0.conf

Flags:
`

// renderer produces one named output section.
type renderer struct {
	name string
	fn   func(*config.Config) (string, error)
}

func main() {
	var (
		file    string
		only    string
		out     string
		debug   bool
		showVer bool
	)
	flag.StringVar(&file, "file", "", "read the vgc url from a file")
	flag.StringVar(&only, "only", "", "output one protocol: ss, vless, wireguard, cloak")
	flag.StringVar(&out, "out", "", "write the result to a file instead of stdout")
	flag.BoolVar(&debug, "debug", false, "enable debug logging")
	flag.BoolVar(&showVer, "version", false, "print version and exit")
	flag.Usage = func() {
		fmt.Fprint(os.Stderr, usage)
		flag.PrintDefaults()
	}
	flag.Parse()

	if showVer {
		fmt.Println(version)
		return
	}

	level := slog.LevelInfo
	if debug {
		level = slog.LevelDebug
	}
	slog.SetDefault(slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: level})))

	if err := execute(file, only, out, flag.Args()); err != nil {
		slog.Error("failed to generate configs", "error", err)
		os.Exit(1)
	}
}

// execute runs the decode and sends the result to stdout or to the -out file.
func execute(file, only, out string, args []string) error {
	// Пишем в буфер: файл трогаем только после успешного разбора, иначе
	// битая ссылка обнулила бы уже существующий конфиг.
	var buf bytes.Buffer
	if err := run(file, only, args, &buf); err != nil {
		return err
	}

	if out == "" {
		_, err := os.Stdout.Write(buf.Bytes())
		return err
	}

	// 0600 — в конфигах приватные ключи и пароли.
	if err := os.WriteFile(out, buf.Bytes(), 0o600); err != nil {
		return fmt.Errorf("write %s: %w", out, err)
	}
	slog.Info("config written", "path", out, "bytes", buf.Len())
	return nil
}

// run reads the input, decodes it and writes the requested sections to w.
func run(file, only string, args []string, w io.Writer) error {
	raw, err := readInput(file, args)
	if err != nil {
		return err
	}

	cfg, err := config.Parse(raw)
	if err != nil {
		return err
	}
	slog.Debug("config decoded", "name", cfg.Config.Name, "domain", cfg.Config.Domain)

	renderers, err := selectRenderers(only)
	if err != nil {
		return err
	}
	return render(cfg, renderers, w)
}

// readInput resolves the vgc url from a file or the positional argument.
func readInput(file string, args []string) (string, error) {
	if file != "" && len(args) > 0 {
		return "", errors.New("provide either -file or a url argument, not both")
	}
	if file != "" {
		// Путь задаёт пользователь через -file: это и есть назначение флага.
		b, err := os.ReadFile(file) // #nosec G304
		if err != nil {
			return "", fmt.Errorf("read %s: %w", file, err)
		}
		return string(b), nil
	}
	if len(args) == 0 {
		return "", errors.New("no input: pass a vgc url or use -file")
	}
	return args[0], nil
}

// selectRenderers maps the -only flag to the sections to print.
func selectRenderers(only string) ([]renderer, error) {
	all := []renderer{
		{"Shadowsocks / Outline", link.Shadowsocks},
		{"VLESS / Reality", link.VLESS},
		{"WireGuard", link.WireGuard},
		{"Cloak", link.Cloak},
	}
	if only == "" {
		return all, nil
	}

	byKey := map[string]renderer{
		"ss":        all[0],
		"outline":   all[0],
		"vless":     all[1],
		"wireguard": all[2],
		"wg":        all[2],
		"cloak":     all[3],
	}
	r, ok := byKey[strings.ToLower(only)]
	if !ok {
		return nil, fmt.Errorf("unknown protocol %q: use ss, vless, wireguard or cloak", only)
	}
	return []renderer{r}, nil
}

// render writes each section, skipping the ones the config does not carry.
// A single -only selection that fails is reported as an error.
func render(cfg *config.Config, renderers []renderer, w io.Writer) error {
	if len(renderers) > 1 {
		fmt.Fprintf(w, "# %s\n", cfg.Config.Name)
		fmt.Fprintf(w, "# domain: %s\n", cfg.Config.Domain)
	}

	var rendered int
	for _, r := range renderers {
		out, err := r.fn(cfg)
		if err != nil {
			if len(renderers) == 1 {
				return err
			}
			// Конфиг может не содержать часть протоколов — это не ошибка.
			slog.Debug("section skipped", "section", r.name, "error", err)
			continue
		}
		rendered++
		if len(renderers) == 1 {
			fmt.Fprintf(w, "%s\n", strings.TrimRight(out, "\n"))
			continue
		}
		fmt.Fprintf(w, "\n## %s\n%s\n", r.name, strings.TrimRight(out, "\n"))
	}

	if rendered == 0 {
		return errors.New("no usable protocol found in config")
	}
	return nil
}
