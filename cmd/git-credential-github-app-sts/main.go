package main

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/alecthomas/kong"

	"github.com/etsy/github-app-sts/internal/client"
	"github.com/etsy/github-app-sts/internal/client/tokensource"
)

var args struct {
	STSUrl      string `name:"sts-url" required:"" help:"STS server URL." env:"GITHUB_APP_STS_URL"`
	Scope       string `name:"scope" required:"" help:"Policy name." env:"GITHUB_APP_STS_SCOPE"`
	TokenSource string `name:"token-source" help:"Token source provider (gcp)." env:"GITHUB_APP_STS_TOKEN_SOURCE" xor:"token"`
	TokenFile   string `name:"token-file" help:"Path to file containing OIDC identity token." env:"GITHUB_APP_STS_TOKEN_FILE" xor:"token"`
	Operation   string `arg:"" help:"Git credential helper operation (get, store, erase)."`
}

func main() {
	k := kong.Parse(&args,
		kong.Name("git-credential-github-app-sts"),
		kong.Description("Git credential helper that uses GitHub App STS for authentication."),
	)

	if args.Operation != "get" {
		return
	}

	attrs, err := readCredentialAttributes(os.Stdin)

	k.FatalIfErrorf(err)

	outAttrs, err := get(attrs)

	k.FatalIfErrorf(err)

	writeCredentialAttributes(os.Stdout, outAttrs)
}

type credentialAttribute struct {
	key   string
	value string
}

func get(in []credentialAttribute) ([]credentialAttribute, error) {
	input := make(map[string]string)

	for _, a := range in {
		input[a.key] = a.value
	}

	if input["protocol"] != "https" {
		return nil, nil
	}

	host := input["host"]

	if host == "" {
		return nil, fmt.Errorf("missing host in credential input")
	}

	path := input["path"]

	if path == "" {
		return nil, fmt.Errorf("missing path in credential input")
	}

	resource := fmt.Sprintf("https://%s/%s", host, path)

	ctx := context.Background()

	subjectToken, err := resolveToken(ctx, args.STSUrl)

	if err != nil {
		return nil, err
	}

	resp, err := client.ExchangeToken(ctx, client.ExchangeRequest{
		STSUrl:       args.STSUrl,
		SubjectToken: subjectToken,
		Resource:     resource,
		Scope:        args.Scope,
	})

	if err != nil {
		return nil, err
	}

	expiryUTC := time.Now().Add(time.Duration(resp.ExpiresIn) * time.Second).UTC()

	return []credentialAttribute{
		{"username", "x-access-token"},
		{"password", resp.AccessToken},
		{"password_expiry_utc", strconv.FormatInt(expiryUTC.Unix(), 10)},
	}, nil
}

func resolveToken(ctx context.Context, audience string) (string, error) {
	if args.TokenFile != "" {
		return tokensource.FromFile(args.TokenFile)
	}

	switch args.TokenSource {
	case "gcp":
		return tokensource.FromGCP(ctx, audience)
	default:
		return "", fmt.Errorf("unknown token source: %s", args.TokenSource)
	}
}

func readCredentialAttributes(r io.Reader) ([]credentialAttribute, error) {
	s := bufio.NewScanner(r)
	a := make([]credentialAttribute, 0)

	for s.Scan() {
		line := s.Text()

		if line == "" {
			break
		}

		key, value, ok := strings.Cut(line, "=")

		if !ok {
			return nil, fmt.Errorf("missing '=' character in git credential input")
		}

		a = append(a, credentialAttribute{key, value})
	}

	if err := s.Err(); err != nil {
		return nil, err
	}

	return a, nil
}

func writeCredentialAttributes(w io.Writer, attrs []credentialAttribute) {
	for _, attr := range attrs {
		fmt.Fprintf(w, "%s=%s\n", attr.key, attr.value)
	}

	fmt.Fprintln(w)
}
