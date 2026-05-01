package main

import (
	"context"
	"fmt"
	"os"

	"github.com/alecthomas/kong"

	"github.com/etsy/github-app-sts/internal/client"
	"github.com/etsy/github-app-sts/internal/client/tokensource"
)

var args struct {
	STSUrl      string `name:"sts-url" required:"" help:"STS server URL." env:"GITHUB_APP_STS_URL"`
	Resource    string `name:"resource" required:"" help:"Target resource URL (e.g. https://github.com/org/repo)." env:"GITHUB_APP_STS_RESOURCE"`
	Scope       string `name:"scope" required:"" help:"Policy name." env:"GITHUB_APP_STS_SCOPE"`
	TokenSource string `name:"token-source" help:"Token source provider (gcp)." env:"GITHUB_APP_STS_TOKEN_SOURCE" xor:"token"`
	TokenFile   string `name:"token-file" help:"Path to file containing OIDC identity token." env:"GITHUB_APP_STS_TOKEN_FILE" xor:"token"`
}

func main() {
	k := kong.Parse(&args,
		kong.Name("github-app-sts-client"),
		kong.Description("Exchange an OIDC token for a GitHub App installation token."),
	)

	ctx := context.Background()

	subjectToken, err := resolveToken(ctx, args.STSUrl)
	k.FatalIfErrorf(err)

	resp, err := client.ExchangeToken(ctx, client.ExchangeRequest{
		STSUrl:       args.STSUrl,
		SubjectToken: subjectToken,
		Resource:     args.Resource,
		Scope:        args.Scope,
	})

	k.FatalIfErrorf(err)

	fmt.Println(resp.AccessToken)
}

func resolveToken(ctx context.Context, audience string) (string, error) {
	if args.TokenFile != "" {
		return tokensource.FromFile(args.TokenFile)
	}

	switch args.TokenSource {
	case "gcp":
		return tokensource.FromGCP(ctx, audience)
	default:
		fmt.Fprintf(os.Stderr, "error: unknown token source: %s\n", args.TokenSource)
		os.Exit(1)
		return "", nil
	}
}
