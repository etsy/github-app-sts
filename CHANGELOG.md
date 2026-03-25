# Changelog

## [1.2.1](https://github.com/etsy/github-app-sts/compare/v1.2.0...v1.2.1) (2026-03-25)


### Bug Fixes

* use getPublicKey to retrieve key algorithms ([#10](https://github.com/etsy/github-app-sts/issues/10)) ([fab64bb](https://github.com/etsy/github-app-sts/commit/fab64bb15c6f9f9c95d352bc1bd64eed9eddd631))

## [1.2.0](https://github.com/etsy/github-app-sts/compare/v1.1.0...v1.2.0) (2026-03-24)


### Features

* add OpenTelemetry tracing and metrics ([2b16c82](https://github.com/etsy/github-app-sts/commit/2b16c82b6ee8f6216d7143390eb7e229eecbb920))
* use node24 for action since node20 is deprecated ([50e899a](https://github.com/etsy/github-app-sts/commit/50e899a4c8732c46cae70fd077ba0f44fd4e5bf0))

## [1.1.0](https://github.com/etsy/github-app-sts/compare/v1.0.0...v1.1.0) (2026-03-23)


### Features

* publish signed Docker image to GAR on release ([#7](https://github.com/etsy/github-app-sts/issues/7)) ([fbea1db](https://github.com/etsy/github-app-sts/commit/fbea1db718738df343c630cb11be7a245bcd7b27))

## 1.0.0 (2026-03-23)


### Features

* `InstallationTokenSource` can now scope tokens ([69a08ec](https://github.com/etsy/github-app-sts/commit/69a08ecc8440480c9c23eb816f9928e2f24ea5bd))
* add `github-app-sts-server` binary ([9438c17](https://github.com/etsy/github-app-sts/commit/9438c1776630d804e1ed634e45ade2a1981ee5a0))
* add cache to `FileReader` ([4743a1b](https://github.com/etsy/github-app-sts/commit/4743a1b0fdf4e2a0a129052d79348fa77cba867a))
* add config ([79ff8bd](https://github.com/etsy/github-app-sts/commit/79ff8bd785846c4d2596e8ceb5802e79d796104f))
* add http handler ([4e468d3](https://github.com/etsy/github-app-sts/commit/4e468d395c11ea6c5f46b97d211d9e9ec24f2e7f))
* add initial github code ([af80eed](https://github.com/etsy/github-app-sts/commit/af80eed61c71bd31d729b8c647b04e922d2a23c0))
* add initial policy mechanism ([ca9ae72](https://github.com/etsy/github-app-sts/commit/ca9ae7272fbe4114f5164770d125a0efd57e1f60))
* add oidc token + policy verification ([2222aaa](https://github.com/etsy/github-app-sts/commit/2222aaa346577fc6786cecae83d4e330cc005ef6))
* add token exchange service ([4f7d029](https://github.com/etsy/github-app-sts/commit/4f7d02978723d22828e02b77a7bf8941c8150767))


### Bug Fixes

* example config ([f97bfa1](https://github.com/etsy/github-app-sts/commit/f97bfa1ef28a2a7d2d446a409af746ccd975d178))
* token caching, expiration logic, and HTTP server hardening ([9c553d5](https://github.com/etsy/github-app-sts/commit/9c553d504121a2ee901146a152ee70bd88c93991))
