# HEADERSHOT

HTTP security header scanner that doesn't just say *what* is wrong, but also
*why it matters* (attack scenario) and *how to fix it*.

by **Hafidzul Rasyid, CCEP** - Certified Cybersecurity Educator Professional

> For authorized security testing and education only.

## Install

Requires Go 1.20+.

```bash
go install github.com/r4tb4c3h/headershot@latest
```

The binary lands in `$(go env GOPATH)/bin` (Windows: `%USERPROFILE%\\go\\bin`).
Make sure that folder is in your `PATH`, then simply run:

```bash
headershot -h
```

Add to PATH:

```powershell
# Windows (PowerShell, then reopen the terminal)
\[Environment]::SetEnvironmentVariable("Path", \[Environment]::GetEnvironmentVariable("Path","User") + ";$env:USERPROFILE\\go\\bin", "User")
```

```bash
# Linux / macOS (put in \~/.bashrc or \~/.zshrc)
export PATH=$PATH:$(go env GOPATH)/bin
```

## Usage

```bash
headershot -d example.com
headershot -l targets.txt -o result.txt
headershot -l targets.txt --silent -o result.json
cat domains.txt | headershot --silent
headershot -d example.com -H "Cookie: session=abc" -no-probe
```

|Flag|Description|
|-|-|
|`-h`|help|
|`-d`|single target (comma-separated allowed)|
|`-l`, `-list`|targets from txt file|
|`-H`|custom request header (repeatable)|
|`-o`|output file (`.json` = JSON, otherwise text)|
|`--silent`|quiet mode, one line per target|
|`-no-probe`|passive only, skip the 2 extra CORS probe requests|
|`-t`|concurrent workers (default 10)|
|`-timeout`|request timeout in seconds (default 10)|
|`-no-color`|disable colors|
|`-version`|show version|

## What it checks

Every `\[VULN]` finding includes **Risk** (attack description) and **Fix**.

* Strict-Transport-Security (missing = SSL stripping / DNS spoofing; present without preload = first-visit SSL stripping)
* Content-Security-Policy (missing / weak: unsafe-inline, unsafe-eval, wildcard)
* X-Frame-Options (clickjacking), X-Content-Type-Options (MIME sniffing)
* Referrer-Policy, Permissions-Policy
* Cross-Origin-Opener / Embedder / Resource-Policy
* CORS: Access-Control-Allow-Origin (wildcard, reflected origin, null origin),
Allow-Credentials, Allow-Methods, Allow-Headers, Expose-Headers,
Allow-Private-Network, Timing-Allow-Origin
* Set-Cookie flags (Secure, HttpOnly, SameSite), Cache-Control
* X-XSS-Protection, X-Permitted-Cross-Domain-Policies, Content-Type charset
* Public-Key-Pins, WWW-Authenticate Basic, dangerous Allow methods
* Information disclosure: Server, X-Powered-By, X-AspNet(Mvc)-Version, X-Generator, X-Backend-Server, X-Debug-Token
* WAF/CDN detection: Cloudflare, Akamai, Imperva, Sucuri, CloudFront, Fastly

### About the active CORS probe

By default HEADERSHOT sends two extra GET requests per target with
`Origin: https://evil-headershot.invalid` and `Origin: null` to see whether the
server reflects them. Use `-no-probe` for a purely passive scan (1 request).

## Release / Scoop

`go install` works as soon as the repo is public. For a tagged version
(shown by `headershot -version`):

```bash
git tag v1.1.0 \&\& git push origin v1.1.0
```

