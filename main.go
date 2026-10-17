// HEADERSHOT - HTTP Security Header Scanner with vulnerability explanations.
// by Hafidzul Rasyid, CCEP (Certified Cybersecurity Educator Professional)
//
// For authorized security testing and education only.
package main

import (
	"bufio"
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"regexp"
	"runtime"
	"runtime/debug"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"
)

var version = "1.1.0"

func init() {
	// When installed with `go install ...@vX.Y.Z` the module version is embedded.
	if bi, ok := debug.ReadBuildInfo(); ok && bi.Main.Version != "" && bi.Main.Version != "(devel)" {
		version = bi.Main.Version
	}
}

func userAgent() string { return "Mozilla/5.0 (compatible; HEADERSHOT/" + version + ")" }

const (
	author         = "Hafdizul Rasyid, CCEP"
	authorTitle    = "Certified Cybersecurity Educator Professional"
	maxRedirects   = 10
	nameWidth      = 33
	lineWidth      = 78
	detailIndent   = 10
	statusSafe     = "SAFE"
	statusVuln     = "VULN"
	statusErr      = "ERROR"
	hstsMinAge     = 15552000 // 180 days
	maxValueLen    = 90
	corsEvilOrigin = "https://evil-headershot.invalid"
)

// ---------------------------------------------------------------------------
// Banner & usage
// ---------------------------------------------------------------------------

var glyphs = map[rune][5]string{
	'H': {` _   _ `, `| | | |`, `| |_| |`, `|  _  |`, `|_| |_|`},
	'E': {` _____ `, `| ____|`, `|  _|  `, `| |___ `, `|_____|`},
	'A': {`    _    `, `   / \   `, `  / _ \  `, ` / ___ \ `, `/_/   \_\`},
	'D': {` ____  `, `|  _ \ `, `| | | |`, `| |_| |`, `|____/ `},
	'R': {` ____  `, `|  _ \ `, `| |_) |`, `|  _ < `, `|_| \_\`},
	'S': {` ____  `, `/ ___| `, `\___ \ `, ` ___) |`, `|____/ `},
	'O': {`  ___  `, ` / _ \ `, `| | | |`, `| |_| |`, ` \___/ `},
	'T': {` _____ `, `|_   _|`, `  | |  `, `  | |  `, `  |_|  `},
}

func printBanner(w io.Writer, p painter) {
	gradient := []string{"96;1", "96;1", "36;1", "36", "34;1"}
	fmt.Fprintln(w)
	for row := 0; row < 5; row++ {
		var sb strings.Builder
		for _, ch := range "HEADERSHOT" {
			sb.WriteString(glyphs[ch][row])
		}
		fmt.Fprintln(w, " "+p.c(gradient[row], sb.String()))
	}
	fmt.Fprintln(w, "   "+p.c("90", "HTTP Security Header Scanner "+version)+
		"   "+p.c("33;1", "[ by "+author+" ]"))
	fmt.Fprintln(w, "   "+p.c("90", authorTitle+" | authorized testing only"))
	fmt.Fprintln(w)
}

func printUsage(w io.Writer) {
	fmt.Fprint(w, `Usage:
  headershot -d example.com
  headershot -l targets.txt -o result.txt
  headershot -l targets.txt --silent -o result.json
  cat domains.txt | headershot

Flags:
  -h, -help           Show this help
  -d  <domain>        Single target (comma-separated allowed): example.com or https://example.com
  -l, -list <file>    File containing targets, one per line ('#' = comment)
  -H  "Name: Value"   Custom request header (repeatable), e.g. -H "Cookie: a=b"
  -o  <file>          Save output to file (".json" = JSON report, otherwise plain text)
  --silent            Quiet mode: no banner, no spinner, one compact line per target
  -no-probe           Passive only: skip the 2 extra CORS probe requests per target
  -t  <n>             Concurrent workers (default 10)
  -timeout <sec>      Timeout per request in seconds (default 10)
  -no-color           Disable colored output
  -version            Show version

Status legend:
  [SAFE]  header present and properly configured
  [VULN]  header missing / weak / information disclosure (with Risk + Fix)
  [WAF]   Cloudflare, Akamai (and other CDN/WAF) detected on target
`)
}

// ---------------------------------------------------------------------------
// Colors / terminal helpers
// ---------------------------------------------------------------------------

type painter struct{ on bool }

func (p painter) c(code, s string) string {
	if !p.on {
		return s
	}
	return "\x1b[" + code + "m" + s + "\x1b[0m"
}

func isTTY(f *os.File) bool {
	fi, err := f.Stat()
	return err == nil && fi.Mode()&os.ModeCharDevice != 0
}

func colorSupported(f *os.File, disabled bool) bool {
	if disabled || os.Getenv("NO_COLOR") != "" || os.Getenv("TERM") == "dumb" {
		return false
	}
	if !isTTY(f) {
		return false
	}
	if runtime.GOOS == "windows" {
		return os.Getenv("WT_SESSION") != "" || os.Getenv("TERM") != "" ||
			os.Getenv("ANSICON") != "" || os.Getenv("ConEmuANSI") == "ON"
	}
	return true
}

// stripCtl removes control characters so hostile servers cannot inject
// terminal escape sequences into our output.
func stripCtl(s string) string {
	return strings.Map(func(r rune) rune {
		if r < 0x20 || r == 0x7f || (r >= 0x80 && r <= 0x9f) {
			return -1
		}
		return r
	}, s)
}

func clean(s string) string {
	s = stripCtl(s)
	rs := []rune(s)
	if len(rs) > maxValueLen {
		return string(rs[:maxValueLen-3]) + "..."
	}
	return s
}

func wrap(s string, width int) []string {
	var lines []string
	cur := ""
	for _, w := range strings.Fields(s) {
		if cur == "" {
			cur = w
			continue
		}
		if len([]rune(cur))+1+len([]rune(w)) > width {
			lines = append(lines, cur)
			cur = w
		} else {
			cur += " " + w
		}
	}
	if cur != "" {
		lines = append(lines, cur)
	}
	return lines
}

// ---------------------------------------------------------------------------
// Data model
// ---------------------------------------------------------------------------

type Finding struct {
	Name     string `json:"header"`
	Status   string `json:"status"`
	Severity string `json:"severity"`
	Value    string `json:"value,omitempty"`
	Note     string `json:"note,omitempty"`
	Risk     string `json:"risk,omitempty"`
	Fix      string `json:"fix,omitempty"`
}

type Result struct {
	Target     string    `json:"target"`
	URL        string    `json:"url,omitempty"`
	HTTPStatus string    `json:"http_status,omitempty"`
	DurationMS int64     `json:"duration_ms,omitempty"`
	WAF        []string  `json:"waf,omitempty"`
	Verdict    string    `json:"verdict"`
	VulnCount  int       `json:"vuln_count"`
	SafeCount  int       `json:"safe_count"`
	Findings   []Finding `json:"findings,omitempty"`
	Error      string    `json:"error,omitempty"`
}

func (r *Result) finalize() {
	if r.Error != "" {
		r.Verdict = statusErr
		return
	}
	for _, f := range r.Findings {
		if f.Status == statusVuln {
			r.VulnCount++
		} else {
			r.SafeCount++
		}
	}
	if r.VulnCount > 0 {
		r.Verdict = statusVuln
	} else {
		r.Verdict = statusSafe
	}
}

type Summary struct {
	Total   int   `json:"total_targets"`
	Scanned int   `json:"scanned"`
	Vuln    int   `json:"vulnerable"`
	Safe    int   `json:"safe"`
	Errors  int   `json:"errors"`
	WAF     int   `json:"behind_waf"`
	Elapsed int64 `json:"elapsed_ms"`
}

func summarize(results []*Result, total int, elapsed time.Duration) Summary {
	s := Summary{Total: total, Elapsed: elapsed.Milliseconds()}
	for _, r := range results {
		if r == nil {
			continue
		}
		s.Scanned++
		switch r.Verdict {
		case statusErr:
			s.Errors++
		case statusVuln:
			s.Vuln++
		default:
			s.Safe++
		}
		if len(r.WAF) > 0 {
			s.WAF++
		}
	}
	return s
}

func vuln(name, sev, value, note, risk, fix string) Finding {
	return Finding{Name: name, Status: statusVuln, Severity: sev, Value: clean(value),
		Note: stripCtl(note), Risk: risk, Fix: fix}
}

func safe(name, sev, value, note string) Finding {
	return Finding{Name: name, Status: statusSafe, Severity: sev, Value: clean(value), Note: stripCtl(note)}
}

// ---------------------------------------------------------------------------
// Vulnerability knowledge base (risk + fix texts)
// ---------------------------------------------------------------------------

const (
	fixHSTS = "Strict-Transport-Security: max-age=31536000; includeSubDomains; preload"

	riskHSTSMissing = "SSL stripping and DNS spoofing / MITM. Without HSTS a network attacker can downgrade the " +
		"victim from HTTPS to HTTP (sslstrip) or redirect to a fake host, then read or modify credentials, " +
		"cookies and traffic."
	riskHSTSWeak = "HSTS window is too short or malformed: browsers forget the policy quickly, so users become " +
		"exposed again to SSL stripping and DNS spoofing."
	riskHSTSPlain = "No HTTPS: traffic is unencrypted, so anyone on the network path can sniff or modify it " +
		"(MITM, credential theft, content injection)."
	infoHSTSFirst = "First-visit SSL stripping (first open): until the browser has seen the HSTS header once, " +
		"or the domain is on the preload list, the very first request can still be downgraded by a MITM. " +
		"Add 'preload' and submit the domain to hstspreload.org."
	infoHSTSSub = "Subdomains are not covered: an insecure or attacker-controlled subdomain can be used to " +
		"strip HTTPS or inject cookies for the parent domain."

	riskCSPMissing = "XSS and data injection. No browser-enforced policy restricts script sources, so any injected " +
		"script runs freely (session/cookie theft, defacement, malicious redirects). Also weakens defenses " +
		"against clickjacking and mixed content."
	riskCSPWeak = "The CSP can be bypassed: permissive script sources let injected or attacker-hosted scripts " +
		"execute, so the policy gives little real XSS protection."
	fixCSP     = "Content-Security-Policy: default-src 'self'; object-src 'none'; base-uri 'none'; frame-ancestors 'self'"
	fixCSPWeak = "Remove 'unsafe-inline', 'unsafe-eval' and wildcards from script-src; use nonces or hashes with 'strict-dynamic'."

	riskXFO = "Clickjacking (UI redressing). The page can be embedded in an attacker's iframe and users tricked " +
		"into clicking hidden buttons (change settings, transfer money, like-jacking)."
	fixXFO = "X-Frame-Options: DENY   (or CSP: frame-ancestors 'self')"

	riskXCTO = "MIME sniffing. Browsers may treat uploaded or reflected content as HTML/JS, enabling XSS through " +
		"content-type confusion."
	fixXCTO = "X-Content-Type-Options: nosniff"

	riskReferrer = "Referrer leakage. Full URLs (paths, query strings, tokens, session IDs, internal paths) are sent " +
		"to third-party sites and can end up in their logs."
	fixReferrer = "Referrer-Policy: strict-origin-when-cross-origin   (or no-referrer)"

	riskPermissions = "Powerful browser features (camera, microphone, geolocation, payment, ...) are not restricted, so " +
		"injected or embedded third-party content may request or abuse them."
	fixPermissions = "Permissions-Policy: camera=(), microphone=(), geolocation=(), payment=()"

	riskCOOP = "Cross-origin window attacks. Pages you open keep a reference to your window (tabnabbing, XS-Leaks) and " +
		"Spectre-style side channels are harder to mitigate."
	fixCOOP = "Cross-Origin-Opener-Policy: same-origin"

	riskCOEP = "No cross-origin isolation. Cross-origin resources load without opt-in, so Spectre-class side-channel " +
		"attacks remain feasible."
	fixCOEP = "Cross-Origin-Embedder-Policy: require-corp"

	riskCORP = "Your resources can be embedded by any other origin, enabling cross-site leaks and Spectre-style " +
		"theft of images, scripts and JSON."
	fixCORP = "Cross-Origin-Resource-Policy: same-origin   (or same-site)"

	riskCORSReflect = "CORS misconfiguration. The server reflects any Origin, so any malicious website can read " +
		"responses cross-origin. With Allow-Credentials: true this means theft of authenticated data " +
		"(account takeover, private data exposure)."
	fixCORSReflect = "Validate Origin against a strict allow-list of trusted origins, never echo it back, and add 'Vary: Origin'."
	riskCORSNull   = "The 'null' origin is trusted. Sandboxed iframes, data: URLs and local files send Origin: null, so " +
		"an attacker page can read responses (often with credentials)."
	fixCORSNull     = "Never allow the null origin; use an explicit allow-list."
	riskCORSWild    = "Any website can read responses from this host inside the victim's browser. Dangerous if the " +
		"content is private, user-specific or reachable only from an internal network (intranet/localhost)."
	fixCORSWild = "Restrict Access-Control-Allow-Origin to specific trusted origins unless the content is fully public."
	riskCORSCreds = "Credentials (cookies, HTTP auth) are allowed for untrusted origins. Attacker sites can make " +
		"authenticated cross-origin requests as the victim and read the results (data theft, account takeover)."
	fixCORSCreds = "Only send Access-Control-Allow-Credentials: true together with a strict origin allow-list; otherwise remove it."
	riskCORSMeth = "State-changing methods are allowed cross-origin. Combined with a weak origin policy this enables " +
		"cross-origin writes (CSRF-style modification or deletion of data)."
	fixCORSMeth = "Allow only the methods your API really needs (e.g. GET, POST) for trusted origins."
	riskCORSHdr = "Any request header is allowed cross-origin, broadening the attack surface (custom auth headers, " +
		"internal headers)."
	fixCORSHdr   = "List the exact headers needed instead of '*'."
	riskCORSExp  = "All response headers are exposed to other origins, possibly leaking tokens or internal metadata."
	fixCORSExp   = "Expose only the specific headers that clients need."
	riskCORSPNA  = "Public websites may reach resources on private networks (routers, intranet, localhost services) " +
		"through the victim's browser."
	fixCORSPNA   = "Remove Access-Control-Allow-Private-Network unless strictly required."
	riskTAO      = "Resource timing details are exposed to any site, enabling timing side-channel and user-tracking attacks."
	fixTAO       = "Timing-Allow-Origin: <specific trusted origin>"

	riskXXSS = "Legacy XSS auditor in filter mode can be abused to selectively block scripts or leak information " +
		"(XS-Leaks) and has introduced vulnerabilities of its own."
	fixXXSS = "X-XSS-Protection: 0   (rely on a strong CSP instead)"

	riskXPCDP = "Adobe Flash/PDF clients may load cross-domain policy files, letting other domains read your data " +
		"through crossdomain.xml."
	fixXPCDP = "X-Permitted-Cross-Domain-Policies: none"

	riskCTMissing = "No Content-Type: the browser must guess the content type (MIME sniffing), which can lead to XSS."
	riskCharset   = "No explicit charset: legacy browsers may auto-detect encodings (e.g. UTF-7), enabling encoding-based XSS."
	fixCT         = "Content-Type: text/html; charset=UTF-8"

	riskCache = "Responses that set cookies can be stored by shared caches/proxies or the browser history, exposing " +
		"session or personal data to other users."
	fixCache = "Cache-Control: no-store   (for pages with sensitive or user-specific content)"

	fixCookie = "Set-Cookie: <name>=<value>; Secure; HttpOnly; SameSite=Lax   (or Strict)"

	riskHPKP = "Deprecated and dangerous: a pinning mistake can lock users out permanently, and an attacker who briefly " +
		"controls the site can hold it hostage (RansomPKP)."
	fixHPKP = "Remove Public-Key-Pins; rely on Certificate Transparency and CAA DNS records."

	riskBasic = "Basic authentication sends credentials base64-encoded (not encrypted) on every request: exposed to " +
		"sniffing without TLS and prone to brute force and credential stuffing."
	fixBasic = "Use session/token-based authentication, enforce HTTPS and rate limiting."

	riskAllow = "Dangerous HTTP methods enabled: TRACE (Cross-Site Tracing, cookie theft), PUT/DELETE/CONNECT " +
		"(unauthorized file modification, deletion or tunneling)."
	fixAllow = "Disable unneeded HTTP methods on the web server or reverse proxy."

	riskDisclose = "Technology/version disclosure helps attackers fingerprint the stack and pick known CVEs and exploits " +
		"for that exact version."
	riskBackend = "Discloses internal backend hostnames/IPs or CMS details, aiding reconnaissance and targeted attacks."
	riskDebug   = "Debug/profiler mode appears enabled in production: may expose stack traces, configuration, environment " +
		"variables, SQL queries and secrets."
	fixDebug = "Disable debug mode in production and block profiler endpoints (e.g. /_profiler)."
)

// ---------------------------------------------------------------------------
// Header analysis
// ---------------------------------------------------------------------------

var (
	reMaxAge  = regexp.MustCompile(`(?i)max-age\s*=\s*"?(\d+)"?`)
	reVersion = regexp.MustCompile(`/\s*\d|\d+\.\d+`)
)

func hget(h http.Header, name string) string {
	return strings.TrimSpace(strings.Join(h.Values(name), ", "))
}

func tokens(v string) []string {
	var out []string
	for _, t := range strings.Split(v, ",") {
		t = strings.ToUpper(strings.TrimSpace(t))
		if t != "" {
			out = append(out, t)
		}
	}
	return out
}

func hasToken(list []string, want string) bool {
	for _, t := range list {
		if t == want {
			return true
		}
	}
	return false
}

func parseCSP(policy string) map[string][]string {
	out := map[string][]string{}
	for _, d := range strings.Split(policy, ";") {
		fields := strings.Fields(strings.ToLower(strings.TrimSpace(d)))
		if len(fields) == 0 {
			continue
		}
		if _, exists := out[fields[0]]; !exists { // first occurrence wins
			out[fields[0]] = fields[1:]
		}
	}
	return out
}

func cspWeaknesses(dirs map[string][]string) []string {
	where := "script-src"
	src, ok := dirs[where]
	if !ok {
		where = "default-src"
		src, ok = dirs[where]
	}
	if !ok {
		return []string{"no script-src/default-src directive"}
	}
	protected := false // nonce/hash/strict-dynamic neutralise 'unsafe-inline'
	for _, t := range src {
		if strings.HasPrefix(t, "'nonce-") || strings.HasPrefix(t, "'sha256-") ||
			strings.HasPrefix(t, "'sha384-") || strings.HasPrefix(t, "'sha512-") ||
			t == "'strict-dynamic'" {
			protected = true
		}
	}
	var weak []string
	for _, t := range src {
		switch t {
		case "'unsafe-inline'":
			if !protected {
				weak = append(weak, where+" allows 'unsafe-inline'")
			}
		case "'unsafe-eval'":
			weak = append(weak, where+" allows 'unsafe-eval'")
		case "*":
			weak = append(weak, where+" allows wildcard (*)")
		case "http:":
			weak = append(weak, where+" allows http:")
		case "data:":
			weak = append(weak, where+" allows data:")
		}
	}
	return weak
}

func checkHSTS(h http.Header, u *url.URL) Finding {
	const name = "Strict-Transport-Security"
	v := hget(h, name)
	if u.Scheme != "https" {
		return vuln(name, "HIGH", v, "site is served over plain HTTP (no HTTPS)", riskHSTSPlain,
			"Enable HTTPS with a valid certificate, redirect all HTTP to HTTPS, then add: "+fixHSTS)
	}
	if v == "" {
		return vuln(name, "HIGH", "", "header missing", riskHSTSMissing, fixHSTS)
	}
	m := reMaxAge.FindStringSubmatch(v)
	if m == nil {
		return vuln(name, "HIGH", v, "max-age directive missing", riskHSTSWeak, fixHSTS)
	}
	if age, err := strconv.ParseUint(m[1], 10, 64); err == nil && age < hstsMinAge {
		return vuln(name, "HIGH", v, fmt.Sprintf("max-age too low (%d < %d)", age, hstsMinAge), riskHSTSWeak, fixHSTS)
	}
	lower := strings.ToLower(v)
	var notes, infos []string
	if !strings.Contains(lower, "includesubdomains") {
		notes = append(notes, "no includeSubDomains")
		infos = append(infos, infoHSTSSub)
	}
	if !strings.Contains(lower, "preload") {
		notes = append(notes, "no preload")
		infos = append(infos, infoHSTSFirst)
	}
	f := safe(name, "HIGH", v, strings.Join(notes, ", "))
	f.Risk = strings.Join(infos, " ")
	return f
}

func checkCSP(h http.Header, dirs map[string][]string) Finding {
	const name = "Content-Security-Policy"
	v := hget(h, name)
	if v == "" {
		if hget(h, "Content-Security-Policy-Report-Only") != "" {
			return vuln(name, "HIGH", "", "only Report-Only found (policy not enforced)", riskCSPMissing, fixCSP)
		}
		return vuln(name, "HIGH", "", "header missing", riskCSPMissing, fixCSP)
	}
	if weak := cspWeaknesses(dirs); len(weak) > 0 {
		return vuln(name, "HIGH", v, "weak policy: "+strings.Join(weak, "; "), riskCSPWeak, fixCSPWeak)
	}
	var adv []string
	if _, ok := dirs["default-src"]; !ok {
		if _, ok := dirs["object-src"]; !ok {
			adv = append(adv, "object-src")
		}
	}
	if _, ok := dirs["base-uri"]; !ok {
		adv = append(adv, "base-uri")
	}
	note := ""
	if len(adv) > 0 {
		note = "advisory: consider adding " + strings.Join(adv, ", ")
	}
	return safe(name, "HIGH", v, note)
}

func checkXFO(h http.Header, dirs map[string][]string) Finding {
	const name = "X-Frame-Options"
	v := hget(h, name)
	up := strings.ToUpper(v)
	if up == "DENY" || up == "SAMEORIGIN" {
		return safe(name, "MEDIUM", v, "")
	}
	if fa, ok := dirs["frame-ancestors"]; ok {
		wild := false
		for _, t := range fa {
			if t == "*" {
				wild = true
			}
		}
		if !wild {
			return safe(name, "MEDIUM", v, "covered by CSP frame-ancestors")
		}
	}
	if v == "" {
		return vuln(name, "MEDIUM", "", "header missing (clickjacking possible)", riskXFO, fixXFO)
	}
	return vuln(name, "MEDIUM", v, "invalid or obsolete value", riskXFO, fixXFO)
}

func checkXCTO(h http.Header) Finding {
	const name = "X-Content-Type-Options"
	v := hget(h, name)
	if strings.Contains(strings.ToLower(v), "nosniff") {
		return safe(name, "MEDIUM", v, "")
	}
	if v == "" {
		return vuln(name, "MEDIUM", "", "header missing (MIME sniffing possible)", riskXCTO, fixXCTO)
	}
	return vuln(name, "MEDIUM", v, "value should be nosniff", riskXCTO, fixXCTO)
}

func checkReferrer(h http.Header) Finding {
	const name = "Referrer-Policy"
	v := hget(h, name)
	if v == "" {
		return vuln(name, "LOW", "", "header missing", riskReferrer, fixReferrer)
	}
	parts := strings.Split(v, ",")
	last := strings.ToLower(strings.TrimSpace(parts[len(parts)-1]))
	if last == "unsafe-url" || last == "no-referrer-when-downgrade" || last == "" {
		return vuln(name, "LOW", v, "weak policy (leaks full URL/referrer)", riskReferrer, fixReferrer)
	}
	return safe(name, "LOW", v, "")
}

func checkPermissions(h http.Header) Finding {
	const name = "Permissions-Policy"
	if v := hget(h, name); v != "" {
		return safe(name, "LOW", v, "")
	}
	if v := hget(h, "Feature-Policy"); v != "" {
		return safe(name, "LOW", v, "legacy Feature-Policy in use")
	}
	return vuln(name, "LOW", "", "header missing", riskPermissions, fixPermissions)
}

func checkCrossOrigin(h http.Header, name, risk, fix string) Finding {
	v := hget(h, name)
	if v == "" {
		return vuln(name, "LOW", "", "header missing", risk, fix)
	}
	if strings.EqualFold(v, "unsafe-none") {
		return vuln(name, "LOW", v, "unsafe-none provides no isolation", risk, fix)
	}
	return safe(name, "LOW", v, "")
}

func checkXXSS(v string) Finding {
	const name = "X-XSS-Protection"
	t := strings.ReplaceAll(strings.ToLower(v), " ", "")
	switch {
	case strings.HasPrefix(t, "0"):
		return safe(name, "LOW", v, "auditor disabled (recommended)")
	case strings.Contains(t, "mode=block"):
		return safe(name, "LOW", v, "legacy header, rely on CSP instead")
	default:
		return vuln(name, "LOW", v, "XSS auditor enabled in filter mode", riskXXSS, fixXXSS)
	}
}

func checkXPCDP(h http.Header) Finding {
	const name = "X-Permitted-Cross-Domain-Policies"
	v := hget(h, name)
	lower := strings.ToLower(v)
	switch {
	case v == "":
		return vuln(name, "LOW", "", "header missing", riskXPCDP, fixXPCDP)
	case lower == "none" || lower == "master-only":
		return safe(name, "LOW", v, "")
	default:
		return vuln(name, "LOW", v, "permissive value", riskXPCDP, fixXPCDP)
	}
}

func checkContentType(h http.Header) Finding {
	const name = "Content-Type"
	v := hget(h, name)
	lower := strings.ToLower(v)
	if v == "" {
		return vuln(name, "LOW", "", "header missing", riskCTMissing, fixCT)
	}
	if strings.HasPrefix(lower, "text/") && !strings.Contains(lower, "charset=") {
		return vuln(name, "LOW", v, "charset not specified", riskCharset, fixCT)
	}
	return safe(name, "LOW", v, "")
}

func checkCacheControl(h http.Header) Finding {
	const name = "Cache-Control"
	v := hget(h, name)
	lower := strings.ToLower(v)
	hasCookies := len(h.Values("Set-Cookie")) > 0
	restrictive := strings.Contains(lower, "no-store") || strings.Contains(lower, "no-cache") ||
		strings.Contains(lower, "private")
	if hasCookies && !restrictive {
		return vuln(name, "LOW", v, "response sets cookies without no-store/no-cache/private", riskCache, fixCache)
	}
	if v == "" {
		return safe(name, "LOW", "", "not set (no cookies in response)")
	}
	return safe(name, "LOW", v, "")
}

func checkCookies(h http.Header) (Finding, bool) {
	const name = "Set-Cookie"
	cookies := (&http.Response{Header: h}).Cookies()
	if len(cookies) == 0 {
		return Finding{}, false
	}
	var noSecure, noHTTPOnly, noSameSite bool
	var summary []string
	bad := 0
	for _, c := range cookies {
		var issues []string
		if !c.Secure {
			noSecure = true
			issues = append(issues, "no Secure")
		}
		if !c.HttpOnly {
			noHTTPOnly = true
			issues = append(issues, "no HttpOnly")
		}
		if c.SameSite == 0 || c.SameSite == http.SameSiteDefaultMode {
			noSameSite = true
			issues = append(issues, "no SameSite")
		} else if c.SameSite == http.SameSiteNoneMode && !c.Secure {
			noSecure = true
			issues = append(issues, "SameSite=None without Secure")
		}
		if len(issues) > 0 {
			bad++
			if len(summary) < 5 {
				summary = append(summary, clean(c.Name)+" ("+strings.Join(issues, ", ")+")")
			}
		}
	}
	if bad == 0 {
		return safe(name, "MEDIUM", "", fmt.Sprintf("%d cookie(s) with Secure, HttpOnly and SameSite", len(cookies))), true
	}
	var risks []string
	if noSecure {
		risks = append(risks, "Cookies without Secure can travel over plain HTTP and be stolen by MITM/sniffing")
	}
	if noHTTPOnly {
		risks = append(risks, "cookies without HttpOnly are readable by JavaScript, so any XSS becomes session hijacking")
	}
	if noSameSite {
		risks = append(risks, "cookies without SameSite are sent on cross-site requests, enabling CSRF and cross-site tracking")
	}
	note := fmt.Sprintf("%d of %d cookie(s) weak: %s", bad, len(cookies), strings.Join(summary, "; "))
	if bad > len(summary) {
		note += "; ..."
	}
	return vuln(name, "MEDIUM", "", note, strings.Join(risks, "; ")+".", fixCookie), true
}

func checkServer(h http.Header) Finding {
	const name = "Server"
	v := hget(h, name)
	if v == "" {
		return safe(name, "LOW", "", "not disclosed")
	}
	if reVersion.MatchString(v) {
		return vuln(name, "LOW", v, "server version disclosed", riskDisclose,
			"Hide the version (nginx: server_tokens off; Apache: ServerTokens Prod; IIS: removeServerHeader).")
	}
	return safe(name, "LOW", v, "")
}

func checkPoweredBy(h http.Header) Finding {
	const name = "X-Powered-By"
	v := hget(h, name)
	if v == "" {
		return safe(name, "LOW", "", "not disclosed")
	}
	return vuln(name, "LOW", v, "technology disclosed", riskDisclose,
		"Remove the header (PHP: expose_php=Off; Express: app.disable('x-powered-by'); ASP.NET: remove the custom header).")
}

// ---- CORS ------------------------------------------------------------------

type corsProbe struct {
	Origin string
	OK     bool
	H      http.Header
}

func (p *corsProbe) get(name string) string {
	if p == nil || !p.OK {
		return ""
	}
	return hget(p.H, name)
}

func varyHasOrigin(v string) bool {
	l := strings.ToLower(v)
	return strings.Contains(l, "origin") || strings.TrimSpace(l) == "*"
}

func analyzeCORS(h http.Header, probes []corsProbe) []Finding {
	var evil, null *corsProbe
	for i := range probes {
		switch probes[i].Origin {
		case corsEvilOrigin:
			evil = &probes[i]
		case "null":
			null = &probes[i]
		}
	}
	baseACAO := hget(h, "Access-Control-Allow-Origin")
	baseACAC := hget(h, "Access-Control-Allow-Credentials")

	evilACAO := evil.get("Access-Control-Allow-Origin")
	nullACAO := null.get("Access-Control-Allow-Origin")
	reflEvil := evilACAO == corsEvilOrigin
	reflNull := nullACAO == "null"
	wildcard := baseACAO == "*" || evilACAO == "*" || nullACAO == "*"
	credsEvil := evil.get("Access-Control-Allow-Credentials") == "true"
	credsNull := null.get("Access-Control-Allow-Credentials") == "true"

	pick := func(name string) string {
		if v := hget(h, name); v != "" {
			return v
		}
		if v := evil.get(name); v != "" {
			return v
		}
		return null.get(name)
	}

	var out []Finding

	// Access-Control-Allow-Origin
	const nACAO = "Access-Control-Allow-Origin"
	switch {
	case reflEvil:
		sev, note := "HIGH", "reflects arbitrary Origin"
		if credsEvil {
			sev, note = "CRITICAL", note+" and allows credentials"
		}
		if !varyHasOrigin(evil.get("Vary")) {
			note += "; no 'Vary: Origin' (cache poisoning)"
		}
		out = append(out, vuln(nACAO, sev, evilACAO, note, riskCORSReflect, fixCORSReflect))
	case reflNull:
		sev, note := "HIGH", "trusts Origin: null"
		if credsNull {
			sev, note = "CRITICAL", note+" and allows credentials"
		}
		out = append(out, vuln(nACAO, sev, nullACAO, note, riskCORSNull, fixCORSNull))
	case wildcard:
		out = append(out, vuln(nACAO, "MEDIUM", "*", "wildcard origin", riskCORSWild, fixCORSWild))
	case baseACAO == "":
		note := "not set (same-origin policy applies)"
		if len(probes) == 0 {
			note = "not set in baseline response (active CORS probe skipped)"
		}
		out = append(out, safe(nACAO, "MEDIUM", "", note))
	default:
		out = append(out, safe(nACAO, "MEDIUM", baseACAO, "specific origin, not reflected"))
	}

	// Access-Control-Allow-Credentials
	const nACAC = "Access-Control-Allow-Credentials"
	acac := pick(nACAC)
	if baseACAC != "" {
		acac = baseACAC
	}
	if acac != "" {
		switch {
		case (reflEvil && credsEvil) || (reflNull && credsNull):
			out = append(out, vuln(nACAC, "CRITICAL", acac, "credentials allowed for untrusted origin", riskCORSCreds, fixCORSCreds))
		case wildcard && acac == "true":
			out = append(out, vuln(nACAC, "MEDIUM", acac, "credentials combined with wildcard origin (invalid, fragile setup)", riskCORSCreds, fixCORSCreds))
		case acac != "true":
			out = append(out, safe(nACAC, "MEDIUM", acac, "invalid value (must be exactly 'true')"))
		default:
			out = append(out, safe(nACAC, "MEDIUM", acac, "make sure Allow-Origin is a strict allow-list"))
		}
	}

	// Access-Control-Allow-Methods
	if v := pick("Access-Control-Allow-Methods"); v != "" {
		ts := tokens(v)
		var bad []string
		for _, m := range []string{"PUT", "DELETE", "PATCH", "TRACE", "CONNECT", "*"} {
			if hasToken(ts, m) {
				bad = append(bad, m)
			}
		}
		if len(bad) > 0 {
			out = append(out, vuln("Access-Control-Allow-Methods", "LOW", v,
				"allows "+strings.Join(bad, ", ")+" cross-origin", riskCORSMeth, fixCORSMeth))
		} else {
			out = append(out, safe("Access-Control-Allow-Methods", "LOW", v, ""))
		}
	}
	// Access-Control-Allow-Headers
	if v := pick("Access-Control-Allow-Headers"); v != "" {
		if hasToken(tokens(v), "*") {
			out = append(out, vuln("Access-Control-Allow-Headers", "LOW", v, "wildcard headers allowed", riskCORSHdr, fixCORSHdr))
		} else {
			out = append(out, safe("Access-Control-Allow-Headers", "LOW", v, ""))
		}
	}
	// Access-Control-Expose-Headers
	if v := pick("Access-Control-Expose-Headers"); v != "" {
		if hasToken(tokens(v), "*") {
			out = append(out, vuln("Access-Control-Expose-Headers", "LOW", v, "all response headers exposed", riskCORSExp, fixCORSExp))
		} else {
			out = append(out, safe("Access-Control-Expose-Headers", "LOW", v, ""))
		}
	}
	// Access-Control-Allow-Private-Network
	if v := pick("Access-Control-Allow-Private-Network"); v != "" {
		if strings.EqualFold(v, "true") {
			out = append(out, vuln("Access-Control-Allow-Private-Network", "MEDIUM", v, "private network access allowed", riskCORSPNA, fixCORSPNA))
		} else {
			out = append(out, safe("Access-Control-Allow-Private-Network", "MEDIUM", v, ""))
		}
	}
	// Timing-Allow-Origin
	if v := pick("Timing-Allow-Origin"); v != "" {
		if strings.TrimSpace(v) == "*" {
			out = append(out, vuln("Timing-Allow-Origin", "LOW", v, "wildcard origin", riskTAO, fixTAO))
		} else {
			out = append(out, safe("Timing-Allow-Origin", "LOW", v, ""))
		}
	}
	return out
}

func analyze(h http.Header, u *url.URL, probes []corsProbe) []Finding {
	csp := parseCSP(hget(h, "Content-Security-Policy"))
	findings := []Finding{
		checkHSTS(h, u),
		checkCSP(h, csp),
		checkXFO(h, csp),
		checkXCTO(h),
		checkReferrer(h),
		checkPermissions(h),
		checkCrossOrigin(h, "Cross-Origin-Opener-Policy", riskCOOP, fixCOOP),
		checkCrossOrigin(h, "Cross-Origin-Embedder-Policy", riskCOEP, fixCOEP),
		checkCrossOrigin(h, "Cross-Origin-Resource-Policy", riskCORP, fixCORP),
	}
	findings = append(findings, analyzeCORS(h, probes)...)

	if v := hget(h, "X-XSS-Protection"); v != "" {
		findings = append(findings, checkXXSS(v))
	}
	findings = append(findings, checkXPCDP(h), checkContentType(h), checkCacheControl(h))
	if f, ok := checkCookies(h); ok {
		findings = append(findings, f)
	}
	if v := hget(h, "Public-Key-Pins"); v != "" {
		findings = append(findings, vuln("Public-Key-Pins", "LOW", v, "deprecated HPKP header present", riskHPKP, fixHPKP))
	}
	if v := hget(h, "WWW-Authenticate"); strings.Contains(strings.ToLower(v), "basic") {
		findings = append(findings, vuln("WWW-Authenticate", "MEDIUM", v, "Basic authentication in use", riskBasic, fixBasic))
	}
	if v := hget(h, "Allow"); v != "" {
		ts := tokens(v)
		var bad []string
		for _, m := range []string{"TRACE", "PUT", "DELETE", "CONNECT"} {
			if hasToken(ts, m) {
				bad = append(bad, m)
			}
		}
		if len(bad) > 0 {
			findings = append(findings, vuln("Allow", "MEDIUM", v, "dangerous methods enabled: "+strings.Join(bad, ", "), riskAllow, fixAllow))
		}
	}

	findings = append(findings, checkServer(h), checkPoweredBy(h))
	for _, n := range []string{"X-AspNet-Version", "X-AspNetMvc-Version"} {
		if v := hget(h, n); v != "" {
			findings = append(findings, vuln(n, "LOW", v, "framework version disclosed", riskDisclose,
				"Remove the header (web.config: <httpRuntime enableVersionHeader=\"false\" />, remove X-AspNetMvc-Version in Global.asax)."))
		}
	}
	for _, n := range []string{"X-Generator", "X-Backend-Server"} {
		if v := hget(h, n); v != "" {
			findings = append(findings, vuln(n, "LOW", v, "internal/CMS details disclosed", riskBackend,
				"Remove or blank this header at the web server or reverse proxy."))
		}
	}
	for _, n := range []string{"X-Debug-Token", "X-Debug-Token-Link"} {
		if v := hget(h, n); v != "" {
			findings = append(findings, vuln(n, "MEDIUM", v, "debug/profiler header exposed", riskDebug, fixDebug))
		}
	}
	return findings
}

// ---------------------------------------------------------------------------
// WAF / CDN detection
// ---------------------------------------------------------------------------

func detectWAF(h http.Header) []string {
	server := strings.ToLower(h.Get("Server"))
	via := strings.ToLower(h.Get("Via"))
	xcdn := strings.ToLower(h.Get("X-Cdn"))
	cookies := strings.ToLower(strings.Join(h.Values("Set-Cookie"), "\n"))
	has := func(n string) bool { return len(h.Values(n)) > 0 }
	contains := strings.Contains

	var out []string
	if contains(server, "cloudflare") || has("Cf-Ray") || has("Cf-Cache-Status") ||
		has("Cf-Mitigated") || contains(cookies, "__cf_bm=") || contains(cookies, "cf_clearance=") {
		out = append(out, "Cloudflare")
	}
	if contains(server, "akamai") || has("Akamai-Grn") || has("X-Akamai-Transformed") ||
		has("X-Akamai-Request-Id") || has("X-Akamai-Staging") ||
		contains(cookies, "ak_bmsc=") || contains(cookies, "bm_sz=") {
		out = append(out, "Akamai")
	}
	if has("X-Iinfo") || contains(xcdn, "imperva") || contains(xcdn, "incapsula") ||
		contains(cookies, "incap_ses_") || contains(cookies, "visid_incap_") {
		out = append(out, "Imperva")
	}
	if has("X-Sucuri-Id") || contains(server, "sucuri") {
		out = append(out, "Sucuri")
	}
	if has("X-Amz-Cf-Id") || contains(via, "cloudfront") || contains(server, "cloudfront") {
		out = append(out, "AWS CloudFront")
	}
	if has("X-Fastly-Request-Id") || has("Fastly-Debug-Digest") {
		out = append(out, "Fastly")
	}
	return out
}

func wafDescription(names []string) string {
	return strings.Join(names, ", ") + " detected - traffic is behind a CDN/WAF, " +
		"headers may be added/stripped at the edge, verify the origin too"
}

// ---------------------------------------------------------------------------
// HTTP scanning
// ---------------------------------------------------------------------------

func newClient(timeout time.Duration) *http.Client {
	tr := &http.Transport{
		Proxy:                 http.ProxyFromEnvironment,
		TLSClientConfig:       &tls.Config{InsecureSkipVerify: true}, // scanner must also inspect self-signed hosts
		DisableKeepAlives:     true,
		TLSHandshakeTimeout:   timeout,
		ResponseHeaderTimeout: timeout,
	}
	return &http.Client{
		Timeout:   timeout,
		Transport: tr,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if len(via) >= maxRedirects {
				return http.ErrUseLastResponse
			}
			return nil
		},
	}
}

func candidateURLs(t string) ([]string, error) {
	if strings.Contains(t, "://") {
		u, err := url.Parse(t)
		if err != nil || u.Hostname() == "" || (u.Scheme != "http" && u.Scheme != "https") {
			return nil, fmt.Errorf("invalid target %q", t)
		}
		return []string{t}, nil
	}
	var out []string
	for _, scheme := range []string{"https://", "http://"} {
		u, err := url.Parse(scheme + t)
		if err != nil || u.Hostname() == "" {
			return nil, fmt.Errorf("invalid target %q", t)
		}
		out = append(out, scheme+t)
	}
	return out, nil
}

func unwrapErr(err error) string {
	var ue *url.Error
	if errors.As(err, &ue) && ue.Err != nil {
		if ue.Timeout() {
			return "timeout"
		}
		return ue.Err.Error()
	}
	return err.Error()
}

func doGet(ctx context.Context, client *http.Client, rawURL string, custom [][2]string, origin string) (*http.Response, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, rawURL, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", userAgent())
	req.Header.Set("Accept", "*/*")
	for _, h := range custom {
		if strings.EqualFold(h[0], "Host") {
			req.Host = h[1]
			continue
		}
		if origin != "" && strings.EqualFold(h[0], "Origin") {
			continue
		}
		req.Header.Set(h[0], h[1])
	}
	if origin != "" {
		req.Header.Set("Origin", origin)
	}
	return client.Do(req)
}

func drainClose(resp *http.Response) {
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 1<<14))
	resp.Body.Close()
}

func corsProbeRequest(ctx context.Context, client *http.Client, rawURL string, custom [][2]string, origin string) corsProbe {
	p := corsProbe{Origin: origin}
	resp, err := doGet(ctx, client, rawURL, custom, origin)
	if err != nil {
		return p
	}
	drainClose(resp)
	p.OK = true
	p.H = resp.Header.Clone()
	return p
}

func scanTarget(ctx context.Context, client *http.Client, target string, custom [][2]string, probe bool) *Result {
	res := &Result{Target: target}
	cands, err := candidateURLs(target)
	if err != nil {
		res.Error = err.Error()
		res.finalize()
		return res
	}
	var errs []string
	for _, cand := range cands {
		start := time.Now()
		resp, err := doGet(ctx, client, cand, custom, "")
		if err != nil {
			scheme := cand[:strings.Index(cand, "://")]
			errs = append(errs, scheme+": "+unwrapErr(err))
			if ctx.Err() != nil {
				break
			}
			continue
		}
		hdr := resp.Header
		status := resp.Status
		finalURL := resp.Request.URL
		drainClose(resp)
		elapsed := time.Since(start)

		var probes []corsProbe
		if probe {
			for _, o := range []string{corsEvilOrigin, "null"} {
				if ctx.Err() != nil {
					break
				}
				probes = append(probes, corsProbeRequest(ctx, client, finalURL.String(), custom, o))
			}
		}

		res.URL = stripCtl(finalURL.Redacted())
		res.HTTPStatus = status
		res.DurationMS = elapsed.Milliseconds()
		res.WAF = detectWAF(hdr)
		res.Findings = analyze(hdr, finalURL, probes)
		res.finalize()
		return res
	}
	res.Error = clean(strings.Join(errs, " | "))
	res.finalize()
	return res
}

// ---------------------------------------------------------------------------
// Output formatting
// ---------------------------------------------------------------------------

func tag(p painter, status string) string {
	switch status {
	case statusSafe:
		return p.c("32;1", "[SAFE]")
	case statusVuln:
		return p.c("31;1", "[VULN]")
	default:
		return p.c("31;1", "[ERR] ")
	}
}

func formatDetail(p painter, label, code, text string) string {
	lines := wrap(text, lineWidth-detailIndent-7)
	var out []string
	for i, l := range lines {
		if i == 0 {
			out = append(out, strings.Repeat(" ", detailIndent)+p.c(code, fmt.Sprintf("%-4s", label))+" : "+l)
		} else {
			out = append(out, strings.Repeat(" ", detailIndent+7)+l)
		}
	}
	return strings.Join(out, "\n")
}

func formatFinding(p painter, f Finding) string {
	var parts []string
	if f.Status == statusVuln {
		if f.Note != "" {
			parts = append(parts, f.Note)
		}
		if f.Value != "" {
			parts = append(parts, "value: "+f.Value)
		}
	} else {
		if f.Value != "" {
			parts = append(parts, f.Value)
		}
		if f.Note != "" {
			parts = append(parts, "("+f.Note+")")
		}
	}
	line := fmt.Sprintf("   %s %-*s %s", tag(p, f.Status), nameWidth, f.Name, strings.Join(parts, " | "))
	if f.Status == statusVuln {
		line += " " + p.c("90", "["+f.Severity+"]")
	}
	out := []string{strings.TrimRight(line, " ")}
	if f.Risk != "" {
		if f.Status == statusVuln {
			out = append(out, formatDetail(p, "Risk", "33;1", f.Risk))
		} else {
			out = append(out, formatDetail(p, "Info", "90", f.Risk))
		}
	}
	if f.Status == statusVuln && f.Fix != "" {
		out = append(out, formatDetail(p, "Fix", "36", f.Fix))
	}
	return strings.Join(out, "\n")
}

func formatSilent(r *Result, p painter) string {
	if r.Error != "" {
		return fmt.Sprintf("%s %s - %s", tag(p, statusErr), r.Target, r.Error)
	}
	line := tag(p, r.Verdict) + " " + r.URL
	if len(r.WAF) > 0 {
		line += " " + p.c("35;1", "[WAF]") + " " + strings.Join(r.WAF, ",")
	}
	var bad []string
	for _, f := range r.Findings {
		if f.Status == statusVuln {
			bad = append(bad, f.Name)
		}
	}
	if len(bad) > 0 {
		line += " | missing/weak: " + strings.Join(bad, ", ")
	}
	return line
}

func formatFull(r *Result, p painter) string {
	var b strings.Builder
	heavy := strings.Repeat("=", lineWidth)
	light := strings.Repeat("-", lineWidth)

	b.WriteString(p.c("90", heavy) + "\n")
	if r.Error != "" {
		fmt.Fprintf(&b, " %s %s\n", tag(p, statusErr), p.c("1", r.Target))
		fmt.Fprintf(&b, "        %s\n", r.Error)
		return b.String()
	}
	fmt.Fprintf(&b, " %s %s\n", tag(p, r.Verdict), p.c("1", r.Target))
	fmt.Fprintf(&b, "        %s | %s | %dms | %d vulnerable, %d safe\n",
		r.URL, stripCtl(r.HTTPStatus), r.DurationMS, r.VulnCount, r.SafeCount)
	if len(r.WAF) > 0 {
		fmt.Fprintf(&b, " %s  %s\n", p.c("35;1", "[WAF]"), wafDescription(r.WAF))
	}
	b.WriteString(p.c("90", light) + "\n")
	for _, f := range r.Findings {
		s := formatFinding(p, f)
		b.WriteString(s + "\n")
		if strings.Contains(s, "\n") {
			b.WriteString("\n")
		}
	}
	return b.String()
}

func formatResult(r *Result, p painter, silent bool) string {
	if silent {
		return formatSilent(r, p)
	}
	return strings.TrimRight(formatFull(r, p), "\n")
}

func formatSummary(s Summary, p painter) string {
	elapsed := (time.Duration(s.Elapsed) * time.Millisecond).Round(10 * time.Millisecond)
	return fmt.Sprintf("%s\n Scanned: %d/%d | %s: %d | %s: %d | %s: %d | %s: %d | Time: %s\n%s",
		p.c("90", strings.Repeat("=", lineWidth)),
		s.Scanned, s.Total,
		p.c("31;1", "VULN"), s.Vuln,
		p.c("32;1", "SAFE"), s.Safe,
		p.c("35;1", "WAF"), s.WAF,
		p.c("31", "ERR"), s.Errors,
		elapsed,
		p.c("90", strings.Repeat("=", lineWidth)))
}

// ---------------------------------------------------------------------------
// Live UI (spinner + serialized printing)
// ---------------------------------------------------------------------------

type UI struct {
	mu      sync.Mutex
	pOut    painter
	pErr    painter
	silent  bool
	spin    bool
	msg     string
	frame   int
	lastW   int
	total   int
	done    int
	stop    chan struct{}
	stopped sync.WaitGroup
}

var spinFrames = []string{"/", "|", "-", "\\"}

func (u *UI) clearLocked() {
	if u.spin && u.lastW > 0 {
		fmt.Fprint(os.Stderr, "\r"+strings.Repeat(" ", u.lastW)+"\r")
		u.lastW = 0
	}
}

func (u *UI) drawLocked() {
	if !u.spin {
		return
	}
	text := fmt.Sprintf("[%d/%d] %s", u.done, u.total, u.msg)
	rs := []rune(text)
	if len(rs) > 70 {
		text = string(rs[:67]) + "..."
		rs = []rune(text)
	}
	width := len(rs) + 2
	pad := 0
	if u.lastW > width {
		pad = u.lastW - width
	}
	fmt.Fprint(os.Stderr, "\r"+u.pErr.c("96;1", spinFrames[u.frame%len(spinFrames)])+" "+text+strings.Repeat(" ", pad))
	u.lastW = width + pad
}

func (u *UI) start() {
	if !u.spin {
		return
	}
	u.stop = make(chan struct{})
	u.stopped.Add(1)
	go func() {
		defer u.stopped.Done()
		t := time.NewTicker(100 * time.Millisecond)
		defer t.Stop()
		for {
			select {
			case <-u.stop:
				return
			case <-t.C:
				u.mu.Lock()
				u.drawLocked()
				u.frame++
				u.mu.Unlock()
			}
		}
	}()
}

func (u *UI) finish() {
	if u.spin {
		close(u.stop)
		u.stopped.Wait()
	}
	u.mu.Lock()
	u.clearLocked()
	u.mu.Unlock()
}

func (u *UI) setMsg(target string) {
	u.mu.Lock()
	u.msg = "scanning " + stripCtl(target)
	u.mu.Unlock()
}

func (u *UI) show(r *Result) {
	u.mu.Lock()
	defer u.mu.Unlock()
	u.done++
	u.clearLocked()
	if u.silent && r.Error != "" {
		fmt.Fprintln(os.Stderr, formatResult(r, u.pErr, true))
		return
	}
	fmt.Fprintln(os.Stdout, formatResult(r, u.pOut, u.silent))
}

// ---------------------------------------------------------------------------
// Input handling
// ---------------------------------------------------------------------------

type headerList []string

func (h *headerList) String() string     { return strings.Join(*h, "; ") }
func (h *headerList) Set(v string) error { *h = append(*h, v); return nil }

func parseCustomHeaders(list []string) ([][2]string, error) {
	var out [][2]string
	for _, raw := range list {
		i := strings.Index(raw, ":")
		if i <= 0 {
			return nil, fmt.Errorf("invalid header %q (expected \"Name: Value\")", raw)
		}
		name := strings.TrimSpace(raw[:i])
		val := strings.TrimSpace(raw[i+1:])
		if name == "" || strings.ContainsAny(name, " \t\r\n") || strings.ContainsAny(val, "\r\n") {
			return nil, fmt.Errorf("invalid header %q", raw)
		}
		out = append(out, [2]string{name, val})
	}
	return out, nil
}

func readLines(r io.Reader, add func(string)) error {
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	first := true
	for sc.Scan() {
		line := sc.Text()
		if first {
			line = strings.TrimPrefix(line, "\ufeff")
			first = false
		}
		fields := strings.Fields(line)
		if len(fields) == 0 {
			continue
		}
		add(fields[0])
	}
	return sc.Err()
}

func loadTargets(domain, listFile string, extra []string, stdin io.Reader) ([]string, error) {
	seen := map[string]bool{}
	var targets []string
	add := func(t string) {
		t = stripCtl(strings.TrimSpace(t))
		if t == "" || strings.HasPrefix(t, "#") {
			return
		}
		key := strings.ToLower(t)
		if !seen[key] {
			seen[key] = true
			targets = append(targets, t)
		}
	}
	for _, d := range strings.Split(domain, ",") {
		add(d)
	}
	for _, e := range extra {
		add(e)
	}
	if listFile != "" {
		f, err := os.Open(listFile)
		if err != nil {
			return nil, fmt.Errorf("cannot open list file: %v", err)
		}
		defer f.Close()
		if err := readLines(f, add); err != nil {
			return nil, fmt.Errorf("error reading list file: %v", err)
		}
	}
	if stdin != nil {
		if err := readLines(stdin, add); err != nil {
			return nil, fmt.Errorf("error reading stdin: %v", err)
		}
	}
	return targets, nil
}

func writeOutput(f *os.File, asJSON bool, results []*Result, sum Summary, silent bool) error {
	var done []*Result
	for _, r := range results {
		if r != nil {
			done = append(done, r)
		}
	}
	plain := painter{on: false}
	if asJSON {
		report := struct {
			Tool    string    `json:"tool"`
			Version string    `json:"version"`
			Author  string    `json:"author"`
			Summary Summary   `json:"summary"`
			Results []*Result `json:"results"`
		}{"HEADERSHOT", version, author, sum, done}
		enc := json.NewEncoder(f)
		enc.SetIndent("", "  ")
		return enc.Encode(report)
	}
	w := bufio.NewWriter(f)
	for _, r := range done {
		fmt.Fprintln(w, formatResult(r, plain, silent))
	}
	if !silent {
		fmt.Fprintln(w, formatSummary(sum, plain))
	}
	return w.Flush()
}

// ---------------------------------------------------------------------------
// main
// ---------------------------------------------------------------------------

func main() { os.Exit(run()) }

func run() int {
	fs := flag.NewFlagSet("headershot", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	fs.Usage = func() {}

	var (
		help       bool
		showVer    bool
		domain     string
		listFile   string
		outFile    string
		silent     bool
		noColor    bool
		noProbe    bool
		threads    int
		timeoutSec int
		custom     headerList
	)
	fs.BoolVar(&help, "h", false, "")
	fs.BoolVar(&help, "help", false, "")
	fs.BoolVar(&showVer, "version", false, "")
	fs.StringVar(&domain, "d", "", "")
	fs.StringVar(&listFile, "l", "", "")
	fs.StringVar(&listFile, "list", "", "")
	fs.Var(&custom, "H", "")
	fs.StringVar(&outFile, "o", "", "")
	fs.BoolVar(&silent, "silent", false, "")
	fs.BoolVar(&noColor, "no-color", false, "")
	fs.BoolVar(&noProbe, "no-probe", false, "")
	fs.IntVar(&threads, "t", 10, "")
	fs.IntVar(&timeoutSec, "timeout", 10, "")

	pOut := painter{on: colorSupported(os.Stdout, noColor)}
	pErr := painter{on: colorSupported(os.Stderr, noColor)}

	if err := fs.Parse(os.Args[1:]); err != nil {
		printBanner(os.Stderr, pErr)
		printUsage(os.Stderr)
		return 2
	}
	// flags such as -no-color are parsed now, recompute painters
	pOut = painter{on: colorSupported(os.Stdout, noColor)}
	pErr = painter{on: colorSupported(os.Stderr, noColor)}

	if showVer {
		fmt.Println("headershot", version)
		return 0
	}
	if help {
		printBanner(os.Stdout, pOut)
		printUsage(os.Stdout)
		return 0
	}

	var stdin io.Reader
	if domain == "" && listFile == "" && len(fs.Args()) == 0 && !isTTY(os.Stdin) {
		stdin = os.Stdin
	}
	targets, err := loadTargets(domain, listFile, fs.Args(), stdin)
	if err != nil {
		if !silent {
			printBanner(os.Stderr, pErr)
		}
		fmt.Fprintln(os.Stderr, pErr.c("31;1", "[ERR]"), err)
		return 1
	}
	if len(targets) == 0 {
		printBanner(os.Stderr, pErr)
		fmt.Fprintln(os.Stderr, pErr.c("31;1", "[ERR]"), "no target specified (use -d, -l or pipe targets via stdin)")
		fmt.Fprintln(os.Stderr)
		printUsage(os.Stderr)
		return 1
	}
	headers, err := parseCustomHeaders(custom)
	if err != nil {
		fmt.Fprintln(os.Stderr, pErr.c("31;1", "[ERR]"), err)
		return 1
	}
	if threads < 1 {
		threads = 1
	}
	if threads > 200 {
		threads = 200
	}
	if timeoutSec < 1 {
		timeoutSec = 1
	}
	if threads > len(targets) {
		threads = len(targets)
	}

	var outF *os.File
	if outFile != "" {
		outF, err = os.Create(outFile)
		if err != nil {
			fmt.Fprintln(os.Stderr, pErr.c("31;1", "[ERR]"), "cannot create output file:", err)
			return 1
		}
		defer outF.Close()
	}

	if !silent {
		printBanner(os.Stderr, pErr)
		mode := "active CORS probe on"
		if noProbe {
			mode = "passive (no CORS probe)"
		}
		fmt.Fprintf(os.Stderr, " %s targets: %d | workers: %d | timeout: %ds | %s\n\n",
			pErr.c("96;1", "[*]"), len(targets), threads, timeoutSec, mode)
	}

	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()

	client := newClient(time.Duration(timeoutSec) * time.Second)
	ui := &UI{
		pOut:   pOut,
		pErr:   pErr,
		silent: silent,
		spin:   !silent && isTTY(os.Stderr),
		total:  len(targets),
		msg:    "starting...",
	}
	ui.start()

	started := time.Now()
	results := make([]*Result, len(targets))
	jobs := make(chan int)
	var wg sync.WaitGroup
	for w := 0; w < threads; w++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for idx := range jobs {
				if ctx.Err() != nil {
					continue
				}
				ui.setMsg(targets[idx])
				r := scanTarget(ctx, client, targets[idx], headers, !noProbe)
				if ctx.Err() != nil && r.Error != "" {
					continue // interrupted mid-request, discard partial result
				}
				results[idx] = r
				ui.show(r)
			}
		}()
	}
feed:
	for i := range targets {
		select {
		case jobs <- i:
		case <-ctx.Done():
			break feed
		}
	}
	close(jobs)
	wg.Wait()
	ui.finish()

	sum := summarize(results, len(targets), time.Since(started))
	if !silent {
		fmt.Fprintln(os.Stdout, formatSummary(sum, pOut))
	}

	code := 0
	if outF != nil {
		if err := writeOutput(outF, strings.HasSuffix(strings.ToLower(outFile), ".json"), results, sum, silent); err != nil {
			fmt.Fprintln(os.Stderr, pErr.c("31;1", "[ERR]"), "failed writing output:", err)
			code = 1
		} else if err := outF.Close(); err != nil {
			fmt.Fprintln(os.Stderr, pErr.c("31;1", "[ERR]"), "failed closing output:", err)
			code = 1
		} else if !silent {
			fmt.Fprintf(os.Stderr, " %s saved to %s\n", pErr.c("96;1", "[*]"), outFile)
		}
	}
	if ctx.Err() != nil {
		fmt.Fprintln(os.Stderr, pErr.c("33;1", "[!]"), "interrupted, partial results only")
		return 130
	}
	return code
}
