# HACKLITH

**HACKLITH** is an offensive web-testing toolkit written in pure Go + bash. It provides a terminal UI and headless CLI for reconnaissance, scanning, and vulnerability assessment. Authorized use only.

## Features

- **15 core modules**: probe, headers, cookies, methods, tech, portscan, dirb, admin, login, sqli, xss, subenum, dns, shell, about
- **25+ advanced modules**: waf, cdn, cors, redirect, hostheader, lfi, cmdi, csrf, ratelimit, ssl, git, dotenv, robots, sitemap, wp, js, banners, vulns, dirlist, backup, email, wayback, graphql, api, http2
- **Interactive TUI**: raw-mode terminal with module browser, streaming output, and target input
- **Headless CLI**: `hacklith.sh --run <module> --target <url>`
- **Shell bridge**: run bundled bash helpers (recon_all, nmap_quick, ssl_check)
- **Embedded wordlists**: works offline with zero external dependencies
- **Single binary backend**: compiled Go ELF, no runtime dependencies

## Installation

```bash
git clone https://github.com/qingethical/hacklith.git
cd hacklith
sudo bash init.sh
```

`init.sh` will:
1. Detect first run
2. Check for Kali Linux tooling (nmap, nikto, gobuster, sqlmap, etc.)
3. Install missing tools via `apt`
4. Download Go if missing
5. Compile the backend into a single `build/hacklith` binary

## Usage

### Interactive TUI
```bash
sudo bash hacklith.sh
```

### Headless
```bash
sudo bash hacklith.sh --run portscan --target 192.168.1.1 --ports top
sudo bash hacklith.sh --run sqli --target http://target/page.php?id=1
```

### Flags
- `--run <module>` — module to execute
- `--target <url>` — target URL or host:port
- `--wordlist <path>` — custom wordlist/creds/script path
- `--ports <spec>` — port spec: `common|top|all|80,443,8000-8100`
- `--timeout <dur>` — overall timeout (e.g. `5m`)

## Modules

| Module | Description |
|--------|-------------|
| probe | Fingerprint the web server (status, headers, title, TLS) |
| headers | Audit security-relevant response headers |
| cookies | Audit cookie flags (Secure, HttpOnly, SameSite) |
| methods | Test dangerous HTTP methods (PUT, TRACE, ...) |
| tech | Fingerprint the technology stack |
| portscan | TCP connect port scan (common/top/all) |
| dirb | Brute-force directories and files |
| admin | Hunt admin panels and sensitive files |
| login | Probe weak credentials on login forms |
| sqli | SQL injection scan (error/boolean/time based) |
| xss | Reflected XSS scan on discovered parameters |
| subenum | Subdomain brute-force via DNS |
| dns | Gather DNS records (A, MX, NS, TXT, CNAME) |
| shell | Run bundled bash helpers (recon_all, nmap_quick, ssl_check) |
| about | Show banner and usage |
| waf | Detect WAF presence (Cloudflare, Imperva, etc.) |
| cdn | Detect CDN (Cloudflare, Akamai, etc.) |
| cors | Check CORS misconfigurations |
| redirect | Open redirect detection |
| hostheader | Host header injection test |
| lfi | Local file inclusion probes |
| cmdi | Command injection probes |
| csrf | CSRF token analysis |
| ratelimit | Rate limiting test |
| ssl | Comprehensive SSL/TLS audit |
| git | Exposed .git directory check |
| dotenv | Exposed .env file check |
| robots | robots.txt analysis |
| sitemap | sitemap.xml analysis |
| wp | WordPress enumeration |
| js | JavaScript secret/endpoint scan |
| banners | Service banner grabbing |
| vulns | CVE/version matching |
| dirlist | Directory listing detection |
| backup | Backup file hunting |
| email | Email harvesting |
| wayback | Wayback Machine URL enumeration |
| graphql | GraphQL introspection query |
| api | API endpoint fuzzing |
| http2 | HTTP/2 support check |

## Reports

Press `s` in the TUI to save a report to `reports/hacklith_YYYYMMDD_HHMMSS.txt`.

## Building

```bash
go build -ldflags "-s -w" -o build/hacklith .
```

## Disclaimer

See `terms.txt` for the full liability disclaimer. Authorized use only — only scan systems you own or are contracted to assess.

## License

GNU General Public License v3.0 — see `LICENSE` for details.
