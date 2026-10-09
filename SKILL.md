---
name: deep-audit
description: A full read-only security audit methodology for any web infrastructure — DNS/CT recon, subdomain mapping, origin discovery, Odoo/Laravel/status-page/API checks, harmless password/restore tests, evidence collection and reporting. Use ONLY on infrastructure you own or are explicitly (in writing) authorized to test.
---

# Deep Audit — Web Infrastructure Security Audit Methodology

> **AUTHORIZATION REQUIRED.** Use this methodology only on systems you own or have
> explicit written permission (scope / rules of engagement) to test. Unauthorized
> scanning and testing is illegal in many jurisdictions. Never go outside the agreed scope.

**Hard rules:** GET/HEAD/OPTIONS plus tightly-bounded tests only; NO write operations (POST/restore/duplicate/drop/wake/register); NO brute force; preserve evidence with `cp` (not `mv`); run a CONTROL TEST (with a wrong/empty value) for every finding; log every action. Below, replace `example.com`, `<ip>`, `<host>` with the target in your own scope.

## 1. Passive reconnaissance
```bash
dig +short example.com A; dig +short example.com AAAA
dig +short example.com MX; dig +short example.com NS; dig +short example.com TXT
dig +short TXT _dmarc.example.com        # empty DMARC = spoofing risk
whois example.com | head -30
# Subdomains — Certificate Transparency:
curl -s "https://crt.sh/?q=%25.example.com&output=json" | python3 -c "
import json,sys
data=json.load(sys.stdin); names=set()
for e in data:
    for n in e.get('name_value','').split('\n'):
        n=n.strip().lstrip('*.')
        if n.endswith('example.com'): names.add(n)
print('\n'.join(sorted(names)))"
dig axfr example.com @<ns>               # zone transfer test (usually refused)
```

## 2. Subdomain mapping (parallel resolve + probe)
```bash
while read -r d; do ( ip=$(dig +short "$d" A | grep -E '^[0-9.]+$' | tail -1)
  if [ -n "$ip" ]; then code=$(curl -sk -o /dev/null -w "%{http_code}" --max-time 6 "https://$d")
    [ "$code" = "000" ] && code=$(curl -s -o /dev/null -w "%{http_code}" --max-time 6 "http://$d")
    echo "$d|$ip|$code" >> live.txt; fi ) &
  while [ "$(jobs -r|wc -l)" -ge 30 ]; do wait -n; done
done < subdomains.txt; wait; sort -t'|' -k2 live.txt -o live.txt
# Skip CDN/proxy (e.g. Cloudflare) IPs — origin IPs = the ones on other providers
```

## 3. Origin discovery and scanning
```bash
nmap -Pn --top-ports 100 -T4 --open <ip>            # quick
nmap -Pn -p 8069,8070,5432,6379,27017,3306,8006,9000 -T4 --open <ip>  # service ports
nmap -Pn -p- --min-rate 3000 --max-retries 1 -T4 --open -oN full.txt <ip>  # full (background, 30-50 min)
# UDP (use nc if no root):
printf "version\r\n" | nc -u -w 3 <ip> 11211        # memcached amplification
# TLS SAN — source of hidden vhosts:
echo | openssl s_client -connect <ip>:443 -servername <host> | openssl x509 -noout -ext subjectAltName
dig +short -x <ip>                                   # PTR
# Host-header vhost discovery:
curl -sk -H "Host: <name>" "https://<ip>/" -w "%{http_code}"
# CONTROL: normalize csrf-token/numbers in responses and compare MD5 — catch-all vs. real vhost
```

## 4. Odoo checks
```bash
curl -sk https://host/web/database/manager -o /dev/null -w "%{http_code}"   # 200 = manager exposed
# DB list (does it work without a password — WITH A CONTROL):
curl -s -X POST https://host/jsonrpc -H "Content-Type: application/json" \
  -d '{"jsonrpc":"2.0","method":"call","id":1,"params":{"service":"db","method":"list","args":[]}}'
curl -s -X POST https://host/web/database/list -H "Content-Type: application/json" \
  -d '{"params":{"master_pwd":"admin"}}'
# ⚠️ IMPORTANT: also try master_pwd with a WRONG and an EMPTY value!
# If they all return the same list, the route does not check the password (unauth enumeration);
# this control test prevents the FALSE conclusion that "the default password works".
# Harmless restore-gate test (3 stages, no writes):
curl -s -o /dev/null -w "%{http_code}" https://host/web/database/restore        # 405 = live
curl -s -X POST .../restore -F master_pwd=WRONG -F backup_file=@empty.zip -F name=x  # expect Access Denied
curl -s -X POST .../restore -F master_pwd=admin -F backup_file=@empty.zip -F name=EXISTING_DB  # again Access Denied = password not default
# Then re-run db.list — confirm no new database appeared
# Login test (bounded, 1-3): POST /web/session/authenticate {"params":{"db":..,"login":"admin","password":"admin"}}
# Version: POST /web/webclient/version_info | Info: /website/info (list of installed modules!)
# Branding: /web/login?db=<name> title; sitemap.xml; /web/signup (open registration?)
```

## 5. Laravel checks
```bash
for p in .env .env.bak .git/config storage/logs/laravel.log backup.zip db.sql telescope horizon _ignition/health-check; do
  curl -sk -o /dev/null -w "$p → %{http_code}\n" https://host/$p; done   # 403/404 = good
# Cookies: XSRF-TOKEN + *_session = Laravel; for /telescope /horizon 302 → verify it's a locale-redirect (must end in 404)
# Ziggy route leak (on Inertia pages):
curl -sk https://host/ | grep -oE 'const Ziggy=(\{.*?\});'   # may expose 50+ route names
# Inertia page-data JSON: extract ">({"component":...})<", then python json.loads(b, strict=False)
# /register → 200 means open registration (important finding on government/internal systems)
# Sanctum: /sanctum/csrf-cookie (204/404)
```

## 6. Status page (Uptime Kuma) / Headscale / APIs
```bash
curl -sk https://status.host/api/entry-page            # entryPage name
curl -sk "https://status.host/socket.io/?EIO=4&transport=polling"   # handshake (info only)
# Headscale: /api/v1/apikey (expect 401), /health
# API docs: /docs /docs.postman /docs.openapi /swagger.json /api-docs
# Extract public endpoints from OpenAPI: grep -i "public\|no authentication"
# CORS reflection: curl -s -H "Origin: https://evil.example" -i <url> | grep -i access-control  # reflected = finding
# OPTIONS: curl -X OPTIONS -i <url> | grep -i allow
```

## 7. Object storage (S3-compatible / provider buckets)
```bash
curl -s https://<bucket>.<provider-endpoint>/                 # 403 = listing closed (good)
curl -s -o /dev/null -w "%{http_code}" <known object URL>     # 200 = public-read objects
# Endpoint varies by provider: s3.<region>.amazonaws.com, <region>.your-objectstorage.com,
# storage.googleapis.com, <acc>.r2.cloudflarestorage.com, etc.
```

## 8. Bounded password test (policy)
- Default only (`admin/admin`) + 2-3 context variants; max 3 attempts per door
- If a lockout risk is detected — do not test at all
- Log every attempt: door | login | password | result | time
- SSH via expect: `expect -c 'spawn ssh -o NumberOfPasswordPrompts=1 user@ip echo OK; expect {"password:" {send "admin\r"; exp_continue} "Permission denied" {exit 1}}'`

## 9. Evidence and reporting
- Folder: `~/<target>-audit/` + `evidence/<finding>/` + control-test log (txt)
- Samples: `evidence/samples/` — only from open doors, one of each document type
- For each finding: evidence (HTTP response/HTML) + CONTROL test + re-check (write a fix-verification command too)
- Report structure: map → findings (with severity) → fixes (transparent!) → action log → remediation plan → scope limits

## 10. General lessons (avoiding false conclusions)
1. **Never draw a password conclusion without a control test** — some list routes don't check the password; this leads to a false-positive "default password works" conclusion
2. A default title doesn't mean the app is dead — look at the module/page list (e.g. `/website/info`)
3. An MD5 difference doesn't prove a catch-all — first normalize csrf/dynamic data
4. Ziggy/Inertia page-data and similar front-end state — the cheapest source of route/data leaks
5. A backup/export route returning 500 may be temporary (e.g. `pg_dump` missing) — mark it as such in the report, not as a reliable defense
