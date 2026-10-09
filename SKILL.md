---
name: deep-audit
description: Har qanday veb-infratuzilma uchun to'liq o'qish-tipidagi (read-only) xavfsizlik audit metodikasi — DNS/CT recon, subdomen xaritalash, origin kashfiyoti, Odoo/Laravel/status-sahifa/API tekshiruvlari, zararsiz parol/restore sinovlari, dalil saqlash va hisobot. FAQAT yozma avtorizatsiyaga ega bo'lgan (o'z yoki ruxsat berilgan) infratuzilmada ishlating.
---

# Deep Audit — Veb-Infratuzilma Xavfsizlik Audit Metodikasi

> **AVTORIZATSIYA SHART.** Bu metodikani faqat o'zingizga tegishli yoki egasidan
> yozma ruxsat (scope/ToR) olingan tizimlarda qo'llang. Ruxsatsiz skanlash va
> sinov ko'p yurisdiksiyalarda noqonuniy. Scope'dan tashqariga chiqmang.

**Qat'iy qoidalar:** faqat GET/HEAD/OPTIONS + aniq chegaralangan sinovlar; yozuv operatsiyalari (POST/restore/duplicate/drop/wake/register) YO'Q; brute-force YO'Q; dalillarni `cp` bilan saqlash (`mv` emas); har topilma uchun NAZORAT TESTI (noto'g'ri/bo'sh qiymat bilan) o'tkazish; barcha amallar jurnalga yozib boriladi. Quyida `example.com`, `<ip>`, `<host>` — o'rniga o'z scope'ingizdagi maqsadni qo'ying.

## 1. Passiv razvedka
```bash
dig +short example.com A; dig +short example.com AAAA
dig +short example.com MX; dig +short example.com NS; dig +short example.com TXT
dig +short TXT _dmarc.example.com        # DMARC bo'sh = spoofing xavfi
whois example.com | head -30
# Subdomenlar — Certificate Transparency:
curl -s "https://crt.sh/?q=%25.example.com&output=json" | python3 -c "
import json,sys
data=json.load(sys.stdin); names=set()
for e in data:
    for n in e.get('name_value','').split('\n'):
        n=n.strip().lstrip('*.')
        if n.endswith('example.com'): names.add(n)
print('\n'.join(sorted(names)))"
dig axfr example.com @<ns>               # zone transfer sinovi (odatda refused)
```

## 2. Subdomen xaritalash (parallel resolve+probe)
```bash
while read -r d; do ( ip=$(dig +short "$d" A | grep -E '^[0-9.]+$' | tail -1)
  if [ -n "$ip" ]; then code=$(curl -sk -o /dev/null -w "%{http_code}" --max-time 6 "https://$d")
    [ "$code" = "000" ] && code=$(curl -s -o /dev/null -w "%{http_code}" --max-time 6 "http://$d")
    echo "$d|$ip|$code" >> live.txt; fi ) &
  while [ "$(jobs -r|wc -l)" -ge 30 ]; do wait -n; done
done < subdomains.txt; wait; sort -t'|' -k2 live.txt -o live.txt
# CDN/proxy (Cloudflare va h.k.) IP'laridan qoching — origin IP'lar = qolgan provayderlardagilari
```

## 3. Origin kashfiyoti va skanlash
```bash
nmap -Pn --top-ports 100 -T4 --open <ip>            # tezkor
nmap -Pn -p 8069,8070,5432,6379,27017,3306,8006,9000 -T4 --open <ip>  # xizmat portlari
nmap -Pn -p- --min-rate 3000 --max-retries 1 -T4 --open -oN full.txt <ip>  # to'liq (fon, 30-50 daq)
# UDP (root yo'q bolsa nc bilan):
printf "version\r\n" | nc -u -w 3 <ip> 11211        # memcached amplification
# TLS SAN — yashirin vhostlar manbasi:
echo | openssl s_client -connect <ip>:443 -servername <host> | openssl x509 -noout -ext subjectAltName
dig +short -x <ip>                                   # PTR
# Host-header vhost kashfiyoti:
curl -sk -H "Host: <nom>" "https://<ip>/" -w "%{http_code}"
# KONTRol: javoblarni csrf-token/raqamlarni normallashtirib MD5 solishtiring — catch-allmi yoki haqiqiy vhostmi
```

## 4. Odoo tekshiruvlari
```bash
curl -sk https://host/web/database/manager -o /dev/null -w "%{http_code}"   # 200 = manager ochiq
# DB ro'yxati (parolsiz ishlaydimi — NAZORAT BILAN):
curl -s -X POST https://host/jsonrpc -H "Content-Type: application/json" \
  -d '{"jsonrpc":"2.0","method":"call","id":1,"params":{"service":"db","method":"list","args":[]}}'
curl -s -X POST https://host/web/database/list -H "Content-Type: application/json" \
  -d '{"params":{"master_pwd":"admin"}}'
# ⚠️ MUHIM: master_pwd ni NOTO'G'RI va BO'SH qiymat bilan ham sinang!
# Agar hammasi bir xil ro'yxatni qaytarsa — marshrut parol tekshirmaydi (unauth enumeration),
# "default parol ishlaydi" degan XATO xulosani shu nazorat testi oldini oladi.
# Restore darvozasini zararsiz sinash (3 bosqich, yozuvsiz):
curl -s -o /dev/null -w "%{http_code}" https://host/web/database/restore        # 405 = jonli
curl -s -X POST .../restore -F master_pwd=WRONG -F backup_file=@empty.zip -F name=x  # Access Denied kutiladi
curl -s -X POST .../restore -F master_pwd=admin -F backup_file=@empty.zip -F name=MAVJUD_DB  # yana Access Denied = parol standart emas
# Keyin db.list qayta — yangi baza paydo bo'lmasligi tasdiqlanadi
# Login sinovi (chegaralangan 1-3): POST /web/session/authenticate {"params":{"db":..,"login":"admin","password":"admin"}}
# Versiya: POST /web/webclient/version_info | Ma'lumot: /website/info (o'rnatilgan modullar ro'yxati!)
# Brend: /web/login?db=<nom> title; sitemap.xml; /web/signup (ochiq ro'yxat bormi)
```

## 5. Laravel tekshiruvlari
```bash
for p in .env .env.bak .git/config storage/logs/laravel.log backup.zip db.sql telescope horizon _ignition/health-check; do
  curl -sk -o /dev/null -w "$p → %{http_code}\n" https://host/$p; done   # 403/404 = yaxshi
# Cookie'lar: XSRF-TOKEN + *_session = Laravel; /telescope /horizon 302 → locale-redirect ekanini tekshiring (404 bilan tugashi kerak)
# Ziggy marshrut sizishi (Inertia sahifalarida):
curl -sk https://host/ | grep -oE 'const Ziggy=(\{.*?\});'   # 50+ marshrut nomi oshkor bo'lishi mumkin
# Inertia page-data JSON: ">({"component":...})<" ni ajratib, python json.loads(b, strict=False)
# /register → 200 bo'lsa ochiq ro'yxat (hukumat/ichki tizimlarida muhim topilma)
# Sanctum: /sanctum/csrf-cookie (204/404)
```

## 6. Status-sahifa (Uptime Kuma) / Headscale / API'lar
```bash
curl -sk https://status.host/api/entry-page            # entryPage nomi
curl -sk "https://status.host/socket.io/?EIO=4&transport=polling"   # handshake (faqat axborot)
# Headscale: /api/v1/apikey (401 kutiladi), /health
# API hujjatlari: /docs /docs.postman /docs.openapi /swagger.json /api-docs
# OpenAPI'dan public endpointlarni ajratish: grep -i "public\|no authentication"
# CORS aksi: curl -s -H "Origin: https://evil.example" -i <url> | grep -i access-control  # aks ettirilsa = topilma
# OPTIONS: curl -X OPTIONS -i <url> | grep -i allow
```

## 7. Object storage (S3-mos / provayder bucketlari)
```bash
curl -s https://<bucket>.<provider-endpoint>/                 # 403 = ro'yxat yopiq (yaxshi)
curl -s -o /dev/null -w "%{http_code}" <ma'lum obyekt URL>    # 200 = public-read obyektlar
# Provayderga qarab endpoint o'zgaradi: s3.<region>.amazonaws.com, <region>.your-objectstorage.com,
# storage.googleapis.com, <acc>.r2.cloudflarestorage.com va h.k.
```

## 8. Chegaralangan parol sinovi (siyosat)
- Faqat standart (`admin/admin`) + 2-3 kontekst varianti; har eshikda maksimum 3 urinish
- Lockout xavfi aniqlansa — umuman sinalmaydi
- Har urinish jurnalga: eshik | login | parol | natija | vaqt
- SSH uchun expect: `expect -c 'spawn ssh -o NumberOfPasswordPrompts=1 user@ip echo OK; expect {"password:" {send "admin\r"; exp_continue} "Permission denied" {exit 1}}'`

## 9. Dalil va hisobot
- Papka: `~/<target>-audit/` + `evidence/<topilma>/` + nazorat testlari jurnali (txt)
- Namunalar: `evidence/namunalar/` — faqat ochiq eshiklardan, har hujjat turidan bittadan
- Har topilma uchun: dalil (HTTP javobi/HTML) + NAZORAT testi + qayta tekshirish (fix buyrug'i ham yozilsin)
- Hisobot tuzilishi: xarita → topilmalar (daraja bilan) → tuzatishlar (shaffof!) → amallar jurnali → ta'mir rejasi → chegaralar

## 10. Umumiy saboqlar (xato xulosalardan qochish)
1. **Nazorat testisiz parol xulosasi chiqarma** — ba'zi list marshrutlari parolni tekshirmaydi; bu "default parol ishlaydi" degan soxta-pozitiv xulosaga olib keladi
2. Sarlavha default bo'lishi ilova o'lik demak emas — modul/sahifa ro'yxatiga qarang (masalan `/website/info`)
3. MD5 farqi catch-all'ni isbotlamaydi — avval csrf/dinamik ma'lumotni normallashtiring
4. Ziggy/Inertia page-data va shunga o'xshash front-end state — eng arzon marshrut/ma'lumot sizish manbai
5. Backup/export marshruti 500 qaytarishi vaqtinchalik (masalan `pg_dump` yo'qligi) bo'lishi mumkin — hisobotda shunday, ishonchli himoya emas deb belgilang
