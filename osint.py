import whois
import dns.resolver
import requests
from bs4 import BeautifulSoup
import re
import ssl
import socket
import json
from datetime import datetime


def dohvati_ip(domen):
    try:
        return socket.gethostbyname(domen)
    except Exception:
        return None


def whois_info(domen):
    rezultat = {}
    BITNA_POLJA = [
        "domain_name", "registrar", "creation_date",
        "expiration_date", "updated_date", "name_servers", "status"
    ]
    try:
        info = whois.whois(domen)
        for kljuc in BITNA_POLJA:
            vrijednost = info.get(kljuc)
            if vrijednost:
                rezultat[kljuc] = str(vrijednost)
    except Exception as e:
        rezultat["greska"] = str(e)
    return rezultat

# Mape za prikaz WHOIS polja u izvještaju
WHOIS_OZNAKE = {
    "domain_name":     "Naziv domena",
    "registrar":       "Registrar",
    "creation_date":   "Datum registracije",
    "expiration_date": "Datum isteka",
    "updated_date":    "Posljednja izmjena",
    "name_servers":    "Name serveri",
    "status":          "Status",
}


def dns_info(domen):
    rezultat = {}
    tipovi = ['A', 'AAAA', 'MX', 'TXT', 'NS', 'CNAME', 'SOA']
    for tip in tipovi:
        try:
            odgovori = dns.resolver.resolve(domen, tip)
            rezultat[tip] = [r.to_text() for r in odgovori]
        except Exception:
            rezultat[tip] = []
    return rezultat


def ssl_info(domen):
    rezultat = {}
    try:
        ctx = ssl.create_default_context()
        with ctx.wrap_socket(socket.socket(), server_hostname=domen) as s:
            s.settimeout(10)
            s.connect((domen, 443))
            cert = s.getpeercert()

        rezultat["subjekat"]      = dict(x[0] for x in cert.get("subject", []))
        rezultat["izdavac"]       = dict(x[0] for x in cert.get("issuer", []))
        rezultat["verzija"]       = cert.get("version")
        rezultat["serijski"]      = cert.get("serialNumber")
        rezultat["vrijedi_od"]    = cert.get("notBefore")
        rezultat["vrijedi_do"]    = cert.get("notAfter")

        not_after = cert.get("notAfter")
        if not_after:
            exp = datetime.strptime(not_after, "%b %d %H:%M:%S %Y %Z")
            preostalo = (exp - datetime.utcnow()).days
            rezultat["preostalo_dana"] = preostalo
            rezultat["istekao"] = preostalo < 0

        san = [f"{t}: {v}" for t, v in cert.get("subjectAltName", [])]
        rezultat["san"] = san
    except Exception as e:
        rezultat["greska"] = str(e)
    return rezultat


def http_headeri(url):
    rezultat = {}
    # Headeri koji su bitni sa sigurnosnog aspekta
    SIG_HEADERI = [
        "Strict-Transport-Security", "Content-Security-Policy",
        "X-Frame-Options", "X-Content-Type-Options",
        "Referrer-Policy", "Permissions-Policy", "X-XSS-Protection"
    ]
    try:
        zaglavlja = {"User-Agent": "Mozilla/5.0"}
        odgovor = requests.get(url, timeout=10, headers=zaglavlja, allow_redirects=True)
        svi = dict(odgovor.headers)

        rezultat["status_kod"]   = odgovor.status_code
        rezultat["finalni_url"]  = odgovor.url
        rezultat["server"]       = svi.get("Server", "N/A")
        rezultat["x_powered_by"] = svi.get("X-Powered-By", "N/A")
        rezultat["content_type"] = svi.get("Content-Type", "N/A")

        sig = {}
        for h in SIG_HEADERI:
            sig[h] = svi.get(h, None)
        rezultat["sigurnosni"] = sig

        kolacici = []
        for c in odgovor.cookies:
            kolacici.append({
                "naziv":    c.name,
                "secure":   c.secure,
                "httponly": "httponly" in str(c).lower(),
                "samesite": c._rest.get("SameSite", "N/A") if hasattr(c, "_rest") else "N/A"
            })
        rezultat["kolacici"] = kolacici
    except Exception as e:
        rezultat["greska"] = str(e)
    return rezultat


def ip_geolokacija(ip):
    rezultat = {}
    try:
        url = f"http://ip-api.com/json/{ip}?fields=status,country,regionName,city,isp,org,as,lat,lon,timezone"
        odgovor = requests.get(url, timeout=10)
        podaci = odgovor.json()
        if podaci.get("status") == "success":
            rezultat = podaci
        else:
            rezultat["greska"] = "ip-api nije vratio uspješan odgovor"
    except Exception as e:
        rezultat["greska"] = str(e)
    return rezultat


def subdomeni_enum(domen):
    # Koristimo crt.sh (Certificate Transparency logovi) za enumeraciju poddomena
    subdomeni = set()
    greska = None
    try:
        url = f"https://crt.sh/?q=%.{domen}&output=json"
        odgovor = requests.get(url, timeout=15)
        if odgovor.status_code == 200:
            for unos in odgovor.json():
                naziv = unos.get("name_value", "")
                for sub in naziv.split("\n"):
                    sub = sub.strip().lstrip("*.")
                    if sub.endswith(domen) and sub != domen:
                        subdomeni.add(sub)
    except Exception as e:
        greska = str(e)
    return {"subdomeni": sorted(list(subdomeni)), "greska": greska}


def generiraj_html(domen, ip, whois_pod, dns_pod, ssl_pod,
                   header_pod, geo_pod, sub_pod):

    datum = datetime.now().strftime("%d.%m.%Y. u %H:%M")

    def red(naziv, vrijednost):
        return f"""
        <tr>
          <td class="naziv">{naziv}</td>
          <td class="vrijednost">{vrijednost}</td>
        </tr>"""

    def odjeljak(id_, naslov, tijelo):
        return f"""
  <section id="{id_}" class="blok">
    <h2 class="blok-naslov">{naslov}</h2>
    <div class="blok-tijelo">{tijelo}</div>
  </section>"""

    if "greska" in whois_pod:
        whois_html = f'<p class="napomena greska">Greška: {whois_pod["greska"]}</p>'
    else:
        redovi = ""
        for kljuc, oznaka in WHOIS_OZNAKE.items():
            if kljuc in whois_pod:
                redovi += red(oznaka, whois_pod[kljuc])
        whois_html = f'<table class="tabela">{redovi}</table>'

    dns_html = '<table class="tabela"><thead><tr><th>Tip</th><th>Zapisi</th></tr></thead><tbody>'
    for tip, zapisi in dns_pod.items():
        if zapisi:
            sadrzaj = "<br>".join(f'<code>{z}</code>' for z in zapisi)
        else:
            sadrzaj = '<span class="prazno">—</span>'
        dns_html += f'<tr><td class="naziv">{tip}</td><td class="vrijednost">{sadrzaj}</td></tr>'
    dns_html += '</tbody></table>'

    if "greska" in ssl_pod:
        ssl_html = f'<p class="napomena greska">Greška: {ssl_pod["greska"]}</p>'
    else:
        preostalo = ssl_pod.get("preostalo_dana", 0)
        if preostalo > 30:
            status_css, status_txt = "status-ok", f"Aktivan ({preostalo} dana)"
        elif preostalo > 0:
            status_css, status_txt = "status-upoz", f"Uskoro ističe ({preostalo} dana)"
        else:
            status_css, status_txt = "status-err", "ISTEKAO"

        subj = ssl_pod.get("subjekat", {})
        iss  = ssl_pod.get("izdavac", {})
        redovi  = red("Organizacija", subj.get("organizationName", subj.get("commonName", "N/A")))
        redovi += red("Izdavač", iss.get("organizationName", "N/A"))
        redovi += red("Vrijedi od", ssl_pod.get("vrijedi_od", "N/A"))
        redovi += red("Vrijedi do", ssl_pod.get("vrijedi_do", "N/A"))
        redovi += red("Status sertifikata", f'<span class="status-pill {status_css}">{status_txt}</span>')
        redovi += red("Verzija", str(ssl_pod.get("verzija", "N/A")))
        ssl_html = f'<table class="tabela">{redovi}</table>'
        if ssl_pod.get("san"):
            san_stavke = "".join(f"<li>{s}</li>" for s in ssl_pod["san"][:20])
            ssl_html += f'<p class="pod-naslov">Subject Alt Names</p><ul class="lista-san">{san_stavke}</ul>'

    if "greska" in header_pod and not header_pod.get("status_kod"):
        header_html = f'<p class="napomena greska">Greška: {header_pod["greska"]}</p>'
    else:
        redovi  = red("Status kod", str(header_pod.get("status_kod", "N/A")))
        redovi += red("Finalni URL", header_pod.get("finalni_url", "N/A"))
        redovi += red("Server", header_pod.get("server", "N/A"))
        redovi += red("X-Powered-By", header_pod.get("x_powered_by", "N/A"))
        redovi += red("Content-Type", header_pod.get("content_type", "N/A"))
        header_html = f'<table class="tabela">{redovi}</table>'

        header_html += '<p class="pod-naslov">Sigurnosni HTTP headeri</p>'
        header_html += '<table class="tabela"><thead><tr><th>Header</th><th>Prisutan</th><th>Vrijednost</th></tr></thead><tbody>'
        for h, v in header_pod.get("sigurnosni", {}).items():
            if v:
                prisutan = '<span class="status-pill status-ok">Da</span>'
                vr = f'<code class="kod-mali">{v[:80]}{"…" if len(v) > 80 else ""}</code>'
            else:
                prisutan = '<span class="status-pill status-err">Ne</span>'
                vr = '<span class="prazno">Nije postavljen</span>'
            header_html += f'<tr><td class="naziv">{h}</td><td>{prisutan}</td><td class="vrijednost">{vr}</td></tr>'
        header_html += '</tbody></table>'

        kolacici = header_pod.get("kolacici", [])
        if kolacici:
            header_html += '<p class="pod-naslov">Kolačići</p>'
            header_html += '<table class="tabela"><thead><tr><th>Naziv</th><th>Secure</th><th>HttpOnly</th><th>SameSite</th></tr></thead><tbody>'
            for c in kolacici:
                def jeste(b): return '<span class="status-pill status-ok">Da</span>' if b else '<span class="status-pill status-err">Ne</span>'
                header_html += f'<tr><td class="naziv">{c["naziv"]}</td><td>{jeste(c["secure"])}</td><td>{jeste(c["httponly"])}</td><td>{c["samesite"]}</td></tr>'
            header_html += '</tbody></table>'

    if "greska" in geo_pod:
        geo_html = f'<p class="napomena greska">Greška: {geo_pod["greska"]}</p>'
    else:
        lat, lon = geo_pod.get("lat"), geo_pod.get("lon")
        mapa = f' &nbsp;<a class="veza-mapa" href="https://www.google.com/maps?q={lat},{lon}" target="_blank">→ Google Maps</a>' if lat else ""
        redovi  = red("IP adresa", ip or "N/A")
        redovi += red("Zemlja", geo_pod.get("country", "N/A"))
        redovi += red("Region", geo_pod.get("regionName", "N/A"))
        redovi += red("Grad", geo_pod.get("city", "N/A"))
        redovi += red("ISP", geo_pod.get("isp", "N/A"))
        redovi += red("Organizacija", geo_pod.get("org", "N/A"))
        redovi += red("AS broj", geo_pod.get("as", "N/A"))
        redovi += red("Vremenska zona", geo_pod.get("timezone", "N/A"))
        redovi += red("Koordinate", f"{lat}, {lon}{mapa}" if lat else "N/A")
        geo_html = f'<table class="tabela">{redovi}</table>'

    subs = sub_pod.get("subdomeni", [])
    sub_html = f'<p class="napomena">Pronađeno ukupno: <strong>{len(subs)}</strong> poddomena putem crt.sh (Certificate Transparency)</p>'
    if subs:
        stavke = "".join(f"<li>{s}</li>" for s in subs[:60])
        sub_html += f'<ul class="lista-sub">{stavke}</ul>'
        if len(subs) > 60:
            sub_html += f'<p class="napomena">Prikazano prvih 60 od {len(subs)} ukupno.</p>'
    else:
        sub_html += '<p class="napomena prazno">Nijjesu pronađeni subdomeni.</p>'
    if sub_pod.get("greska"):
        sub_html += f'<p class="napomena greska">Greška: {sub_pod["greska"]}</p>'

    html = f"""<!DOCTYPE html>
<html lang="sr-Latn">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>OSINT izvještaj — {domen}</title>
<link rel="preconnect" href="https://fonts.googleapis.com">
<link href="https://fonts.googleapis.com/css2?family=IBM+Plex+Mono:wght@400;600&family=IBM+Plex+Sans:wght@400;500;600&display=swap" rel="stylesheet">
<style>
*, *::before, *::after {{ box-sizing: border-box; margin: 0; padding: 0; }}

body {{
  font-family: 'IBM Plex Sans', sans-serif;
  font-size: 13.5px;
  line-height: 1.65;
  background: #f0ece4;
  color: #1a1a1a;
}}

a {{ color: #1a4a8a; }}
a:hover {{ text-decoration: underline; }}

code, .kod-mali {{
  font-family: 'IBM Plex Mono', monospace;
  font-size: 12px;
  background: #e8e3d8;
  padding: 1px 5px;
  border-radius: 3px;
  word-break: break-all;
}}

.zaglavlje {{
  background: #1a1a2e;
  color: #f0ece4;
  padding: 0;
  border-bottom: 4px solid #c8a84b;
}}

.zaglavlje-unutra {{
  max-width: 960px;
  margin: 0 auto;
  padding: 36px 40px 28px;
  display: grid;
  grid-template-columns: 1fr auto;
  align-items: end;
  gap: 20px;
}}

.zag-lijevo {{}}

.zag-oznaka {{
  font-family: 'IBM Plex Mono', monospace;
  font-size: 10px;
  letter-spacing: 3px;
  text-transform: uppercase;
  color: #c8a84b;
  margin-bottom: 8px;
}}

.zag-domen {{
  font-size: 32px;
  font-weight: 600;
  letter-spacing: -0.5px;
  color: #ffffff;
  margin-bottom: 4px;
}}

.zag-ip {{
  font-family: 'IBM Plex Mono', monospace;
  font-size: 12px;
  color: #8a8a9a;
}}

.zag-desno {{
  text-align: right;
}}

.zag-datum {{
  font-size: 11px;
  color: #8a8a9a;
  font-family: 'IBM Plex Mono', monospace;
  line-height: 2;
}}

.navigacija {{
  background: #252540;
  border-bottom: 1px solid #3a3a5a;
}}

.nav-unutra {{
  max-width: 960px;
  margin: 0 auto;
  padding: 0 40px;
  display: flex;
  gap: 0;
  overflow-x: auto;
}}

.nav-unutra a {{
  display: block;
  padding: 11px 18px;
  font-size: 11px;
  font-weight: 500;
  letter-spacing: 1.2px;
  text-transform: uppercase;
  color: #9090aa;
  text-decoration: none;
  border-bottom: 3px solid transparent;
  transition: color .15s, border-color .15s;
  white-space: nowrap;
}}

.nav-unutra a:hover {{
  color: #c8a84b;
  border-bottom-color: #c8a84b;
}}

main {{
  max-width: 960px;
  margin: 0 auto;
  padding: 32px 40px 60px;
  display: grid;
  gap: 24px;
}}

.blok {{
  background: #faf8f3;
  border: 1px solid #d8d2c6;
  border-radius: 4px;
  overflow: hidden;
  page-break-inside: avoid;
}}

.blok-naslov {{
  background: #1a1a2e;
  color: #f0ece4;
  font-size: 12px;
  font-weight: 600;
  letter-spacing: 2px;
  text-transform: uppercase;
  padding: 10px 20px;
  border-bottom: 2px solid #c8a84b;
  font-family: 'IBM Plex Mono', monospace;
}}

.blok-tijelo {{
  padding: 20px;
}}

.tabela {{
  width: 100%;
  border-collapse: collapse;
  margin-bottom: 4px;
}}

.tabela thead tr {{
  background: #ede8de;
}}

.tabela thead th {{
  text-align: left;
  padding: 7px 12px;
  font-size: 11px;
  font-weight: 600;
  letter-spacing: 0.8px;
  text-transform: uppercase;
  color: #5a5a6a;
  border-bottom: 1px solid #d0c8b8;
}}

.tabela tbody tr {{
  border-bottom: 1px solid #e8e2d6;
}}

.tabela tbody tr:last-child {{ border-bottom: none; }}

.tabela tbody tr:hover {{ background: #f5f0e8; }}

td.naziv {{
  color: #5a5055;
  font-size: 11.5px;
  font-weight: 500;
  padding: 8px 12px;
  width: 210px;
  vertical-align: top;
  white-space: nowrap;
}}

td.vrijednost {{
  padding: 8px 12px;
  color: #1a1a1a;
  word-break: break-word;
  font-family: 'IBM Plex Mono', monospace;
  font-size: 12px;
}}

.status-pill {{
  display: inline-block;
  font-size: 10.5px;
  font-weight: 600;
  padding: 2px 9px;
  border-radius: 2px;
  font-family: 'IBM Plex Mono', monospace;
  letter-spacing: 0.5px;
}}

.status-ok   {{ background: #d4edda; color: #1a5c2a; border: 1px solid #a8d5b5; }}
.status-err  {{ background: #fde0e0; color: #8b1a1a; border: 1px solid #f0a8a8; }}
.status-upoz {{ background: #fff3cd; color: #7a5c00; border: 1px solid #e8d080; }}

.lista-sub, .lista-san {{
  list-style: none;
  padding: 0;
  columns: 2;
  column-gap: 20px;
  margin-top: 8px;
}}

.lista-sub li, .lista-san li {{
  font-family: 'IBM Plex Mono', monospace;
  font-size: 11.5px;
  color: #2a3a5a;
  padding: 3px 0;
  border-bottom: 1px dotted #d8d2c6;
  break-inside: avoid;
}}

.lista-sub li::before {{ content: "↳ "; color: #c8a84b; }}
.lista-san li::before {{ content: "• "; color: #888; }}

.pod-naslov {{
  font-size: 11px;
  font-weight: 600;
  letter-spacing: 1.5px;
  text-transform: uppercase;
  color: #8a7a6a;
  margin: 20px 0 10px;
  padding-bottom: 4px;
  border-bottom: 1px solid #d8d2c6;
}}

.napomena {{
  font-size: 12px;
  color: #6a6a7a;
  margin-bottom: 12px;
  padding: 8px 12px;
  background: #f0ece4;
  border-left: 3px solid #c8a84b;
  border-radius: 0 2px 2px 0;
}}

.napomena.greska {{
  color: #8b1a1a;
  background: #fdf0f0;
  border-left-color: #e05050;
}}

.prazno {{ color: #aaa; font-style: italic; }}

.veza-mapa {{
  font-size: 11px;
  font-family: 'IBM Plex Mono', monospace;
}}

.podnozje {{
  background: #1a1a2e;
  color: #6a6a8a;
  text-align: center;
  padding: 20px 40px;
  font-size: 11px;
  font-family: 'IBM Plex Mono', monospace;
  letter-spacing: 0.5px;
  border-top: 3px solid #c8a84b;
}}

@media print {{
  body {{ background: white; font-size: 11px; }}
  .navigacija, .nav-unutra {{ display: none; }}
  .zaglavlje {{ -webkit-print-color-adjust: exact; print-color-adjust: exact; }}
  .blok {{ break-inside: avoid; border: 1px solid #ccc; }}
  .blok-naslov {{ -webkit-print-color-adjust: exact; print-color-adjust: exact; }}
}}
</style>
</head>
<body>

<header class="zaglavlje">
  <div class="zaglavlje-unutra">
    <div class="zag-lijevo">
      <div class="zag-oznaka">OSINT Izviđački Izvještaj</div>
      <div class="zag-domen">{domen}</div>
      <div class="zag-ip">IP: {ip or "nije razriješen"}</div>
    </div>
    <div class="zag-desno">
      <div class="zag-datum">
        Datum analize:<br>
        <strong style="color:#f0ece4">{datum}</strong>
      </div>
    </div>
  </div>
</header>

<nav class="navigacija">
  <div class="nav-unutra">
    <a href="#whois">WHOIS</a>
    <a href="#dns">DNS</a>
    <a href="#ssl">SSL/TLS</a>
    <a href="#headeri">HTTP Headeri</a>
    <a href="#geo">Geolokacija</a>
    <a href="#subdomeni">Subdomeni</a>
  </div>
</nav>

<main>
  {odjeljak("whois",     "01 · WHOIS informacije",               whois_html)}
  {odjeljak("dns",       "02 · DNS zapisi",                      dns_html)}
  {odjeljak("ssl",       "03 · SSL/TLS sertifikat",              ssl_html)}
  {odjeljak("headeri",   "04 · HTTP header analiza",             header_html)}
  {odjeljak("geo",       "05 · IP geolokacija",                  geo_html)}
  {odjeljak("subdomeni", "06 · Enumeracija poddomena (crt.sh)",  sub_html)}
</main>

<footer class="podnozje">
  OSINT alat — specijalistički rad &nbsp;·&nbsp; Analiza izvršena: {datum}
</footer>

</body>
</html>"""
    return html


print("=" * 52)
print("   OSINT ALAT — Specijalistički rad")
print("=" * 52)

unos = input("\nUnesi domen (npr. example.com): ").strip().lower()
if unos.startswith("http://") or unos.startswith("https://"):
    unos = unos.split("//")[1].split("/")[0]
domen = unos
url   = f"http://{domen}"

print("\n[1/6] Dohvatam WHOIS informacije...")
whois_pod = whois_info(domen)

print("[2/6] Dohvatam DNS zapise...")
dns_pod = dns_info(domen)

print("[3/6] Skeniram SSL/TLS sertifikat...")
ssl_pod = ssl_info(domen)

print("[4/6] Analiziram HTTP headere...")
header_pod = http_headeri(url)

print("[5/6] Dohvatam IP adresu i geolokaciju...")
ip = dohvati_ip(domen)
geo_pod = ip_geolokacija(ip) if ip else {"greska": "Nije moguće razriješiti IP adresu"}

print("[6/6] Enumeracija poddomena putem crt.sh (može potrajati)...")
sub_pod = subdomeni_enum(domen)

print("\nGeneriram HTML izvještaj...")
html_sadrzaj = generiraj_html(
    domen, ip, whois_pod, dns_pod,
    ssl_pod, header_pod, geo_pod, sub_pod
)

naziv_fajla = f"osint_{domen.replace('.', '_')}.html"
with open(naziv_fajla, "w", encoding="utf-8") as f:
    f.write(html_sadrzaj)

print(f"\n Gotovo! Izvještaj sačuvan kao: {naziv_fajla}")
print(f"   Otvori ga u pregledaču da vidiš rezultate.")
print("=" * 52)