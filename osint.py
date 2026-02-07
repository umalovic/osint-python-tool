import whois
import dns.resolver
import requests
from bs4 import BeautifulSoup
import re

def whois_info(domena, report):
    report.write("\n WHOIS INFORMACIJE:\n")
    try:
        info = whois.whois(domena)
        for key, value in info.items():
            report.write(f"{key}: {value}\n")
        print("WHOIS informacije spremljene u report.txt")
    except Exception as e:
        report.write(f"Greška pri dohvatanju WHOIS informacija: {e}\n")
        print("Greška pri WHOIS-u. Provjeri report.txt za detalje.")

def dns_info(domena, report):
    report.write("\n DNS ZAPISI:\n")
    zapisi = ['A', 'AAAA', 'MX', 'TXT', 'NS', 'CNAME', 'SOA']
    for record in zapisi:
        try:
            odgovori = dns.resolver.resolve(domena, record)
            report.write(f"\n{record} zapisi:\n")
            for rdata in odgovori:
                report.write(f"  {rdata.to_text()}\n")
        except Exception:
            report.write(f"Nema {record} zapisa ili nije moguće dohvatiti.\n")
    print("DNS zapisi spremljeni u report.txt")


def email_scraper(url, report):
    report.write("\n Pretraga e-mail adresa na stranici:\n")
    try:
        response = requests.get(url, timeout=10)
        if response.status_code != 200:
            # pokušaj HTTPS fallback
            if url.startswith("http://"):
                url = url.replace("http://", "https://")
                response = requests.get(url, timeout=10)
        
        html = response.text
        emails = re.findall(r"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}", html)
        if emails:
            for email in set(emails):
                report.write(f" - {email}\n")
        else:
            report.write("Nema pronađenih e-mail adresa.\n")
        print("Email scraping završen. Rezultati u report.txt")
    except Exception as e:
        report.write(f"Greška pri dohvaćanju stranice: {e}\n")
        print("Greška pri web scraping-u. Provjeri report.txt")

# Glavni dio
print("=== OSINT BASIC TOOL (sa report.txt) ===")
domena = input("Unesi domenu (npr. example.com): ")
url = f"http://{domena}"

# Otvaranje fajla 
with open("report.txt", "w", encoding="utf-8") as report:
    report.write(f"OSINT IZVJEŠTAJ ZA: {domena}\n")
    whois_info(domena, report)
    dns_info(domena, report)
    email_scraper(url, report)

print("\n✅ Pretraga završena. Pogledaj report.txt za rezultate.")
