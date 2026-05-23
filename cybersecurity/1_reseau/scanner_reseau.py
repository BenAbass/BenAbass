#!/usr/bin/env python3
"""
SCANNER RÉSEAU - Compétence fondamentale en cybersécurité
Techniques: Scan de ports, détection d'hôtes, fingerprinting
"""

import socket
import subprocess
import ipaddress
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime

# ─────────────────────────────────────────────────
# 1. PING SWEEP — Découverte d'hôtes actifs
# ─────────────────────────────────────────────────
def ping_host(ip: str) -> bool:
    """Vérifie si un hôte est en ligne via ICMP."""
    result = subprocess.run(
        ["ping", "-c", "1", "-W", "1", str(ip)],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL
    )
    return result.returncode == 0

def ping_sweep(network: str) -> list[str]:
    """Scanne tout un sous-réseau pour trouver les hôtes actifs."""
    actifs = []
    net = ipaddress.ip_network(network, strict=False)
    print(f"[*] Scan du réseau {network} ({net.num_addresses} adresses)...")

    with ThreadPoolExecutor(max_workers=100) as executor:
        resultats = {str(ip): executor.submit(ping_host, str(ip)) for ip in net.hosts()}

    for ip, future in resultats.items():
        if future.result():
            print(f"  [+] {ip} — EN LIGNE")
            actifs.append(ip)

    return actifs


# ─────────────────────────────────────────────────
# 2. SCAN DE PORTS — Découverte des services exposés
# ─────────────────────────────────────────────────
PORTS_COMMUNS = {
    21: "FTP",    22: "SSH",    23: "Telnet",   25: "SMTP",
    53: "DNS",    80: "HTTP",   110: "POP3",    143: "IMAP",
    443: "HTTPS", 445: "SMB",   3306: "MySQL",  3389: "RDP",
    5432: "PostgreSQL", 6379: "Redis", 8080: "HTTP-Alt", 27017: "MongoDB"
}

def scan_port(ip: str, port: int, timeout: float = 1.0) -> bool:
    """Tente une connexion TCP sur un port (SYN scan simplifié)."""
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(timeout)
            return s.connect_ex((ip, port)) == 0
    except socket.error:
        return False

def banner_grab(ip: str, port: int) -> str:
    """Récupère la bannière d'un service pour identifier sa version."""
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(2)
            s.connect((ip, port))
            s.send(b"HEAD / HTTP/1.0\r\n\r\n")  # probe HTTP
            return s.recv(1024).decode(errors="ignore").strip()[:80]
    except Exception:
        return ""

def scan_ports(ip: str, ports: list[int] = None) -> dict:
    """Scanne les ports d'un hôte et retourne les services détectés."""
    if ports is None:
        ports = list(PORTS_COMMUNS.keys())

    ouverts = {}
    print(f"\n[*] Scan de {ip} — {len(ports)} ports...")
    debut = datetime.now()

    with ThreadPoolExecutor(max_workers=50) as executor:
        resultats = {port: executor.submit(scan_port, ip, port) for port in ports}

    for port, future in resultats.items():
        if future.result():
            service = PORTS_COMMUNS.get(port, "Inconnu")
            banniere = banner_grab(ip, port)
            ouverts[port] = {"service": service, "banniere": banniere}
            print(f"  [+] Port {port:5d}/tcp  OUVERT  {service:<15} {banniere}")

    duree = (datetime.now() - debut).total_seconds()
    print(f"\n[*] Terminé en {duree:.2f}s — {len(ouverts)} port(s) ouvert(s)")
    return ouverts


# ─────────────────────────────────────────────────
# 3. RÉSOLUTION DNS — Reconnaissance passive
# ─────────────────────────────────────────────────
def dns_lookup(domaine: str) -> dict:
    """Résout un domaine et ses variantes."""
    resultats = {}
    sous_domaines = ["", "www", "mail", "ftp", "admin", "api", "dev", "staging"]

    for sub in sous_domaines:
        host = f"{sub}.{domaine}" if sub else domaine
        try:
            ip = socket.gethostbyname(host)
            resultats[host] = ip
            print(f"  [+] {host:<30} → {ip}")
        except socket.gaierror:
            pass

    return resultats


# ─────────────────────────────────────────────────
# DÉMONSTRATION
# ─────────────────────────────────────────────────
if __name__ == "__main__":
    print("=" * 60)
    print("  SCANNER RÉSEAU — Guide Ingénieur Cybersécurité")
    print("=" * 60)

    # Scan localhost pour la démo
    print("\n[EXEMPLE] Scan des ports de localhost:")
    ports_ouverts = scan_ports("127.0.0.1", list(range(1, 1025)))

    print("\n[EXEMPLE] Résolution DNS:")
    dns_lookup("example.com")

    print("\n[CONSEIL] En production, utilisez Nmap:")
    print("  nmap -sV -sC -p- --open -T4 <cible>")
    print("  nmap -sU --top-ports 100 <cible>  # UDP")
