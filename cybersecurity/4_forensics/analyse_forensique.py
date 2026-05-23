#!/usr/bin/env python3
"""
FORENSIQUE NUMÉRIQUE — Analyse d'incidents et collecte de preuves
Techniques: Analyse de fichiers, logs, métadonnées, réseau
"""

import os
import re
import stat
import hashlib
import struct
from pathlib import Path
from datetime import datetime

# ─────────────────────────────────────────────────
# 1. INTÉGRITÉ DES FICHIERS — Hash pour preuve légale
# ─────────────────────────────────────────────────
def hash_fichier(chemin: str) -> dict:
    """
    Calcule les hashs cryptographiques d'un fichier.
    Standard légal: MD5 + SHA-256 ensemble pour une preuve solide.
    """
    md5 = hashlib.md5()
    sha256 = hashlib.sha256()
    sha1 = hashlib.sha1()

    with open(chemin, "rb") as f:
        for chunk in iter(lambda: f.read(65536), b""):
            md5.update(chunk)
            sha256.update(chunk)
            sha1.update(chunk)

    return {
        "fichier":  chemin,
        "md5":      md5.hexdigest(),
        "sha1":     sha1.hexdigest(),
        "sha256":   sha256.hexdigest(),
        "taille":   os.path.getsize(chemin),
    }

def comparer_hashs(chemin1: str, chemin2: str) -> bool:
    """Vérifie si deux fichiers sont identiques (intégrité)."""
    h1 = hash_fichier(chemin1)["sha256"]
    h2 = hash_fichier(chemin2)["sha256"]
    return h1 == h2


# ─────────────────────────────────────────────────
# 2. MAGIC BYTES — Identification du vrai type de fichier
# ─────────────────────────────────────────────────
MAGIC_BYTES = {
    b"\x89PNG\r\n\x1a\n":     "PNG Image",
    b"\xff\xd8\xff":           "JPEG Image",
    b"GIF87a":                 "GIF87 Image",
    b"GIF89a":                 "GIF89 Image",
    b"%PDF":                   "PDF Document",
    b"PK\x03\x04":            "ZIP Archive (aussi .docx .xlsx .jar)",
    b"\x1f\x8b":               "GZIP Archive",
    b"BZh":                    "BZIP2 Archive",
    b"\x7fELF":                "ELF Exécutable Linux",
    b"MZ":                     "PE Exécutable Windows (.exe .dll)",
    b"#!":                     "Script (shebang)",
    b"\xca\xfe\xba\xbe":      "Java Class File",
    b"OggS":                   "OGG Audio/Video",
    b"fLaC":                   "FLAC Audio",
    b"\x00\x00\x00\x18ftyp":  "MP4 Video",
    b"RIFF":                   "WAV Audio / AVI Video",
    b"\x52\x61\x72\x21":      "RAR Archive",
    b"7z\xbc\xaf'\x1c":       "7-ZIP Archive",
}

def identifier_type_fichier(chemin: str) -> str:
    """
    Identifie le vrai type d'un fichier via ses magic bytes.
    Un attaquant peut renommer un .exe en .jpg — les magic bytes révèlent la vérité.
    """
    with open(chemin, "rb") as f:
        debut = f.read(16)

    for magic, description in MAGIC_BYTES.items():
        if debut.startswith(magic):
            return description

    return f"Inconnu (premiers octets: {debut.hex()[:16]})"


# ─────────────────────────────────────────────────
# 3. MÉTADONNÉES — Informations cachées dans les fichiers
# ─────────────────────────────────────────────────
def extraire_metadonnees(chemin: str) -> dict:
    """Extrait les métadonnées d'un fichier (pour enquête forensique)."""
    chemin_obj = Path(chemin)
    stats = chemin_obj.stat()

    permissions = stat.filemode(stats.st_mode)

    return {
        "nom":             chemin_obj.name,
        "extension":       chemin_obj.suffix,
        "taille_octets":   stats.st_size,
        "taille_lisible":  f"{stats.st_size / 1024:.2f} KB",
        "permissions":     permissions,
        "proprietaire_uid": stats.st_uid,
        "cree":            datetime.fromtimestamp(stats.st_ctime).isoformat(),
        "modifie":         datetime.fromtimestamp(stats.st_mtime).isoformat(),
        "accede":          datetime.fromtimestamp(stats.st_atime).isoformat(),
        "type_reel":       identifier_type_fichier(chemin),
        "sha256":          hash_fichier(chemin)["sha256"],
    }


# ─────────────────────────────────────────────────
# 4. ANALYSE DE LOGS — Détection d'intrusions
# ─────────────────────────────────────────────────
PATTERNS_SUSPECTS = {
    "Brute Force SSH":       r"Failed password for .* from (\d+\.\d+\.\d+\.\d+)",
    "Connexion SSH réussie": r"Accepted password for .* from (\d+\.\d+\.\d+\.\d+)",
    "Sudo abuse":            r"sudo:.*COMMAND=",
    "Accès root":            r"session opened for user root",
    "Modification compte":   r"usermod|useradd|userdel|passwd",
    "SQLi dans Apache":      r"(UNION|SELECT|INSERT|DROP|;--|\/\*)",
    "Scan de ports":         r"Port scan detected|nmap",
    "XSS dans Apache":       r"(<script|javascript:|onerror=)",
}

def analyser_logs(chemin_log: str) -> dict:
    """
    Analyse un fichier de log pour détecter des activités suspectes.
    Fichiers clés: /var/log/auth.log, /var/log/apache2/access.log
    """
    resultats = {pattern: [] for pattern in PATTERNS_SUSPECTS}
    ips_suspectes = {}

    try:
        with open(chemin_log, "r", errors="ignore") as f:
            for numero, ligne in enumerate(f, 1):
                for nom_pattern, regex in PATTERNS_SUSPECTS.items():
                    match = re.search(regex, ligne, re.IGNORECASE)
                    if match:
                        resultats[nom_pattern].append({
                            "ligne": numero,
                            "contenu": ligne.strip()[:120],
                            "groupe": match.group(1) if match.lastindex else None
                        })

                        # Tracker les IPs pour brute force
                        if nom_pattern == "Brute Force SSH" and match.lastindex:
                            ip = match.group(1)
                            ips_suspectes[ip] = ips_suspectes.get(ip, 0) + 1

    except FileNotFoundError:
        print(f"  [!] Fichier non trouvé: {chemin_log}")
        return {}

    # Rapport
    print(f"\n[*] Analyse de: {chemin_log}")
    for pattern, occurrences in resultats.items():
        if occurrences:
            print(f"  [!] {pattern}: {len(occurrences)} occurrence(s)")

    if ips_suspectes:
        print(f"\n  [!] IPs avec tentatives SSH multiples:")
        for ip, count in sorted(ips_suspectes.items(), key=lambda x: -x[1]):
            print(f"      {ip}: {count} tentatives")

    return resultats

def extraire_ips_logs(chemin_log: str) -> dict:
    """Extrait et compte toutes les IPs d'un fichier de log."""
    ips = {}
    pattern_ip = re.compile(r"\b(\d{1,3}(?:\.\d{1,3}){3})\b")

    try:
        with open(chemin_log, "r", errors="ignore") as f:
            for ligne in f:
                for ip in pattern_ip.findall(ligne):
                    ips[ip] = ips.get(ip, 0) + 1
    except FileNotFoundError:
        return {}

    return dict(sorted(ips.items(), key=lambda x: -x[1]))


# ─────────────────────────────────────────────────
# 5. STÉGANOGRAPHIE — Données cachées dans les images
# ─────────────────────────────────────────────────
def cacher_message_lsb(image_bytes: bytes, message: str) -> bytes:
    """
    Cache un message dans les bits de poids faible (LSB steganography).
    Technique utilisée par les malwares pour exfiltrer des données.
    """
    message_bits = "".join(f"{ord(c):08b}" for c in message) + "00000000"
    pixels = bytearray(image_bytes)

    if len(message_bits) > len(pixels):
        raise ValueError("Image trop petite pour le message")

    for i, bit in enumerate(message_bits):
        pixels[i] = (pixels[i] & 0b11111110) | int(bit)

    return bytes(pixels)

def extraire_message_lsb(image_bytes: bytes) -> str:
    """Extrait un message caché via LSB steganography."""
    bits = "".join(str(b & 1) for b in image_bytes)
    chars = []

    for i in range(0, len(bits) - 8, 8):
        octet = bits[i:i+8]
        if octet == "00000000":
            break
        chars.append(chr(int(octet, 2)))

    return "".join(chars)


# ─────────────────────────────────────────────────
# 6. STRINGS — Extraire les chaînes d'un binaire
# ─────────────────────────────────────────────────
def extraire_strings(chemin: str, longueur_min: int = 4) -> list[str]:
    """
    Équivalent de la commande Unix 'strings'.
    Permet d'analyser des malwares sans les exécuter.
    """
    strings_trouvees = []
    pattern = re.compile(rb"[ -~]{" + str(longueur_min).encode() + rb",}")

    with open(chemin, "rb") as f:
        contenu = f.read()

    for match in pattern.finditer(contenu):
        strings_trouvees.append(match.group().decode("ascii"))

    return strings_trouvees


# ─────────────────────────────────────────────────
# DÉMONSTRATION
# ─────────────────────────────────────────────────
if __name__ == "__main__":
    print("=" * 60)
    print("  FORENSIQUE NUMÉRIQUE — Guide Ingénieur Cybersécurité")
    print("=" * 60)

    # Créer un fichier de test
    fichier_test = "/tmp/test_forensique.txt"
    with open(fichier_test, "w") as f:
        f.write("Fichier de test pour l'analyse forensique\n")
        f.write("Données sensibles simulées\n")

    print("\n[1] HASH DU FICHIER (intégrité):")
    hashes = hash_fichier(fichier_test)
    for k, v in hashes.items():
        print(f"  {k:<10} {str(v)[:50]}")

    print("\n[2] TYPE RÉEL DU FICHIER:")
    type_reel = identifier_type_fichier(fichier_test)
    print(f"  → {type_reel}")

    print("\n[3] MÉTADONNÉES:")
    meta = extraire_metadonnees(fichier_test)
    for k, v in meta.items():
        print(f"  {k:<20} {v}")

    print("\n[4] STÉGANOGRAPHIE LSB (démonstration sur données simulées):")
    donnees_fictives = bytes(range(256)) * 10
    modifiees = cacher_message_lsb(donnees_fictives, "SECRET")
    extrait = extraire_message_lsb(modifiees)
    print(f"  Message caché puis extrait: {extrait!r}")

    print("\n[OUTILS PROS]")
    print("  autopsy/sleuthkit — Analyse de disques")
    print("  volatility        — Analyse de RAM: vol.py -f mem.raw imageinfo")
    print("  binwalk           — Analyse binaire: binwalk -e fichier")
    print("  exiftool          — Métadonnées: exiftool fichier.jpg")
    print("  stegsolve         — Stéganographie dans images")
    print("  strings           — Extraire texte: strings binaire | grep -i pass")
    print("  wireshark/tcpdump — Capture réseau")
