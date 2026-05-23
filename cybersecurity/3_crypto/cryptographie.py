#!/usr/bin/env python3
"""
CRYPTOGRAPHIE — Fondamentaux pour la cybersécurité
Techniques: Hachage, chiffrement symétrique/asymétrique, analyse de mots de passe
"""

import hashlib
import hmac
import base64
import os
import secrets
import struct
from itertools import product

# ─────────────────────────────────────────────────
# 1. HACHAGE — Intégrité et stockage de mots de passe
# ─────────────────────────────────────────────────
def hacher_mot_de_passe(mot_de_passe: str) -> dict:
    """
    Démontre différents algorithmes de hachage.
    MD5/SHA1 sont OBSOLÈTES pour les mots de passe.
    Utiliser bcrypt, scrypt ou argon2 en production.
    """
    mdp_bytes = mot_de_passe.encode()
    return {
        "MD5 (OBSOLÈTE)":    hashlib.md5(mdp_bytes).hexdigest(),
        "SHA-1 (OBSOLÈTE)":  hashlib.sha1(mdp_bytes).hexdigest(),
        "SHA-256":           hashlib.sha256(mdp_bytes).hexdigest(),
        "SHA-512":           hashlib.sha512(mdp_bytes).hexdigest(),
        "SHA3-256":          hashlib.sha3_256(mdp_bytes).hexdigest(),
        "BLAKE2b":           hashlib.blake2b(mdp_bytes).hexdigest(),
    }

def hachage_avec_sel(mot_de_passe: str) -> tuple[str, str]:
    """
    Hachage sécurisé avec sel — méthode recommandée.
    Le sel empêche les attaques par rainbow tables.
    """
    sel = secrets.token_hex(32)          # 256 bits de sel aléatoire
    hash_final = hashlib.pbkdf2_hmac(
        "sha256",
        mot_de_passe.encode(),
        sel.encode(),
        iterations=600_000               # NIST recommande 600k pour PBKDF2-SHA256
    )
    return sel, hash_final.hex()

def verifier_mot_de_passe(mot_de_passe: str, sel: str, hash_stocke: str) -> bool:
    """Vérifie un mot de passe contre son hash stocké."""
    hash_calcule = hashlib.pbkdf2_hmac(
        "sha256", mot_de_passe.encode(), sel.encode(), iterations=600_000
    )
    return hmac.compare_digest(hash_calcule.hex(), hash_stocke)


# ─────────────────────────────────────────────────
# 2. CHIFFREMENT SYMÉTRIQUE — XOR et AES simplifié
# ─────────────────────────────────────────────────
def chiffrement_xor(message: bytes, cle: bytes) -> bytes:
    """
    XOR cipher — le plus simple, base de tous les chiffrements.
    JAMAIS utilisé seul en production (cassé trivialemement).
    C'est la base de comprendre les chiffrements de flux.
    """
    return bytes(m ^ c for m, c in zip(message, (cle * (len(message) // len(cle) + 1))[:len(message)]))

def analyser_xor_monocle(ciphertext: bytes) -> list[tuple]:
    """
    Attaque par force brute sur XOR avec clé 1 octet.
    Technique fondamentale pour les CTF.
    """
    resultats = []
    for cle in range(256):
        decode = bytes(b ^ cle for b in ciphertext)
        try:
            texte = decode.decode("utf-8")
            score = sum(1 for c in texte.lower() if c in "etaoinshrdlucmfywgpbvkjxqz ")
            resultats.append((score, cle, texte))
        except UnicodeDecodeError:
            pass

    resultats.sort(reverse=True)
    return resultats[:5]

def simuler_aes_ecb_faiblesse(blocs_message: list[bytes]) -> list[bytes]:
    """
    Démontre la faiblesse du mode ECB d'AES:
    Blocs identiques → ciphertexts identiques.
    C'est pourquoi on utilise CBC/GCM à la place.
    """
    # Simulation: en vrai AES, les blocs égaux donnent les mêmes sorties
    print("\n[!] Faiblesse ECB: blocs identiques → même chiffré")
    for i, bloc in enumerate(blocs_message):
        print(f"  Bloc {i}: {bloc.hex()}")

    print("\n  En mode CBC avec IV aléatoire: chaque bloc est unique")
    print("  En mode GCM: authentification + chiffrement intégré")
    return blocs_message


# ─────────────────────────────────────────────────
# 3. ENCODING — Base64, Hex, URL (souvent confondus avec chiffrement)
# ─────────────────────────────────────────────────
def encoder_decoder(texte: str) -> dict:
    """
    ATTENTION: L'encodage n'est PAS du chiffrement!
    Base64 est réversible sans clé — c'est juste du formatage.
    """
    return {
        "texte_original":  texte,
        "base64":          base64.b64encode(texte.encode()).decode(),
        "base64_url":      base64.urlsafe_b64encode(texte.encode()).decode(),
        "hex":             texte.encode().hex(),
        "url_encoded":     "".join(f"%{ord(c):02x}" if not c.isalnum() else c for c in texte),
        "base64_decode":   base64.b64decode(base64.b64encode(texte.encode())).decode(),
    }


# ─────────────────────────────────────────────────
# 4. ANALYSE DE MOTS DE PASSE — Attaques courantes
# ─────────────────────────────────────────────────
def attaque_dictionnaire(hash_cible: str, wordlist: list[str]) -> str | None:
    """
    Attaque par dictionnaire — la plus efficace en pratique.
    Plus de 80% des mots de passe sont dans des wordlists connues.
    """
    print(f"\n[*] Attaque dictionnaire sur: {hash_cible[:20]}...")
    for mot in wordlist:
        if hashlib.md5(mot.encode()).hexdigest() == hash_cible:
            print(f"  [TROUVÉ] Mot de passe: {mot!r}")
            return mot
    print("  [!] Non trouvé dans le dictionnaire")
    return None

def attaque_bruteforce(hash_cible: str, charset: str, longueur_max: int = 4) -> str | None:
    """
    Brute force — teste toutes les combinaisons possibles.
    Exponentiel: 62^8 = 218 trillions pour 8 chars alphanumériques.
    """
    print(f"\n[*] Brute force (max {longueur_max} chars, charset: {charset[:20]}...)")
    for longueur in range(1, longueur_max + 1):
        for combo in product(charset, repeat=longueur):
            candidat = "".join(combo)
            if hashlib.md5(candidat.encode()).hexdigest() == hash_cible:
                print(f"  [TROUVÉ] {candidat!r}")
                return candidat
    print("  [!] Non trouvé")
    return None

def evaluer_force_mdp(mot_de_passe: str) -> dict:
    """Évalue la force d'un mot de passe."""
    score = 0
    problemes = []

    if len(mot_de_passe) >= 12:
        score += 2
    elif len(mot_de_passe) >= 8:
        score += 1
    else:
        problemes.append("Trop court (< 8 caractères)")

    if any(c.isupper() for c in mot_de_passe):
        score += 1
    else:
        problemes.append("Aucune majuscule")

    if any(c.islower() for c in mot_de_passe):
        score += 1
    else:
        problemes.append("Aucune minuscule")

    if any(c.isdigit() for c in mot_de_passe):
        score += 1
    else:
        problemes.append("Aucun chiffre")

    if any(c in "!@#$%^&*()_+-=[]{}|;:,.<>?" for c in mot_de_passe):
        score += 2
    else:
        problemes.append("Aucun caractère spécial")

    # Mots de passe communs
    communs = {"password", "123456", "qwerty", "admin", "letmein", "password123"}
    if mot_de_passe.lower() in communs:
        score = 0
        problemes.append("MOT DE PASSE COMMUN — extrêmement dangereux!")

    niveaux = {0: "TERRIBLE", 1: "TRÈS FAIBLE", 2: "FAIBLE", 3: "MOYEN", 4: "BON", 5: "FORT", 6: "TRÈS FORT", 7: "EXCELLENT"}
    return {"score": score, "niveau": niveaux.get(score, "EXCELLENT"), "problemes": problemes}


# ─────────────────────────────────────────────────
# 5. HMAC — Authentification des messages
# ─────────────────────────────────────────────────
def creer_hmac(message: str, cle_secrete: str) -> str:
    """HMAC garantit l'intégrité ET l'authenticité d'un message."""
    signature = hmac.new(
        cle_secrete.encode(),
        message.encode(),
        hashlib.sha256
    ).hexdigest()
    return signature

def verifier_hmac(message: str, cle_secrete: str, signature: str) -> bool:
    """Vérifie un HMAC de façon sécurisée (résistant aux timing attacks)."""
    signature_attendue = creer_hmac(message, cle_secrete)
    return hmac.compare_digest(signature, signature_attendue)  # Pas de comparaison directe!


# ─────────────────────────────────────────────────
# DÉMONSTRATION
# ─────────────────────────────────────────────────
if __name__ == "__main__":
    print("=" * 60)
    print("  CRYPTOGRAPHIE — Guide Ingénieur Cybersécurité")
    print("=" * 60)

    # Hachage
    print("\n[1] HACHAGE DU MOT DE PASSE 'password123':")
    hashes = hacher_mot_de_passe("password123")
    for algo, h in hashes.items():
        print(f"  {algo:<25} {h[:40]}...")

    # Hachage sécurisé
    print("\n[2] HACHAGE SÉCURISÉ AVEC SEL:")
    sel, hash_securise = hachage_avec_sel("MonMotDePasse!")
    print(f"  Sel:  {sel[:32]}...")
    print(f"  Hash: {hash_securise[:40]}...")
    print(f"  Vérification: {verifier_mot_de_passe('MonMotDePasse!', sel, hash_securise)}")

    # Encodage
    print("\n[3] ENCODAGE (≠ CHIFFREMENT):")
    enc = encoder_decoder("Bonjour le monde")
    for k, v in enc.items():
        print(f"  {k:<18} {v}")

    # Évaluation de mots de passe
    print("\n[4] ÉVALUATION DE MOTS DE PASSE:")
    for mdp in ["password", "Pass1!", "Tr0ub4dor&3", "C0rrect#H0rse$Battery"]:
        result = evaluer_force_mdp(mdp)
        print(f"  {mdp:<25} → {result['niveau']} (score: {result['score']}/7)")

    # HMAC
    print("\n[5] HMAC:")
    msg = "Transférer 1000€ à Alice"
    cle = "cle_secrete_super_longue_et_aleatoire"
    sig = creer_hmac(msg, cle)
    print(f"  Message:   {msg}")
    print(f"  HMAC:      {sig[:40]}...")
    print(f"  Valide:    {verifier_hmac(msg, cle, sig)}")
    print(f"  Falsifié:  {verifier_hmac(msg + ' au lieu de Bob', cle, sig)}")

    # Dictionnaire
    print("\n[6] ATTAQUE DICTIONNAIRE:")
    wordlist = ["admin", "password", "123456", "letmein", "qwerty"]
    hash_test = hashlib.md5("letmein".encode()).hexdigest()
    attaque_dictionnaire(hash_test, wordlist)

    print("\n[OUTILS PROS]")
    print("  hashcat    — GPU cracking: hashcat -m 0 hash.txt wordlist.txt")
    print("  john       — John The Ripper: john --format=md5 hash.txt")
    print("  openssl    — Crypto en ligne de commande")
    print("  python cryptography — Lib Python pro: pip install cryptography")
