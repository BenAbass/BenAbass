# Guide Complet — Ingénieur en Cybersécurité

## Structure du guide

```
cybersecurity/
├── 1_reseau/           Scanner réseau, découverte d'hôtes, ports
├── 2_web/              Sécurité web, OWASP Top 10, fuzzing
├── 3_crypto/           Hachage, chiffrement, attaques de mots de passe
├── 4_forensics/        Analyse forensique, logs, stéganographie
├── 5_exploitation/     Buffer overflow, reverse shells, privesc
├── 6_defensive/        IDS, WAF, SIEM, Incident Response
└── 7_outils/           Référence des commandes et outils
```

---

## Domaines couverts

### 1. Sécurité Réseau (`1_reseau/`)
- Ping sweep et découverte d'hôtes
- Scan de ports TCP/UDP
- Banner grabbing et fingerprinting
- Résolution DNS et énumération de sous-domaines

### 2. Sécurité Web (`2_web/`)
- Analyse des en-têtes HTTP de sécurité
- Détection SQL Injection (OWASP A03)
- Détection XSS réfléchi
- Path Traversal et LFI
- Fuzzing de répertoires

### 3. Cryptographie (`3_crypto/`)
- Algorithmes de hachage (MD5, SHA-256, BLAKE2b)
- Hachage sécurisé avec sel (PBKDF2)
- Chiffrement XOR et principes AES
- Attaque par dictionnaire et brute force
- HMAC pour l'authentification de messages
- Évaluation de la force des mots de passe

### 4. Forensique Numérique (`4_forensics/`)
- Hash de fichiers pour preuve légale (MD5 + SHA-256)
- Identification via magic bytes
- Extraction de métadonnées
- Analyse de logs (auth.log, access.log)
- Stéganographie LSB
- Extraction de strings depuis des binaires

### 5. Exploitation (`5_exploitation/`)
- Théorie du buffer overflow et architecture stack
- Pattern cyclique pour localiser EIP
- Format string vulnerabilities
- Génération de reverse shells (bash, python, php, powershell)
- Privilege escalation Linux (SUID, sudo, crontab)
- Mécanismes de persistance

### 6. Sécurité Défensive (`6_defensive/`)
- IDS (Intrusion Detection System)
- WAF (Web Application Firewall) avec rate limiting
- SIEM avec corrélation d'événements
- Checklist hardening Linux
- Plan Incident Response (6 phases PICERL)
- Commandes de collecte de preuves

### 7. Outils Essentiels (`7_outils/`)
- Nmap (scan réseau)
- Netcat (connexions)
- Hydra (brute force)
- Gobuster (fuzzing web)
- SQLMap (SQLi)
- John / Hashcat (crack de hashs)
- Metasploit (exploitation)
- OpenSSL (cryptographie)
- Wireshark / Tcpdump (analyse réseau)
- Outils OSINT (theHarvester, Sublist3r, Shodan)

---

## Roadmap d'apprentissage

```
DÉBUTANT (0-6 mois)
├── Linux CLI (bash, permissions, réseau)
├── Networking (TCP/IP, DNS, HTTP)
├── Python scripting de base
├── TryHackMe — Parcours "Pre-Security" et "SOC Level 1"
└── CTF débutants (PicoCTF)

INTERMÉDIAIRE (6-18 mois)
├── OWASP Top 10 (PortSwigger Web Academy)
├── Nmap, Burp Suite, Metasploit
├── HackTheBox — Machines "Easy"
├── Certifications: CompTIA Security+, eJPT
└── CTF réguliers (CTFtime.org)

AVANCÉ (18-36 mois)
├── Binary exploitation (pwntools, GDB, ROP chains)
├── Malware analysis (Ghidra, IDA Free, Cutter)
├── Active Directory attacks
├── Certifications: OSCP, CEH, CISSP
└── Bug bounty (HackerOne, Bugcrowd)

EXPERT (36+ mois)
├── Exploit development 0-day
├── Reverse engineering avancé
├── Red Team operations
├── Certifications: OSEP, OSED, CRTO
└── Contribution à la sécurité open source
```

---

## Certifications recommandées

| Niveau | Certification | Domaine |
|--------|---------------|---------|
| Débutant | CompTIA Security+ | Généraliste |
| Débutant | eJPT (eLearnSecurity) | Pentesting |
| Intermédiaire | CEH (EC-Council) | Ethical Hacking |
| Intermédiaire | OSCP (Offensive Security) | Pentesting |
| Avancé | CISSP (ISC²) | Management |
| Avancé | CRTO (Zero-Point Security) | Red Team |
| Expert | OSED/OSEP | Exploitation avancée |

---

## Plateformes d'entraînement

- **TryHackMe.com** — Idéal pour débutants, guided learning
- **HackTheBox.com** — Challenges réalistes, CTF compétitifs
- **PortSwigger Web Security Academy** — Meilleure ressource web gratuite
- **CTFtime.org** — Calendrier des compétitions CTF
- **PentesterLab.com** — Vulnérabilités web avec badges
- **DVWA** (Damn Vulnerable Web App) — Lab local pour web
- **VulnHub.com** — VMs vulnérables à télécharger

---

## Avertissement légal

> Ces techniques sont présentées à des **fins éducatives uniquement**.
> Ne les appliquez JAMAIS sans **autorisation écrite explicite** du propriétaire du système.
> L'accès non autorisé à des systèmes informatiques est **illégal** dans tous les pays.
> Utilisez toujours des environnements de laboratoire isolés.
