#!/usr/bin/env python3
"""
SÉCURITÉ DÉFENSIVE — Blue Team, Monitoring, Durcissement
Techniques: IDS, SIEM, WAF, Hardening, Incident Response
"""

import re
import time
import hashlib
import logging
import ipaddress
from collections import defaultdict
from datetime import datetime, timedelta
from typing import Callable

# ─────────────────────────────────────────────────
# 1. SYSTÈME DE DÉTECTION D'INTRUSION (IDS) simplifié
# ─────────────────────────────────────────────────
class IDS:
    """
    IDS basique: détecte les patterns d'attaque dans le trafic réseau.
    En production: Snort, Suricata, Zeek (anciennement Bro).
    """

    REGLES = [
        {"nom": "Scan de ports",      "pattern": r"SYN.*SYN.*SYN.*SYN",        "severite": "MEDIUM"},
        {"nom": "SQLi détectée",      "pattern": r"(UNION SELECT|OR 1=1|DROP TABLE)", "severite": "HIGH"},
        {"nom": "XSS détectée",       "pattern": r"<script.*?>|javascript:",    "severite": "HIGH"},
        {"nom": "Path Traversal",     "pattern": r"(\.\.\/){2,}|%2e%2e%2f",    "severite": "HIGH"},
        {"nom": "Commande injection", "pattern": r"(;|\|).*?(ls|cat|whoami|id)", "severite": "CRITICAL"},
        {"nom": "Shell upload",       "pattern": r"\.(php|asp|aspx|jsp).*upload", "severite": "CRITICAL"},
        {"nom": "Brute force",        "pattern": r"Failed.*login.*Failed.*login", "severite": "HIGH"},
        {"nom": "Scan Nmap",          "pattern": r"nmap|masscan",               "severite": "LOW"},
        {"nom": "User-Agent suspect", "pattern": r"(sqlmap|nikto|burp|w3af)",   "severite": "MEDIUM"},
    ]

    def __init__(self):
        self.alertes = []
        self.compteurs_ip = defaultdict(int)
        self.setup_logging()

    def setup_logging(self):
        logging.basicConfig(
            level=logging.INFO,
            format="%(asctime)s [%(levelname)s] %(message)s",
            datefmt="%Y-%m-%d %H:%M:%S"
        )
        self.logger = logging.getLogger("IDS")

    def analyser_requete(self, ip: str, requete: str) -> list[dict]:
        """Analyse une requête HTTP pour détecter des attaques."""
        alertes_trouvees = []

        for regle in self.REGLES:
            if re.search(regle["pattern"], requete, re.IGNORECASE):
                alerte = {
                    "timestamp": datetime.now().isoformat(),
                    "ip_source": ip,
                    "type": regle["nom"],
                    "severite": regle["severite"],
                    "requete": requete[:100],
                }
                alertes_trouvees.append(alerte)
                self.alertes.append(alerte)

                emoji = {"LOW": "[i]", "MEDIUM": "[!]", "HIGH": "[!!]", "CRITICAL": "[!!!]"}[regle["severite"]]
                self.logger.warning(f"{emoji} {regle['severite']} — {regle['nom']} depuis {ip}")

        return alertes_trouvees

    def detecter_brute_force(self, ip: str, succes: bool, fenetre_secondes: int = 60, seuil: int = 10) -> bool:
        """Détecte les attaques brute force par rate limiting."""
        cle = f"{ip}_{int(time.time() // fenetre_secondes)}"
        if not succes:
            self.compteurs_ip[cle] += 1
            if self.compteurs_ip[cle] >= seuil:
                self.logger.critical(f"[!!!] BRUTE FORCE — {ip}: {self.compteurs_ip[cle]} tentatives en {fenetre_secondes}s")
                return True
        return False

    def rapport(self) -> dict:
        """Génère un rapport des alertes."""
        par_severite = defaultdict(list)
        par_type = defaultdict(int)
        ips_suspectes = defaultdict(int)

        for alerte in self.alertes:
            par_severite[alerte["severite"]].append(alerte)
            par_type[alerte["type"]] += 1
            ips_suspectes[alerte["ip_source"]] += 1

        return {
            "total_alertes": len(self.alertes),
            "par_severite": {k: len(v) for k, v in par_severite.items()},
            "types_attaques": dict(par_type),
            "top_ips": dict(sorted(ips_suspectes.items(), key=lambda x: -x[1])[:10]),
        }


# ─────────────────────────────────────────────────
# 2. WAF — Web Application Firewall (simplifié)
# ─────────────────────────────────────────────────
class WAF:
    """
    WAF basique: filtre et bloque les requêtes malveillantes.
    En production: ModSecurity, Cloudflare WAF, AWS WAF.
    """

    IPS_BLOQUEES: set[str] = set()
    RATE_LIMIT: dict[str, list] = defaultdict(list)

    PATTERNS_BLOQUES = [
        r"(UNION\s+SELECT)",                  # SQLi
        r"(OR\s+1\s*=\s*1)",                  # SQLi auth bypass
        r"(<script[^>]*>.*?</script>)",       # XSS
        r"(javascript\s*:)",                  # XSS
        r"(\.\./){2,}",                       # Path traversal
        r"(\|.*?(bash|sh|cmd|powershell))",   # Command injection
        r"(eval\s*\()",                       # Code injection
        r"(base64_decode\s*\()",              # PHP obfuscation
    ]

    @classmethod
    def filtrer_requete(cls, ip: str, methode: str, chemin: str,
                        params: dict, headers: dict) -> tuple[bool, str]:
        """
        Filtre une requête HTTP.
        Retourne (autorisé: bool, raison: str)
        """
        # Vérifier si l'IP est bloquée
        if ip in cls.IPS_BLOQUEES:
            return False, f"IP {ip} bloquée"

        # Rate limiting (max 100 req/minute)
        maintenant = time.time()
        cls.RATE_LIMIT[ip] = [t for t in cls.RATE_LIMIT[ip] if maintenant - t < 60]
        cls.RATE_LIMIT[ip].append(maintenant)

        if len(cls.RATE_LIMIT[ip]) > 100:
            cls.IPS_BLOQUEES.add(ip)
            return False, f"Rate limit dépassé: {len(cls.RATE_LIMIT[ip])} req/min"

        # Scanner tous les paramètres
        toutes_valeurs = list(params.values()) + [chemin]
        for valeur in toutes_valeurs:
            for pattern in cls.PATTERNS_BLOQUES:
                if re.search(pattern, str(valeur), re.IGNORECASE):
                    return False, f"Payload malveillant détecté: {pattern[:30]}"

        # Vérifier User-Agent suspect
        user_agent = headers.get("User-Agent", "")
        outils_scan = ["sqlmap", "nikto", "masscan", "nmap", "dirbuster", "gobuster"]
        for outil in outils_scan:
            if outil.lower() in user_agent.lower():
                return False, f"Outil de scan détecté: {outil}"

        return True, "OK"

    @classmethod
    def sanitiser_input(cls, valeur: str) -> str:
        """Nettoie les entrées utilisateur pour prévenir XSS/SQLi."""
        remplacements = {
            "<": "&lt;",
            ">": "&gt;",
            '"': "&quot;",
            "'": "&#x27;",
            "/": "&#x2F;",
            "\\": "&#x5C;",
        }
        for char, escape in remplacements.items():
            valeur = valeur.replace(char, escape)
        return valeur


# ─────────────────────────────────────────────────
# 3. AUDIT DE CONFIGURATION — Hardening
# ─────────────────────────────────────────────────
CHECKLIST_HARDENING_LINUX = {
    "Désactiver root SSH": {
        "fichier": "/etc/ssh/sshd_config",
        "check": "PermitRootLogin no",
        "commande": "sed -i 's/PermitRootLogin yes/PermitRootLogin no/' /etc/ssh/sshd_config",
    },
    "SSH par clé uniquement": {
        "fichier": "/etc/ssh/sshd_config",
        "check": "PasswordAuthentication no",
        "commande": "sed -i 's/PasswordAuthentication yes/PasswordAuthentication no/' /etc/ssh/sshd_config",
    },
    "Firewall UFW actif": {
        "commande_check": "ufw status | grep 'Status: active'",
        "commande_fix": "ufw enable && ufw default deny incoming && ufw allow 22/tcp",
    },
    "Fail2ban installé": {
        "commande_check": "systemctl is-active fail2ban",
        "commande_fix": "apt install fail2ban -y && systemctl enable fail2ban",
    },
    "Mises à jour auto": {
        "commande_fix": "apt install unattended-upgrades -y && dpkg-reconfigure -plow unattended-upgrades",
    },
    "Désactiver IPv6 si inutile": {
        "fichier": "/etc/sysctl.conf",
        "check": "net.ipv6.conf.all.disable_ipv6 = 1",
    },
    "Partitions /tmp et /var séparées": {
        "description": "Monter /tmp avec noexec,nosuid,nodev",
    },
    "Audit avec auditd": {
        "commande_fix": "apt install auditd -y && systemctl enable auditd",
    },
    "Permissions /etc/passwd et /etc/shadow": {
        "commande_check": "stat /etc/passwd /etc/shadow",
        "attendu": "chmod 644 /etc/passwd && chmod 640 /etc/shadow",
    },
    "Umask restrictif": {
        "fichier": "/etc/profile",
        "check": "umask 027",
    },
}

REGLES_FIREWALL = [
    "ufw default deny incoming",
    "ufw default allow outgoing",
    "ufw allow 22/tcp    # SSH",
    "ufw allow 80/tcp    # HTTP",
    "ufw allow 443/tcp   # HTTPS",
    "ufw deny 23/tcp     # Telnet (non chiffré)",
    "ufw deny 21/tcp     # FTP (non chiffré)",
    "ufw deny 3306/tcp   # MySQL (jamais exposé publiquement)",
    "ufw deny 27017/tcp  # MongoDB (jamais exposé publiquement)",
    "ufw enable",
]


# ─────────────────────────────────────────────────
# 4. SIEM — Corrélation d'événements
# ─────────────────────────────────────────────────
class SIEM:
    """
    SIEM simplifié: collecte et corrèle des événements de sécurité.
    En production: Splunk, Elastic SIEM, IBM QRadar, Wazuh.
    """

    def __init__(self):
        self.evenements: list[dict] = []
        self.regles_correlation = [
            self._detecter_lateral_movement,
            self._detecter_exfiltration,
            self._detecter_persistance,
        ]

    def ingerer_evenement(self, source: str, type_evt: str,
                          donnees: dict, severite: str = "INFO") -> None:
        """Ingère un événement dans le SIEM."""
        evt = {
            "timestamp": datetime.now().isoformat(),
            "source": source,
            "type": type_evt,
            "severite": severite,
            "donnees": donnees,
        }
        self.evenements.append(evt)
        self._corréler(evt)

    def _corréler(self, nouvel_evt: dict) -> None:
        """Applique les règles de corrélation sur le nouvel événement."""
        for regle in self.regles_correlation:
            alerte = regle(nouvel_evt)
            if alerte:
                print(f"  [SIEM ALERTE] {alerte}")

    def _detecter_lateral_movement(self, evt: dict) -> str | None:
        """Détecte le mouvement latéral (connexions entre machines internes)."""
        if evt["type"] == "connexion_ssh":
            ip_src = evt["donnees"].get("ip_source", "")
            ip_dst = evt["donnees"].get("ip_destination", "")
            try:
                src = ipaddress.ip_address(ip_src)
                dst = ipaddress.ip_address(ip_dst)
                if src.is_private and dst.is_private and ip_src != ip_dst:
                    connexions_recentes = [
                        e for e in self.evenements[-20:]
                        if e["type"] == "connexion_ssh" and
                           e["donnees"].get("ip_source") == ip_src
                    ]
                    if len(connexions_recentes) > 3:
                        return f"Mouvement latéral possible: {ip_src} → plusieurs hôtes internes"
            except ValueError:
                pass
        return None

    def _detecter_exfiltration(self, evt: dict) -> str | None:
        """Détecte une possible exfiltration de données."""
        if evt["type"] == "transfert_fichier":
            taille_mb = evt["donnees"].get("taille_mb", 0)
            if taille_mb > 100:
                return f"Exfiltration possible: {taille_mb}MB transférés vers {evt['donnees'].get('destination')}"
        return None

    def _detecter_persistance(self, evt: dict) -> str | None:
        """Détecte la création de mécanismes de persistance."""
        if evt["type"] == "modification_fichier":
            fichier = evt["donnees"].get("fichier", "")
            fichiers_persistance = ["~/.bashrc", "~/.bash_profile", "/etc/crontab",
                                    "/etc/init.d/", "authorized_keys"]
            for f in fichiers_persistance:
                if f in fichier:
                    return f"Possible persistance: modification de {fichier}"
        return None


# ─────────────────────────────────────────────────
# 5. INCIDENT RESPONSE — Plan de réponse
# ─────────────────────────────────────────────────
PLAN_IR = {
    "1_PREPARATION": [
        "Mettre en place une équipe CSIRT",
        "Documenter l'inventaire des assets",
        "Configurer les outils de logging et monitoring",
        "Créer des playbooks par type d'incident",
        "Tester régulièrement les procédures (tabletop exercises)",
    ],
    "2_IDENTIFICATION": [
        "Analyser les alertes des IDS/SIEM",
        "Déterminer si c'est un vrai incident (triage)",
        "Documenter: Quoi? Quand? Comment? Qui?",
        "Classer la sévérité (P1/P2/P3/P4)",
        "Notifier les parties prenantes",
    ],
    "3_CONTAINMENT": [
        "Isoler les systèmes compromis du réseau",
        "Bloquer les IPs malveillantes au firewall",
        "Changer les mots de passe compromis",
        "Révoquer les tokens et sessions actives",
        "Préserver les preuves (snapshot, logs)",
    ],
    "4_ERADICATION": [
        "Identifier la cause racine",
        "Supprimer les malwares et backdoors",
        "Patcher les vulnérabilités exploitées",
        "Nettoyer les comptes compromis",
        "Scanner pour assurer la propreté",
    ],
    "5_RECOVERY": [
        "Restaurer depuis des backups sains",
        "Monitorer intensément pendant 72h",
        "Valider le retour à la normale",
        "Tester les systèmes restaurés",
        "Communication aux utilisateurs",
    ],
    "6_LESSONS_LEARNED": [
        "Post-mortem dans les 2 semaines",
        "Documenter la timeline complète",
        "Identifier ce qui a bien/mal fonctionné",
        "Mettre à jour les playbooks",
        "Former l'équipe sur les leçons",
    ],
}

COMMANDES_IR_LINUX = {
    "Connexions actives":       "ss -tlnp && netstat -tlnp",
    "Processus suspects":       "ps auxf && ls -la /proc/*/exe 2>/dev/null",
    "Fichiers modifiés récemment": "find / -mtime -1 -type f 2>/dev/null | head -50",
    "Utilisateurs connectés":   "who && w && last | head -20",
    "Historique commandes":     "cat ~/.bash_history && cat /root/.bash_history 2>/dev/null",
    "Tâches planifiées":        "crontab -l && cat /etc/crontab",
    "Services inhabituels":     "systemctl list-units --type=service --state=running",
    "Fichiers SUID récents":    "find / -perm -4000 -newer /bin/bash 2>/dev/null",
    "Dump mémoire":             "avml /tmp/memory.lime  # ou LiME kernel module",
    "Capture réseau":           "tcpdump -i eth0 -w /tmp/capture.pcap",
}


# ─────────────────────────────────────────────────
# DÉMONSTRATION
# ─────────────────────────────────────────────────
if __name__ == "__main__":
    print("=" * 60)
    print("  SÉCURITÉ DÉFENSIVE — Guide Ingénieur Cybersécurité")
    print("=" * 60)

    print("\n[1] TEST IDS:")
    ids = IDS()
    requetes_test = [
        ("192.168.1.100", "GET /page?id=1 UNION SELECT * FROM users--"),
        ("10.0.0.5",      "POST /login avec User-Agent: sqlmap/1.6"),
        ("8.8.8.8",       "GET /index.html HTTP/1.1"),
        ("192.168.1.200", "<script>alert('xss')</script>"),
    ]

    for ip, requete in requetes_test:
        ids.analyser_requete(ip, requete)

    rapport = ids.rapport()
    print(f"\n  Rapport IDS: {rapport['total_alertes']} alertes détectées")

    print("\n[2] TEST WAF:")
    cas_test = [
        ("192.168.1.1", "GET", "/page", {"id": "1 UNION SELECT 1,2,3--"}, {}),
        ("192.168.1.2", "GET", "/index", {"q": "normal search"}, {}),
        ("192.168.1.3", "GET", "/api", {}, {"User-Agent": "sqlmap/1.6.12#stable"}),
    ]

    for ip, methode, chemin, params, headers in cas_test:
        autorise, raison = WAF.filtrer_requete(ip, methode, chemin, params, headers)
        statut = "[OK]" if autorise else "[BLOQUÉ]"
        print(f"  {statut} {ip}: {raison}")

    print("\n[3] SIEM — Corrélation:")
    siem = SIEM()
    siem.ingerer_evenement("auth", "connexion_ssh", {"ip_source": "10.0.0.5", "ip_destination": "10.0.0.10", "user": "admin"})
    siem.ingerer_evenement("auth", "connexion_ssh", {"ip_source": "10.0.0.5", "ip_destination": "10.0.0.11", "user": "admin"})
    siem.ingerer_evenement("auth", "connexion_ssh", {"ip_source": "10.0.0.5", "ip_destination": "10.0.0.12", "user": "admin"})
    siem.ingerer_evenement("auth", "connexion_ssh", {"ip_source": "10.0.0.5", "ip_destination": "10.0.0.13", "user": "admin"})
    siem.ingerer_evenement("file", "modification_fichier", {"fichier": "~/.bashrc", "user": "admin"})
    siem.ingerer_evenement("network", "transfert_fichier", {"taille_mb": 500, "destination": "185.x.x.x"})

    print("\n[4] PLAN INCIDENT RESPONSE:")
    for phase, etapes in PLAN_IR.items():
        print(f"\n  {phase}:")
        for etape in etapes:
            print(f"    □ {etape}")

    print("\n[5] COMMANDES IR LINUX (collecte de preuves):")
    for action, cmd in COMMANDES_IR_LINUX.items():
        print(f"  [{action}]")
        print(f"    $ {cmd}")

    print("\n[OUTILS PROS]")
    print("  Wazuh      — SIEM open source complet")
    print("  Snort/Suricata — IDS/IPS réseau")
    print("  OSSEC      — HIDS (Host IDS)")
    print("  TheHive    — Plateforme IR")
    print("  Velociraptor — Forensique à grande échelle")
    print("  MITRE ATT&CK — Framework tactiques attaquants")
