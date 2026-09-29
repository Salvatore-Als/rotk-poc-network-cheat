# Rapport de recherche - Lecture réseau passive H1Z1 / ROTK

**Date :** 2026-09-23
**Auteur :** Salvatore
**Statut :** Killfeed fonctionnel (PoC validé)

## 1. La faille

H1Z1 (King of the Kill / ROTK) utilise le protocole **SOE UDP** pour toutes les communications client-serveur. Ce protocole est partiellement documenté via le projet open-source [h1emu](https://github.com/H1emu/h1z1-server).

Le problème de fond : le serveur envoie des informations de jeu au client sans vérifier si le destinataire est censé les voir. N'importe qui qui capture son propre trafic réseau peut lire ces données après déchiffrement.

**Point important sur la méthode : tout se fait 100% côté réseau.**

- Aucune injection de code dans le processus du jeu
- Aucune lecture de la mémoire du client
- Aucune modification du client (pas de patch binaire, pas de DLL injection, pas de hook)
- Aucun contact avec le processus du jeu, ni en lecture ni en écriture
- Le jeu tourne normalement, l'outil observe uniquement le trafic UDP entrant sur la carte réseau

Le PoC se comporte comme un simple sniffer réseau. Wireshark ferait la même chose techniquement, il faudrait juste ajouter le déchiffrement RC4 par-dessus. Ca signifie que **les anti-cheat qui surveillent le processus du jeu (EAC, BattlEye, etc.) ne peuvent pas détecter ce type d'outil** : il n'y a rien à détecter côté processus.

Ce n'est pas un exploit classique (pas d'injection, pas de corruption mémoire). C'est un problème de conception : le serveur fait confiance au client pour ne pas utiliser ce qu'il ne devrait pas voir.

## 2. Déchiffrement du trafic

### 2.1 Double vulnérabilité sur la clé RC4

Le trafic SOE est chiffré en RC4 avec une clé de session de 16 octets. Cette clé est compromise à deux niveaux indépendants.

**Niveau 1 : la clé statique est dans le binaire.**
La clé par défaut `F70IaxuU8C/w7FPXY1ibXw==` est stockée en clair dans le binaire du serveur, et dans le code source h1emu public. Un `strings` sur l'exécutable suffit à la retrouver, sans débogueur, sans exécution. C'est cette clé qui chiffre le canal `LoginUdp`, le premier canal ouvert à chaque connexion.

**Niveau 2 : la clé de session voyage en clair dans le trafic.**
Une fois `LoginUdp` déchiffré avec la clé statique, le paquet `CharacterLoginReply` contient la clé RC4 de session (16 octets) en clair. Structure :
```
[addrLen u32][addr ASCII "ip:port"][ticketLen u32][ticket...][keyLen u32 = 16][key 16B]
```

Les deux se combinent : la clé statique (dans le binaire) déchiffre `LoginUdp`, `LoginUdp` expose la clé de session, la clé de session déchiffre tous les canaux suivants (gateway, zones BR).

### 2.2 Protocole SOE : réassemblage des fragments

SOE UDP n'est pas un protocole trivial. Les messages applicatifs sont fragmentés sur plusieurs datagrammes UDP, chiffrés par flot RC4 avec état persistant (pas de reset entre paquets). Ca implique que :

- Un paquet perdu désynchronise définitivement le keystream RC4 pour ce canal
- Le réassemblage doit respecter l'ordre des numéros de séquence (u16 big-endian, offset 2 ou 3 selon le flag compression)
- Un même datagramme peut contenir plusieurs messages applicatifs multiplexés, marqués par le header `0x00 0x19` suivi de sous-longueurs variables

Opcodes SOE traités :

| Opcode | Nom | Direction |
|--------|-----|-----------|
| `0x0001` | SessionRequest | client -> serveur |
| `0x0002` | SessionReply | serveur -> client |
| `0x0009` | Data | serveur -> client |
| `0x000D` | DataFragment | serveur -> client |

### 2.3 Séquence d'exploitation complète

1. Capture passive (filtre `udp`, mode promiscuous)
2. Détecter `SessionRequest` (opcode `0x0001`) : le nom du protocole est en ASCII à offset 14, terminé par `0x00`. Si c'est `LoginUdp_16`, c'est le canal de login.
3. Alimenter le stream SOE LoginUdp avec la clé statique hardcodée. Chaque `Data` / `DataFragment` reçu est déchiffré RC4, réassemblé dans l'ordre de séquence.
4. Dans les messages applicatifs déchiffrés, scanner le pattern `[addrLen][addr "ip:port"][ticketLen][ticket][keyLen=16][key]` pour extraire la clé de session zone.
5. `SessionReply` (opcode `0x0002`) expose deux paramètres importants : `crcLength` (octet 10) et `compression` (octet 11), qui ajustent l'offset de lecture des séquences dans les Data suivants.
6. Ouvrir les canaux zone avec leur clé respective. Le même mécanisme de handoff se répète à chaque transition lobby -> BR -> zone.

## 3. Killfeed (VALIDE)

Le killfeed est autonome. Aucun état préalable requis : pas besoin d'observer les spawns, pas besoin de registre de joueurs. Le paquet de kill contient déjà toutes les infos nécessaires (noms, IDs, type de kill) dans son propre payload.

### 3.1 Kill broadcast direct (zone opcode `0x02`)

Quand un joueur meurt en BR, le serveur émet un broadcast sur le canal zone. Format : tunnel V1 (`payload[0] & 0x1F == 0x05`), opcode zone `payload[5] == 0x02`, taille ~240-260 bytes.

Structure du paquet (déchiffré) :
```
[0]      0x05                  tunnel gw byte
[1..4]   length u32
[5]      0x02                  zone opcode kill
[6..8]   header tunnel
[9..12]  victim_char_id u64 LE (bytes 9..16)
[17..20] victim_steam u64
[21..24] zeros
[25..28] zeros
[29..32] victim_name_len u32
[33..N]  victim_name ASCII
[N+1..N+4]  zeros (4 bytes padding)
[N+5..N+8]  u32 = 17
[N+9..N+25] steam_id ASCII (17 bytes)
[N+26..N+38] zeros
[N+39..N+42] rank u32 (classement de la victime dans la partie)
[N+43..N+50] unk (2x u32)
[N+51..N+54] kill_type u32   4=normal, 5=headshot
--- attacker block (offset 91 + victim_name_len) ---
[+0..+7]   attacker_char_id u64 LE
[+8..+11]  unk u32
[+12..+15] unk u32
[+16..+19] unk u32
[+20..+23] attacker_name_len u32
[+24..]    attacker_name ASCII
```

Parsing : validation ASCII sur les deux blocs de nom, lecture du `kill_type`, émission d'un event `killEvent` avec `{ killer, victim, headshot }` sur le hub temps réel.

Extraction : nom du tueur, nom de la victime, type de kill (normal ou headshot), rang de la victime. En temps réel, sans toucher au client, sans lecture mémoire.

**Ce PoC prouve que la lecture réseau passive suffit pour extraire des informations de jeu en temps réel, sans modifier le client, sans injection de code, sans accès mémoire processus.**

## 4. Positions

J'ai commencé à travailler sur l'extraction des positions des joueurs et j'ai bien avancé sur le sujet.

Comme ce travail demande beaucoup de temps de recherche et de tests en session live, je ne vais pas plus loin dans ce rapport. Le killfeed suffit à démontrer la faille de fond.

## 5. Comment corriger côté réseau

### 5.1 Mitigation : clé non transmissible

Remplacer l'échange de clé actuel par du ECDH ou TLS enlève la possibilité de déchiffrer le trafic d'un tiers.

Limite : si l'attaquant sniffe son propre trafic (sa propre machine), TLS ne change rien. La clé reste accessible en mémoire processus. Cette mitigation protège uniquement contre la lecture du trafic d'autres joueurs sur un réseau partagé.

### 5.2 Mitigation court terme : rotation du format

Varier les opcodes, la structure et l'encodage des paquets à chaque patch, idéalement par session. Ca force un retravail de reverse engineering à chaque mise à jour. Coût faible côté développeur, coût élevé pour maintenir un outil externe.

### 5.3 Anti-cheat au niveau kernel avec surveillance réseau

Les anti-cheat modernes comme EAC ou BattlEye tournent déjà en kernel mode et ont techniquement la capacité de voir les drivers chargés sur la machine. Mais historiquement leur focus est côté processus du jeu : détection de DLL injection, hooks mémoire, signatures de cheats connus, intégrité du code. La surveillance active du trafic réseau et des sniffers passifs n'est pas leur point fort.

Pour détecter ce type d'outil, l'anti-cheat kernel devrait ajouter deux capacités explicites :

- Détection des drivers de capture réseau actifs pendant la partie (Npcap, WinPcap, tap drivers, raw sockets non légitimes)
- Surveillance des processus qui lisent le trafic UDP à destination du jeu, en particulier ceux qui ouvrent un socket promiscuous ou un handle de capture sur l'interface où le jeu communique

Concrètement le driver kernel du jeu doit pouvoir dire : "un process autre que le jeu lit les paquets UDP qui arrivent sur le port de session H1Z1". C'est le seul angle d'attaque logiciel viable côté client contre un outil qui n'injecte rien.

Ca ne résout pas la faille (le trafic reste déchiffrable), mais ça bloque son exploitation en production tant que le joueur n'a pas trouvé un moyen de sniffer hors machine (VM, routeur, port mirror sur le switch).
