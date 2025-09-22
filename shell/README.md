# PiStarter

![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)
![Version](https://img.shields.io/badge/version-1.0.0-blue)
![Issues](https://img.shields.io/github/issues/PrinMeshia/PiStarter)
![Last Commit](https://img.shields.io/github/last-commit/PrinMeshia/PiStarter)
![Bash](https://img.shields.io/badge/script-bash-1f425f.svg)
![Raspberry Pi](https://img.shields.io/badge/Raspberry%20Pi-supported-green?logo=raspberry-pi)

> Script d'installation et configuration automatique pour Raspberry Pi

## ⚡ Présentation

**RPi Auto-Configurator** est un script Bash interactif qui simplifie et sécurise la configuration initiale de votre Raspberry Pi. Il automatise :
- La mise à jour du système
- La configuration réseau (Wi-Fi/Ethernet, IP statique)
- La sécurisation et optimisation de SSH
- L'installation de monitoring et de sécurité (Fail2Ban, monitoring adaptatif SSH)
- L'installation d'outils optionnels (Docker, etc.)
- L'application d'optimisations système et matériel (SSD, sysctl)
- La création de scripts de diagnostic et dashboard système

## 🚀 Installation rapide

Vous pouvez lancer le script directement depuis votre Pi (non root) :

```bash
curl -fsSL https://raw.githubusercontent.com/PrinMeshia/PiStarter/refs/heads/main/rpi-config.sh | bash
```
ou
```bash
wget -qO- https://raw.githubusercontent.com/PrinMeshia/PiStarter/refs/heads/main/rpi-config.sh | bash
```

> **Ne pas exécuter en tant que root** – le script vérifie et refusera.

## 📝 Fonctionnalités principales

- **Configuration interactive** : choix du type d’usage, réseau, sécurité, outils, optimisations
- **Détection automatique du modèle Raspberry Pi**
- **Sauvegarde des fichiers de configuration avant modification**
- **Mise à jour et installation des paquets essentiels**
- **Personnalisation avancée de SSH (port, sécurité, monitoring)**
- **Monitoring SSH adaptatif avec service systemd**
- **Installation et configuration de Fail2Ban**
- **Installation optionnelle de Docker**
- **Optimisations pour SSD et performances réseau**
- **Dashboard système (`rpi-status`) & diagnostics SSH (`rpi-ssh-debug`)**
- **Alias pratiques ajoutés à `.bashrc`**

## 📦 Fichiers générés

- `/var/log/rpi-autoconfig.log` — Log principal du script
- `/etc/rpi-autoconfig/backups/` — Sauvegardes des fichiers originaux
- `/usr/local/bin/rpi-status` — Dashboard système
- `/usr/local/bin/rpi-ssh-debug` — Diagnostic SSH
- `/usr/local/bin/ssh-monitor-safe.sh` — Script de monitoring SSH
- `/etc/systemd/system/ssh-monitor-safe.service` — Service systemd
- `/etc/ssh/sshd_config` — SSH sécurisé et personnalisé
- `/boot/firmware/config.txt` — Optimisation boot Raspberry Pi

## 🛡️ Sécurité et monitoring

- Monitoring SSH adaptatif (recharge ou redémarrage ultra-prudent du service en cas de problème sans couper les connexions actives)
- Fail2Ban configuré sur le port SSH personnalisé
- SSH renforcé : désactivation du root, gestion stricte des tentatives

## 💡 Utilisation des scripts outils

Après installation, redémarrez votre Raspberry Pi pour appliquer toutes les optimisations.

Utilisez les commandes suivantes :

```bash
rpi-status       # Dashboard système complet
ssh-debug        # Diagnostic SSH détaillé
ssh-status       # Statut du monitoring SSH
ssh-logs         # Logs du monitoring SSH en temps réel
```

## 🖥️ Compatibilité

- **Modèles supportés** : Raspberry Pi 3, 4, Zero, autres
- **OS** : Raspberry Pi OS (Debian-based)
- **Prérequis** : Bash, accès sudo, connexion internet

## ⚠️ Recommandations & limitations

- Ce script est conçu pour un usage sur Raspberry Pi uniquement. Il refusera de s’exécuter sur d’autres matériels.
- Vérifiez la sauvegarde de vos données avant exécution.
- Certaines optimisations (SSD) désactivent le swap et modifient `/etc/fstab`.


### 🇫🇷 Script et documentation en français.  
Pour toute suggestion ou bug, ouvrez une issue ou un pull request !
