#!/bin/bash
# PiStarter - Auto-Configurator
# Script d'installation et configuration automatique pour Raspberry Pi
# Usage: curl -fsSL https://raw.githubusercontent.com/PrinMeshia/PiStarter/refs/heads/main/rpi-config.sh | bash
# Ou: wget -qO- https://raw.githubusercontent.com/PrinMeshia/PiStarter/refs/heads/main/rpi-config.sh | bash

VERSION="1.0.0"
SCRIPT_NAME="PiStarter"
LOGFILE="/var/log/rpi-autoconfig.log"
CONFIG_DIR="/etc/rpi-autoconfig"
BACKUP_DIR="/etc/rpi-autoconfig/backups"

# Couleurs pour l'affichage
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
PURPLE='\033[0;35m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color

# Configuration par défaut
DEFAULT_USERNAME="pi"
DEFAULT_TIMEZONE="Europe/Paris"
DEFAULT_LOCALE="fr_FR.UTF-8"
DEFAULT_KEYBOARD="fr"

# Templates de fichiers de configuration
SSH_CONFIG_TEMPLATE='# Configuration SSH générée par PiStarter
Port $SSH_PORT
AddressFamily inet
ListenAddress 0.0.0.0

# Sécurité de base
PermitRootLogin no
StrictModes yes
MaxAuthTries 6
MaxSessions 10
MaxStartups 10:30:60

# Authentification
PubkeyAuthentication yes
AuthorizedKeysFile .ssh/authorized_keys
PasswordAuthentication $([[ $SSH_PASSWORD_AUTH == "y" ]] && echo "yes" || echo "no")
PermitEmptyPasswords no
ChallengeResponseAuthentication no

# Keep-alive pour stabilité
ClientAliveInterval 30
ClientAliveCountMax 6
TCPKeepAlive yes

# Optimisations
Compression delayed
UseDNS no
GSSAPIAuthentication no
UsePAM yes

# Logging
SyslogFacility AUTHPRIV
LogLevel INFO

# SFTP
Subsystem sftp /usr/lib/openssh/sftp-server

# Limitations utilisateur
AllowUsers $DEFAULT_USERNAME
Protocol 2
HostbasedAuthentication no
IgnoreRhosts yes

# Chiffrements optimisés
Ciphers chacha20-poly1305@openssh.com,aes128-ctr,aes192-ctr,aes256-ctr
MACs hmac-sha2-256,hmac-sha2-512
KexAlgorithms curve25519-sha256@libssh.org,diffie-hellman-group16-sha512'

FAIL2BAN_CONFIG_TEMPLATE='[DEFAULT]
bantime = 3600
findtime = 600
maxretry = 3

[ssh]
enabled = true
port = $SSH_PORT
filter = sshd
logpath = /var/log/auth.log'

SYSTEMD_SERVICE_TEMPLATE='[Unit]
Description=SSH Connection Monitor (Safe Mode)
After=network.target ssh.service
Wants=network.target

[Service]
Type=simple
ExecStart=/usr/local/bin/ssh-monitor-safe.sh
Restart=on-failure
RestartSec=60
User=root
StandardOutput=journal
StandardError=journal

[Install]
WantedBy=multi-user.target'

# Fonctions utilitaires pour générer le contenu des fichiers
generate_ssh_config() {
    eval "echo \"$SSH_CONFIG_TEMPLATE\""
}

generate_fail2ban_config() {
    eval "echo \"$FAIL2BAN_CONFIG_TEMPLATE\""
}

generate_systemd_service() {
    eval "echo \"$SYSTEMD_SERVICE_TEMPLATE\""
}

generate_boot_config_header() {
    cat << 'EOF'
# Configuration générée par PiStarter
# Pour plus d'options: http://rptl.io/configtxt

# Interfaces matérielles
dtparam=i2c_arm=on
dtparam=spi=on

# Mode 64-bit et optimisations de base
arm_64bit=1
disable_overscan=1
arm_boost=1

# Gestion automatique des overlays
camera_auto_detect=1
display_auto_detect=1
auto_initramfs=1

# Driver vidéo
dtoverlay=vc4-kms-v3d
max_framebuffers=2
disable_fw_kms_setup=1

# Configuration spécifique selon l'usage
EOF
}

generate_usage_config() {
    local usage_type=$1
    case $usage_type in
        1) # Serveur
            cat << 'EOF'
# Configuration SERVEUR
start_x=0
gpu_mem=16
dtparam=audio=off
hdmi_blanking=1
dtparam=act_led_trigger=none
dtparam=act_led_activelow=off
dtparam=pwr_led_trigger=none
dtparam=pwr_led_activelow=off
EOF
            ;;
        2) # Desktop
            cat << 'EOF'
# Configuration DESKTOP
gpu_mem=128
dtparam=audio=on
EOF
            ;;
        3) # IoT
            cat << 'EOF'
# Configuration IoT/DOMOTIQUE
start_x=0
gpu_mem=16
dtparam=audio=off
hdmi_blanking=1
# Optimisations énergie
dtparam=act_led_trigger=none
dtparam=pwr_led_trigger=none
EOF
            ;;
        4) # Développement
            cat << 'EOF'
# Configuration DEVELOPPEMENT
gpu_mem=64
EOF
            ;;
        5) # Media Center
            cat << 'EOF'
# Configuration MEDIA CENTER
gpu_mem=256
EOF
            ;;
    esac
}

generate_rpi4_optimizations() {
    cat << 'EOF'

# Optimisations RPi 4
arm_freq=1800
over_voltage=6
temp_limit=80
dtparam=sd_overclock=100
EOF
}

generate_status_script() {
    cat << 'EOF'
#!/bin/bash
# Script de statut RPi généré par Auto-Configurator

echo "🍓 Raspberry Pi Status Dashboard"
echo "================================"
echo "Date: $(date)"
echo "Uptime: $(uptime -p)"
echo "Température: $(vcgencmd measure_temp 2>/dev/null || echo "temp=N/A")"
echo "Fréquence CPU: $(vcgencmd measure_clock arm | awk -F"=" "{print $2/1000000}") MHz"
echo "Mémoire: $(free -h | grep Mem | awk "{print $3 \"/\" $2}")"
echo "Charge: $(cat /proc/loadavg | awk "{print $1, $2, $3}")"
echo "Stockage: $(df -h / | tail -1 | awk "{print $3 \"/\" $2 \" (\" $5 \")"}")"
echo
echo "🌐 Réseau:"
ip addr show | grep -E "inet.*wlan0|inet.*eth0" | awk "{print \"  \" $NF \": \" $2}"
echo
echo "🔐 SSH:"
systemctl is-active ssh >/dev/null 2>&1 && echo "  Service: Actif" || echo "  Service: Inactif"
echo "  Port: $SSH_PORT"
echo "  Connexions: $(ss -tn state established | grep :$SSH_PORT | wc -l || true)"
echo
if systemctl is-active ssh-monitor-safe >/dev/null 2>&1; then
    echo "📊 Monitoring: Actif"
    echo "  Logs récents:"
    tail -3 /var/log/ssh-monitor-safe.log 2>/dev/null | sed "s/^/    /"
else
    echo "📊 Monitoring: Inactif"
fi
echo
echo "⚙️ Commandes utiles:"
echo "  rpi-status                    - Ce dashboard"
echo "  sudo systemctl status ssh-monitor-safe  - Statut monitoring"
echo "  sudo tail -f /var/log/ssh-monitor-safe.log  - Logs monitoring"
echo "  sudo journalctl -u ssh-monitor-safe -f     - Logs systemd"
EOF
}

generate_ssh_debug_script() {
    cat << 'EOF'
#!/bin/bash
echo "🔍 Diagnostic SSH Raspberry Pi"
echo "==============================="

if systemctl list-units --type=service 2>/dev/null | grep -q "ssh.service"; then
    SSH_SVC="ssh"
elif systemctl list-units --type=service 2>/dev/null | grep -q "sshd.service"; then
    SSH_SVC="sshd"
else
    SSH_SVC="ssh"
fi

echo "Service SSH détecté: $SSH_SVC"
echo
echo "📊 État du service:"
systemctl status $SSH_SVC --no-pager | head -10
echo
echo "🔌 Ports d'écoute:"
ss -tlnp | grep :$SSH_PORT || true
echo
echo "🖥️ Processus SSH:"
ps aux | grep sshd | grep -v grep || true
echo
echo "📝 Logs SSH récents:"
journalctl -u $SSH_SVC --since "10 minutes ago" --no-pager | tail -10 || true
echo
echo "🔒 Connexions actives:"
who || true
ss -tn state established | grep :$SSH_PORT || true
echo
if [ -f /var/log/ssh-monitor-safe.log ]; then
    echo "📊 Monitoring SSH:"
    tail -5 /var/log/ssh-monitor-safe.log || true
fi
EOF
}

# Vérification terminal interactif
if [[ ! -t 0 ]]; then
    echo -e "${RED}Ce script doit être lancé dans un terminal interactif.${NC}"
    exit 1
fi

print_header() {
    clear
    echo -e "${PURPLE}╔══════════════════════════════════════════════════════════════╗${NC}"
    echo -e "${PURPLE}║                                                              ║${NC}"
    echo -e "${PURPLE}║           🍓 ${SCRIPT_NAME} v${VERSION} 🍓                  ║${NC}"
    echo -e "${PURPLE}║                                                              ║${NC}"
    echo -e "${PURPLE}║        Configuration automatique de Raspberry Pi             ║${NC}"
    echo -e "${PURPLE}║                                                              ║${NC}"
    echo -e "${PURPLE}╚══════════════════════════════════════════════════════════════╝${NC}"
    echo
}

log() {
    local level=$1
    shift
    local message="$*"
    local timestamp=$(date '+%Y-%m-%d %H:%M:%S')
    
    # Couleur selon le niveau
    case $level in
        "INFO")  echo -e "${GREEN}[INFO]${NC} $message" ;;
        "WARN")  echo -e "${YELLOW}[WARN]${NC} $message" ;;
        "ERROR") echo -e "${RED}[ERROR]${NC} $message" ;;
        "DEBUG") echo -e "${CYAN}[DEBUG]${NC} $message" ;;
        *)       echo -e "${BLUE}[LOG]${NC} $message" ;;
    esac
    
    # Enregistrer dans le fichier de log
    echo "$timestamp [$level] $message" >> "$LOGFILE"
}

create_directories() {
    log "INFO" "Création des répertoires de configuration..."
    sudo mkdir -p "$CONFIG_DIR" "$BACKUP_DIR"
    sudo chmod 755 "$CONFIG_DIR" "$BACKUP_DIR"
    # Création et permission pour le fichier log
    sudo touch "$LOGFILE"
    sudo chown "$USER" "$LOGFILE"
}

detect_rpi_model() {
    local model=$(cat /proc/cpuinfo | grep "Model" | cut -d: -f2 | xargs)
    local revision=$(cat /proc/cpuinfo | grep "Revision" | cut -d: -f2 | xargs)
    
    log "INFO" "Modèle détecté: $model"
    log "INFO" "Révision: $revision"
    
    # Déterminer le type de RPi pour les optimisations spécifiques
    if echo "$model" | grep -q "Pi 4"; then
        RPI_MODEL="4"
    elif echo "$model" | grep -q "Pi 3"; then
        RPI_MODEL="3"
    elif echo "$model" | grep -q "Pi Zero"; then
        RPI_MODEL="zero"
    else
        RPI_MODEL="other"
    fi
    
    log "INFO" "Modèle configuré pour: RPi $RPI_MODEL"
}

interactive_setup() {
    print_header
    echo -e "${BLUE}Configuration interactive du Raspberry Pi${NC}"
    echo
    
    # Type d'utilisation (choix multiple)
    echo -e "${CYAN}1. Type d'utilisation:${NC}"
    echo "1) Serveur (headless, SSH, performances)"
    echo "2) Bureau/Desktop (interface graphique)"
    echo "3) IoT/Domotique (économie d'énergie, capteurs)"
    echo "4) Développement (outils dev, serveur web)"
    echo "5) Media Center (Kodi, streaming)"
    echo -e "${YELLOW}Vous pouvez sélectionner plusieurs usages séparés par des virgules (ex: 1,4)${NC}"
    read -p "Choisissez les usages (ex : 1,4) [1]: " USAGE_TYPE
    USAGE_TYPE=${USAGE_TYPE:-1}
    IFS=',' read -ra USAGE_ARRAY <<< "$USAGE_TYPE"
    
    # Configuration réseau
    echo -e "\n${CYAN}2. Configuration réseau:${NC}"
    echo "1) Wi-Fi + Ethernet"
    echo "2) Ethernet uniquement"
    echo "3) Wi-Fi uniquement"
    read -p "Choisissez (1-3) [1]: " NETWORK_TYPE
    NETWORK_TYPE=${NETWORK_TYPE:-1}
    
    if [[ $NETWORK_TYPE == "1" || $NETWORK_TYPE == "3" ]]; then
        read -p "SSID Wi-Fi: " WIFI_SSID
        read -s -p "Mot de passe Wi-Fi: " WIFI_PASSWORD
        echo
        read -p "IP statique (optionnel, format: 192.168.1.100/24): " STATIC_IP
    fi
    
    # Configuration SSH
    echo -e "\n${CYAN}3. Configuration SSH:${NC}"
    read -p "Autoriser l'authentification par mot de passe? (y/n) [y]: " SSH_PASSWORD_AUTH
    SSH_PASSWORD_AUTH=${SSH_PASSWORD_AUTH:-y}
    
    read -p "Port SSH personnalisé (22 par défaut) [22]: " SSH_PORT
    SSH_PORT=${SSH_PORT:-22}
    
    # Monitoring
    echo -e "\n${CYAN}4. Monitoring et sécurité:${NC}"
    read -p "Installer le monitoring SSH/réseau? (y/n) [y]: " INSTALL_MONITORING
    INSTALL_MONITORING=${INSTALL_MONITORING:-y}
    
    read -p "Installer fail2ban (protection SSH)? (y/n) [y]: " INSTALL_FAIL2BAN
    INSTALL_FAIL2BAN=${INSTALL_FAIL2BAN:-y}
    
    # Outils supplémentaires
    echo -e "\n${CYAN}5. Outils et optimisations:${NC}"
    read -p "Installer Docker? (y/n) [n]: " INSTALL_DOCKER
    INSTALL_DOCKER=${INSTALL_DOCKER:-n}
    
    read -p "Optimiser pour SSD (si boot sur SSD)? (y/n) [n]: " SSD_OPTIMIZATIONS
    SSD_OPTIMIZATIONS=${SSD_OPTIMIZATIONS:-n}
    
    # Récapitulatif
    echo -e "\n${PURPLE}═══ RÉCAPITULATIF DE LA CONFIGURATION ═══${NC}"
    echo "Type(s) d'usage sélectionné(s) :"
    for type in "${USAGE_ARRAY[@]}"; do
        case $type in
            1) echo "- Serveur headless" ;;
            2) echo "- Desktop/Bureau" ;;
            3) echo "- IoT/Domotique" ;;
            4) echo "- Développement" ;;
            5) echo "- Media Center" ;;
        esac
    done
    echo "Réseau: $(case $NETWORK_TYPE in
        1) echo "Wi-Fi + Ethernet";;
        2) echo "Ethernet seul";;
        3) echo "Wi-Fi seul";;
    esac)"
    [[ -n $WIFI_SSID ]] && echo "Wi-Fi: $WIFI_SSID"
    echo "SSH Port: $SSH_PORT"
    echo "Monitoring: $([[ $INSTALL_MONITORING == 'y' ]] && echo 'Oui' || echo 'Non')"
    echo "Fail2Ban: $([[ $INSTALL_FAIL2BAN == 'y' ]] && echo 'Oui' || echo 'Non')"
    echo
    
    read -p "Continuer avec cette configuration? (y/n): " CONFIRM
    if [[ $CONFIRM != "y" ]]; then
        log "INFO" "Configuration annulée par l'utilisateur"
        exit 0
    fi
}

backup_original_configs() {
    log "INFO" "Sauvegarde des configurations originales..."
    
    local files_to_backup=(
        "/boot/firmware/config.txt"
        "/etc/ssh/sshd_config"
        "/etc/dhcpcd.conf"
        "/etc/sysctl.conf"
        "/etc/fstab"
    )
    
    for file in "${files_to_backup[@]}"; do
        if [[ -f $file ]]; then
            local backup_name="$(basename $file).$(date +%Y%m%d_%H%M%S).bak"
            sudo cp "$file" "$BACKUP_DIR/$backup_name"
            log "INFO" "Sauvegardé: $file -> $backup_name"
        fi
    done
}

update_system() {
    log "INFO" "Mise à jour du système..."
    sudo apt update && sudo apt upgrade -y
    
    # Paquets essentiels
    local essential_packages=(
        "curl" "wget" "git" "vim" "htop" "tree" "unzip"
        "bc" "netcat-openbsd" "iproute2" "dnsutils"
        "rsync" "screen" "tmux" "iotop" "ncdu"
    )
    
    log "INFO" "Installation des paquets essentiels..."
    sudo apt install -y "${essential_packages[@]}"
}

configure_boot_config() {
    log "INFO" "Configuration du fichier boot/config.txt..."

    local config_file="/boot/firmware/config.txt"
    local temp_config="/tmp/config.txt.new"

    # Générer l'en-tête commun
    generate_boot_config_header > "$temp_config"

    # Configurations spécifiques selon les usages sélectionnés
    for type in "${USAGE_ARRAY[@]}"; do
        generate_usage_config "$type" >> "$temp_config"
        
        # Configurations réseau spécifiques pour le serveur
        if [[ $type == "1" ]]; then
            if [[ $NETWORK_TYPE == "2" ]]; then
                echo "dtoverlay=pi3-disable-wifi" >> "$temp_config"
            fi
            if [[ $NETWORK_TYPE == "3" ]]; then
                echo "dtoverlay=pi3-disable-bt" >> "$temp_config"
            fi
        fi
    done

    # Optimisations selon le modèle de RPi
    if [[ $RPI_MODEL == "4" ]]; then
        generate_rpi4_optimizations >> "$temp_config"
    fi

    # Appliquer la configuration
    sudo cp "$temp_config" "$config_file"
    log "INFO" "Configuration boot appliquée"
}


configure_ssh() {
    log "INFO" "Configuration SSH sécurisée..."
    
    local sshd_config="/etc/ssh/sshd_config"
    local temp_config="/tmp/sshd_config.new"
    
    # Générer la configuration SSH
    generate_ssh_config > "$temp_config"
    
    # Tester la configuration
    if sudo sshd -t -f "$temp_config"; then
        sudo cp "$temp_config" "$sshd_config"
        log "INFO" "Configuration SSH appliquée"
    else
        log "ERROR" "Configuration SSH invalide"
        return 1
    fi
}

configure_network() {
    log "INFO" "Configuration réseau..."
    
    if [[ $NETWORK_TYPE == "1" || $NETWORK_TYPE == "3" ]] && [[ -n $WIFI_SSID ]]; then
        # Configuration Wi-Fi avec NetworkManager
        log "INFO" "Configuration Wi-Fi: $WIFI_SSID"
        
        sudo nmcli dev wifi connect "$WIFI_SSID" password "$WIFI_PASSWORD"
        
        # Configuration IP statique si demandée
        if [[ -n $STATIC_IP ]]; then
            local connection_name=$(nmcli -t -f NAME,DEVICE con show --active | grep wlan0 | cut -d: -f1)
            if [[ -n $connection_name ]]; then
                local ip_addr=$(echo $STATIC_IP | cut -d/ -f1)
                local prefix=$(echo $STATIC_IP | cut -d/ -f2)
                local gateway=$(ip route | grep default | awk '{print $3}' | head -1)
                
                sudo nmcli con modify "$connection_name" \
                    ipv4.method manual \
                    ipv4.addresses "$STATIC_IP" \
                    ipv4.gateway "$gateway" \
                    ipv4.dns "8.8.8.8,1.1.1.1"
                
                log "INFO" "IP statique configurée: $STATIC_IP"
            fi
        fi
    fi
}

install_monitoring() {
    if [[ $INSTALL_MONITORING == 'y' ]]; then
        log "INFO" "Installation du monitoring SSH/réseau..."

        # Création du script de monitoring
        sudo bash -c 'cat > /usr/local/bin/ssh-monitor-safe.sh << '\''MONITOR_SCRIPT'\''
#!/bin/bash
# Script de monitoring SSH adaptatif - intégré par PiStarter
LOGFILE="/var/log/ssh-monitor-safe.log"
CHECK_INTERVAL=300  # 5 minutes
FAILURE_THRESHOLD=3
CONSECUTIVE_FAILURES=0
LAST_CHECK_TIME=0

# Variables de configuration auto-détectées
SSH_SERVICE=""
SSH_PROCESS_PATTERN=""

log() {
    echo "$(date '+%Y-%m-%d %H:%M:%S') - $1" | tee -a $LOGFILE
}

# Auto-détection de la configuration SSH au démarrage
detect_ssh_configuration() {
    log "INFO" "Auto-détection de la configuration SSH..."

    if systemctl list-units --type=service 2>/dev/null | grep -q "ssh.service"; then
        SSH_SERVICE="ssh"
    elif systemctl list-units --type=service 2>/dev/null | grep -q "sshd.service"; then
        SSH_SERVICE="sshd"
    elif systemctl list-units --type=service 2>/dev/null | grep -q "openssh.service"; then
        SSH_SERVICE="openssh"
    else
        SSH_SERVICE="ssh"
    fi

    local patterns=("sshd" "/usr/sbin/sshd" "/usr/bin/sshd")
    for pattern in "${patterns[@]}"; do
        if pgrep -f "$pattern" >/dev/null 2>/dev/null; then
            SSH_PROCESS_PATTERN="$pattern"
            break
        fi
    done

    if [ -z "$SSH_PROCESS_PATTERN" ]; then
        SSH_PROCESS_PATTERN="sshd"
    fi

    log "INFO" "Configuration SSH détectée - Service: $SSH_SERVICE, Processus: $SSH_PROCESS_PATTERN"
}

check_active_sessions() {
    local active_sessions=$(who 2>/dev/null | wc -l)
    local ssh_sessions=$(ss -tn state established 2>/dev/null | grep :$SSH_PORT | wc -l || true)

    if [ "$active_sessions" -gt 0 ] || [ "$ssh_sessions" -gt 0 ]; then
        log "INFO" "$active_sessions session(s) utilisateur(s), $ssh_sessions connexion(s) SSH actives - PAS de redémarrage"
        return 1
    fi
    return 0
}

test_ssh_health() {
    local failures=0
    if ! systemctl is-active --quiet "$SSH_SERVICE" 2>/dev/null; then
        log "WARNING" "Service $SSH_SERVICE inactif selon systemd"
        ((failures++))
    fi

    if ! ss -tnlp 2>/dev/null | grep -q ":$SSH_PORT"; then
        log "WARNING" "SSH n'écoute pas sur le port $SSH_PORT"
        ((failures++))
    fi

    if ! pgrep -f "$SSH_PROCESS_PATTERN" >/dev/null 2>/dev/null; then
        log "WARNING" "Aucun processus SSH trouvé avec le pattern '$SSH_PROCESS_PATTERN'"
        ((failures++))
    fi

    if ! timeout 3 nc -z localhost $SSH_PORT 2>/dev/null; then
        log "WARNING" "Port $SSH_PORT non accessible via nc"
        ((failures++))
    fi

    if [ $failures -le 2 ]; then
        if [ $failures -gt 0 ]; then
            log "INFO" "SSH fonctionnel malgré $failures problème(s) mineur(s)"
        fi
        return 0
    else
        log "WARNING" "SSH health check failed ($failures problèmes détectés)"
        return 1
    fi
}

safe_restart_ssh() {
    log "ALERT" "Tentative de redémarrage SSH après $CONSECUTIVE_FAILURES échecs"

    if ! check_active_sessions; then
        log "ABORT" "Sessions actives détectées, annulation du redémarrage SSH"
        CONSECUTIVE_FAILURES=0
        return 1
    fi

    log "INFO" "Tentative de reload SSH (moins intrusif)"
    if systemctl reload "$SSH_SERVICE" 2>/dev/null; then
        sleep 5
        if test_ssh_health; then
            log "SUCCESS" "SSH reload réussi, service fonctionnel"
            CONSECUTIVE_FAILURES=0
            return 0
        fi
    fi

    log "INFO" "Reload insuffisant, redémarrage complet nécessaire"
    if systemctl restart "$SSH_SERVICE"; then
        sleep 10
        if test_ssh_health; then
            log "SUCCESS" "SSH redémarré avec succès"
            CONSECUTIVE_FAILURES=0
            return 0
        fi
    fi

    log "ERROR" "Échec du redémarrage SSH"
    return 1
}

main_monitoring_loop() {
    log "INFO" "Démarrage du monitoring SSH adaptatif (PID: $$)"
    log "INFO" "Configuration: Service=$SSH_SERVICE, Pattern=$SSH_PROCESS_PATTERN, Port=$SSH_PORT"

    while true; do
        current_time=$(date +%s)

        if test_ssh_health; then
            if [ $CONSECUTIVE_FAILURES -gt 0 ]; then
                log "INFO" "SSH récupéré après $CONSECUTIVE_FAILURES échec(s)"
                CONSECUTIVE_FAILURES=0
            fi

            if [ $((current_time - LAST_CHECK_TIME)) -ge 1800 ]; then
                local temp=$(vcgencmd measure_temp 2>/dev/null || echo "temp=N/A")
                log "INFO" "SSH stable - $temp"
                LAST_CHECK_TIME=$current_time
            fi
        else
            CONSECUTIVE_FAILURES=$((CONSECUTIVE_FAILURES + 1))
            log "WARNING" "Échec SSH #$CONSECUTIVE_FAILURES/$FAILURE_THRESHOLD"

            if [ $CONSECUTIVE_FAILURES -ge $FAILURE_THRESHOLD ]; then
                log "CRITICAL" "Seuil d'échec atteint ($CONSECUTIVE_FAILURES)"

                if check_active_sessions; then
                    if safe_restart_ssh; then
                        log "INFO" "Problème SSH résolu"
                    else
                        log "ERROR" "Impossible de résoudre le problème SSH"
                        sleep $((CHECK_INTERVAL * 3))
                    fi
                else
                    log "INFO" "Problème SSH détecté mais sessions actives, attente..."
                    CONSECUTIVE_FAILURES=$((CONSECUTIVE_FAILURES - 1))
                fi
            fi
        fi

        sleep $CHECK_INTERVAL
    done
}

cleanup() {
    log "INFO" "Arrêt du monitoring SSH adaptatif"
    exit 0
}

trap cleanup SIGTERM SIGINT

for cmd in nc ss systemctl; do
    if ! command -v $cmd >/dev/null; then
        log "ERROR" "Commande '$cmd' manquante"
        exit 1
    fi
done

detect_ssh_configuration
main_monitoring_loop
MONITOR_SCRIPT'

        # Injecter la valeur du port SSH au début du script généré
        sudo sed -i "1i SSH_PORT=${SSH_PORT:-22}" /usr/local/bin/ssh-monitor-safe.sh
        sudo chmod +x /usr/local/bin/ssh-monitor-safe.sh

        # Service systemd
        cat > /etc/systemd/system/ssh-monitor-safe.service << 'SERVICE_FILE'
[Unit]
Description=SSH Connection Monitor (Safe Mode)
After=network.target ssh.service
Wants=network.target

[Service]
Type=simple
ExecStart=/usr/local/bin/ssh-monitor-safe.sh
Restart=on-failure
RestartSec=60
User=root
StandardOutput=journal
StandardError=journal

[Install]
WantedBy=multi-user.target
SERVICE_FILE

        sudo systemctl daemon-reload
        sudo systemctl enable ssh-monitor-safe.service
        log "INFO" "Monitoring SSH adaptatif installé et activé"
    fi
}


        
        sudo chmod +x /usr/local/bin/ssh-monitor-safe.sh
        
        # Service systemd
        generate_systemd_service > /etc/systemd/system/ssh-monitor-safe.service
        
        sudo systemctl daemon-reload
        sudo systemctl enable ssh-monitor-safe.service
        log "INFO" "Monitoring SSH adaptatif installé et activé"
    fi
}

# Variables globales pour le monitoring SSH
SSH_SERVICE=""
SSH_PROCESS_PATTERN=""
CONSECUTIVE_FAILURES=0
FAILURE_THRESHOLD=3
CHECK_INTERVAL=300
LAST_CHECK_TIME=0

# Auto-détection de la configuration SSH
detect_ssh_configuration() {
    log "INFO" "Auto-détection de la configuration SSH..."
    
    if systemctl list-units --type=service 2>/dev/null | grep -q "ssh.service"; then
        SSH_SERVICE="ssh"
    elif systemctl list-units --type=service 2>/dev/null | grep -q "sshd.service"; then
        SSH_SERVICE="sshd"
    elif systemctl list-units --type=service 2>/dev/null | grep -q "openssh.service"; then
        SSH_SERVICE="openssh"
    else
        SSH_SERVICE="ssh"
    fi
    
    local patterns=("sshd" "/usr/sbin/sshd" "/usr/bin/sshd")
    for pattern in "${patterns[@]}"; do
        if pgrep -f "$pattern" >/dev/null 2>/dev/null; then
            SSH_PROCESS_PATTERN="$pattern"
            break
        fi
    done
    
    if [ -z "$SSH_PROCESS_PATTERN" ]; then
        SSH_PROCESS_PATTERN="sshd"
    fi
    
    log "INFO" "Configuration SSH détectée - Service: $SSH_SERVICE, Processus: $SSH_PROCESS_PATTERN"
}

# Vérifier s'il y a des sessions SSH actives
check_active_sessions() {
    local active_sessions=$(who 2>/dev/null | wc -l)
    local ssh_sessions=$(ss -tn state established 2>/dev/null | grep :$SSH_PORT | wc -l)
    
    if [ $active_sessions -gt 0 ] || [ $ssh_sessions -gt 0 ]; then
        log "INFO" "$active_sessions session(s) utilisateur(s), $ssh_sessions connexion(s) SSH actives - PAS de redémarrage"
        return 1  # Ne pas redémarrer s'il y a des sessions
    fi
    return 0  # OK pour redémarrer si nécessaire
}

# Test de santé SSH adaptatif
test_ssh_health() {
    local failures=0
    
    # Test 1: Le service SSH est-il actif ?
    if ! systemctl is-active --quiet "$SSH_SERVICE" 2>/dev/null; then
        log "WARNING" "Service $SSH_SERVICE inactif selon systemd"
        ((failures++))
    fi
    
    # Test 2: SSH écoute-t-il sur le port ?
    if ! ss -tnlp 2>/dev/null | grep -q ":$SSH_PORT"; then
        log "WARNING" "SSH n'écoute pas sur le port $SSH_PORT"
        ((failures++))
    fi
    
    # Test 3: Y a-t-il un processus SSH ?
    if ! pgrep -f "$SSH_PROCESS_PATTERN" >/dev/null 2>/dev/null; then
        log "WARNING" "Aucun processus SSH trouvé avec le pattern '$SSH_PROCESS_PATTERN'"
        ((failures++))
    fi
    
    # Test 4: Test de connectivité basique
    if ! timeout 3 nc -z localhost $SSH_PORT 2>/dev/null; then
        log "WARNING" "Port $SSH_PORT non accessible via nc"
        ((failures++))
    fi
    
    # Évaluation finale : tolérant si pas plus de 2 échecs
    if [ $failures -le 2 ]; then
        if [ $failures -gt 0 ]; then
            log "INFO" "SSH fonctionnel malgré $failures problème(s) mineur(s)"
        fi
        return 0
    else
        log "WARNING" "SSH health check failed ($failures problèmes détectés)"
        return 1
    fi
}

# Redémarrage SSH ultra-prudent
safe_restart_ssh() {
    log "ALERT" "Tentative de redémarrage SSH après $CONSECUTIVE_FAILURES échecs"
    
    # Double vérification des sessions avant redémarrage
    if ! check_active_sessions; then
        log "ABORT" "Sessions actives détectées, annulation du redémarrage SSH"
        CONSECUTIVE_FAILURES=0
        return 1
    fi
    
    # Redémarrage en douceur (reload d'abord)
    log "INFO" "Tentative de reload SSH (moins intrusif)"
    if systemctl reload "$SSH_SERVICE" 2>/dev/null; then
        sleep 5
        if test_ssh_health; then
            log "SUCCESS" "SSH reload réussi, service fonctionnel"
            CONSECUTIVE_FAILURES=0
            return 0
        fi
    fi
    
    # Si reload échoue, restart complet
    log "INFO" "Reload insuffisant, redémarrage complet nécessaire"
    if systemctl restart "$SSH_SERVICE"; then
        sleep 10
        if test_ssh_health; then
            log "SUCCESS" "SSH redémarré avec succès"
            CONSECUTIVE_FAILURES=0
            return 0
        fi
    fi
    
    log "ERROR" "Échec du redémarrage SSH"
    return 1
}

# Boucle de monitoring principale
main_monitoring_loop() {
    log "INFO" "Démarrage du monitoring SSH adaptatif (PID: $$)"
    log "INFO" "Configuration: Service=$SSH_SERVICE, Pattern=$SSH_PROCESS_PATTERN, Port=$SSH_PORT"
    
    while true; do
        current_time=$(date +%s)
        
        if test_ssh_health; then
            if [ $CONSECUTIVE_FAILURES -gt 0 ]; then
                log "INFO" "SSH récupéré après $CONSECUTIVE_FAILURES échec(s)"
                CONSECUTIVE_FAILURES=0
            fi
            
            # Log périodique (toutes les 30 minutes)
            if [ $((current_time - LAST_CHECK_TIME)) -ge 1800 ]; then
                local temp=$(vcgencmd measure_temp 2>/dev/null || echo "temp=N/A")
                log "INFO" "SSH stable - $temp"
                LAST_CHECK_TIME=$current_time
            fi
        else
            CONSECUTIVE_FAILURES=$((CONSECUTIVE_FAILURES + 1))
            log "WARNING" "Échec SSH #$CONSECUTIVE_FAILURES/$FAILURE_THRESHOLD"
            
            if [ $CONSECUTIVE_FAILURES -ge $FAILURE_THRESHOLD ]; then
                log "CRITICAL" "Seuil d'échec atteint ($CONSECUTIVE_FAILURES)"
                
                if check_active_sessions; then
                    if safe_restart_ssh; then
                        log "INFO" "Problème SSH résolu"
                    else
                        log "ERROR" "Impossible de résoudre le problème SSH"
                        sleep $((CHECK_INTERVAL * 3))
                    fi
                else
                    log "INFO" "Problème SSH détecté mais sessions actives, attente..."
                    CONSECUTIVE_FAILURES=$((CONSECUTIVE_FAILURES - 1))
                fi
            fi
        fi
        
        sleep $CHECK_INTERVAL
    done
}

# Gestion des signaux
cleanup() {
    log "INFO" "Arrêt du monitoring SSH adaptatif"
    exit 0
}

trap cleanup SIGTERM SIGINT

# Vérification des dépendances
for cmd in nc ss systemctl; do
    if ! command -v $cmd >/dev/null; then
        log "ERROR" "Commande '$cmd' manquante"
        exit 1
    fi
done

# Auto-détection et démarrage
detect_ssh_configuration
main_monitoring_loop

install_security() {
    if [[ $INSTALL_FAIL2BAN == 'y' ]]; then
        log "INFO" "Installation de fail2ban..."
        sudo apt install -y fail2ban
        
        # Configuration fail2ban pour SSH
        generate_fail2ban_config > /etc/fail2ban/jail.local
        
        sudo systemctl enable fail2ban
        sudo systemctl start fail2ban
        log "INFO" "Fail2ban configuré"
    fi
}

install_optional_tools() {
    if [[ $INSTALL_DOCKER == 'y' ]]; then
        log "INFO" "Installation de Docker..."
        curl -fsSL https://get.docker.com -o get-docker.sh
        sudo sh get-docker.sh
        sudo usermod -aG docker "$DEFAULT_USERNAME"
        rm get-docker.sh
        log "INFO" "Docker installé"
    fi
}

apply_system_optimizations() {
    log "INFO" "Application des optimisations système..."
    
    # Optimisations sysctl
    cat >> /etc/sysctl.conf << 'EOF'

# Optimisations PiStarter
vm.swappiness=10
vm.dirty_ratio=15
vm.dirty_background_ratio=5
net.core.rmem_default=262144
net.core.rmem_max=16777216
net.core.wmem_default=262144
net.core.wmem_max=16777216
net.ipv4.tcp_keepalive_time=300
net.ipv4.tcp_keepalive_intvl=30
net.ipv4.tcp_keepalive_probes=6
EOF
    
    # Optimisations SSD si demandées
    if [[ $SSD_OPTIMIZATIONS == 'y' ]]; then
        log "INFO" "Application des optimisations SSD..."
        
        # Désactiver le swap si on boot sur SSD
        sudo dphys-swapfile swapoff
        sudo dphys-swapfile uninstall
        sudo systemctl disable dphys-swapfile
        
        # Optimisations fstab pour SSD
        if ! grep -q "noatime" /etc/fstab; then
            sudo sed -i 's/defaults/defaults,noatime,nodiratime/' /etc/fstab
        fi
    fi
}

create_status_script() {
    log "INFO" "Création du script de statut système..."

    # Créer le script de statut
    generate_status_script > /usr/local/bin/rpi-status
    sudo chmod +x /usr/local/bin/rpi-status

    # Préfixer le script rpi-status par la valeur du port SSH et du username utilisés
    sudo sed -i "1i SSH_PORT=${SSH_PORT:-22}" /usr/local/bin/rpi-status
    sudo sed -i "1i DEFAULT_USERNAME=${DEFAULT_USERNAME}" /usr/local/bin/rpi-status

    # Créer le script de diagnostic SSH
    generate_ssh_debug_script > /usr/local/bin/rpi-ssh-debug
    sudo chmod +x /usr/local/bin/rpi-ssh-debug
    sudo sed -i "1i SSH_PORT=${SSH_PORT:-22}" /usr/local/bin/rpi-ssh-debug

    # Alias pour faciliter l'usage
    echo "alias status='rpi-status'" >> "/home/$DEFAULT_USERNAME/.bashrc"
    echo "alias ssh-logs='sudo tail -f /var/log/ssh-monitor-safe.log'" >> "/home/$DEFAULT_USERNAME/.bashrc"
    echo "alias ssh-status='sudo systemctl status ssh-monitor-safe'" >> "/home/$DEFAULT_USERNAME/.bashrc"
    echo "alias ssh-debug='sudo rpi-ssh-debug'" >> "/home/$DEFAULT_USERNAME/.bashrc"
}


finalize_installation() {
    log "INFO" "Finalisation de l'installation..."
    
    # Redémarrage des services
    sudo systemctl restart ssh
    
    if [[ $INSTALL_MONITORING == 'y' ]]; then
        # Attendre un peu que SSH soit bien redémarré
        sleep 5
        sudo systemctl start ssh-monitor-safe.service
        
        # Vérifier que le monitoring démarre correctement
        sleep 10
        if systemctl is-active --quiet ssh-monitor-safe.service; then
            log "INFO" "Service de monitoring SSH démarré avec succès"
        else
            log "WARN" "Problème avec le démarrage du monitoring SSH"
        fi
    fi
    
    # Application des optimisations sysctl
    sudo sysctl -p
    
    # Nettoyage
    sudo apt autoremove -y
    sudo apt autoclean
    
    # Rapport final
    print_header
    echo -e "${GREEN}✅ Installation terminée avec succès !${NC}"
    echo
    echo -e "${BLUE}📋 Résumé de la configuration:${NC}"
    echo "• Type d'usage: $(case $USAGE_TYPE in 1) 'Serveur' ;; 2) 'Desktop' ;; 3) 'IoT' ;; 4) 'Développement' ;; 5) 'Media Center' ;; esac)"
    echo "• SSH Port: $SSH_PORT"
    echo "• Monitoring SSH: $([[ $INSTALL_MONITORING == 'y' ]] && echo 'Activé (adaptatif)' || echo 'Désactivé')"
    echo "• Fail2ban: $([[ $INSTALL_FAIL2BAN == 'y' ]] && echo 'Installé' || echo 'Non installé')"
    echo "• Docker: $([[ $INSTALL_DOCKER == 'y' ]] && echo 'Installé' || echo 'Non installé')"
    echo "• Modèle RPi: $RPI_MODEL"
    echo
    echo -e "${YELLOW}📝 Commandes utiles:${NC}"
    echo "• rpi-status               - Dashboard système complet"
    echo "• ssh-status               - Statut du monitoring SSH"
    echo "• ssh-logs                 - Logs du monitoring en temps réel"
    echo "• sudo systemctl status ssh-monitor-safe  - Détails du service"
    echo
    echo -e "${PURPLE}🔧 Fichiers de configuration:${NC}"
    echo "• SSH: /etc/ssh/sshd_config"
    echo "• Boot: /boot/firmware/config.txt"
    echo "• Monitoring: /var/log/ssh-monitor-safe.log"
    echo "• Sauvegardes: $BACKUP_DIR"
    echo
    
    if [[ $INSTALL_MONITORING == 'y' ]]; then
        echo -e "${CYAN}📊 Test du monitoring SSH:${NC}"
        sleep 2
        if tail -3 /var/log/ssh-monitor-safe.log 2>/dev/null | grep -q "SSH stable\|Configuration SSH détectée"; then
            echo "✅ Monitoring SSH fonctionnel"
        else
            echo "⚠️ Monitoring SSH en cours de démarrage..."
        fi
        echo
    fi
    
    echo -e "${RED}🔄 Redémarrage recommandé pour appliquer toutes les optimisations${NC}"
    echo -e "${GREEN}🎉 Votre Raspberry Pi est maintenant optimisé et sécurisé !${NC}"
    echo
    
    read -p "Redémarrer maintenant? (y/n) [y]: " REBOOT_NOW
    if [[ ${REBOOT_NOW:-y} == "y" ]]; then
        log "INFO" "Redémarrage du système..."
        echo -e "${BLUE}Le système va redémarrer. Reconnectez-vous ensuite avec:${NC}"
        echo "ssh $DEFAULT_USERNAME@$(hostname -I | awk '{print $1}') -p $SSH_PORT"
        sleep 3
        sudo reboot
    fi
}

# Point d'entrée principal
main() {
    # Vérifications préliminaires
    if [[ $EUID -eq 0 ]]; then
        echo -e "${RED}Ne pas exécuter ce script en tant que root${NC}"
        exit 1
    fi
    
    if ! grep -q "Raspberry Pi" /proc/cpuinfo; then
        echo -e "${RED}Ce script est conçu pour Raspberry Pi uniquement${NC}"
        exit 1
    fi
    
    # Initialisation
    create_directories
    detect_rpi_model
    
    # Configuration interactive
    interactive_setup
    
    # Exécution des étapes
    log "INFO" "Début de la configuration automatique"
    backup_original_configs
    update_system
    configure_boot_config
    configure_ssh
    configure_network
    install_monitoring
    install_security  
    install_optional_tools
    apply_system_optimizations
    create_status_script
    finalize_installation
}

# Gestion des signaux
trap 'log "ERROR" "Installation interrompue"; exit 1' SIGINT SIGTERM

# Démarrage du script
main "$@"
