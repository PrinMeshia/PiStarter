#!/bin/bash
# PiStarter

# Script d'installation et configuration automatique pour Raspberry Pi
# Usage: curl -fsSL hhttps://raw.githubusercontent.com/PrinMeshia/PiStarter/refs/heads/main/rpi-config.sh | bash
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

print_header() {
    clear
    echo -e "${PURPLE}╔══════════════════════════════════════════════════════════════╗${NC}"
    echo -e "${PURPLE}║                                                              ║${NC}"
    echo -e "${PURPLE}║           🍓 ${SCRIPT_NAME} v${VERSION} 🍓                   ║${NC}"
    echo -e "${PURPLE}║                                                              ║${NC}"
    echo -e "${PURPLE}║        Configuration automatique de Raspberry Pi            ║${NC}"
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

# Fonction de validation des entrées utilisateur
validate_input() {
    local input=$1
    local type=$2
    
    case $type in
        "port")
            if ! [[ "$input" =~ ^[0-9]+$ ]] || [ "$input" -lt 1 ] || [ "$input" -gt 65535 ]; then
                log "ERROR" "Port invalide: $input (doit être entre 1 et 65535)"
                return 1
            fi
            ;;
        "ip")
            if ! [[ "$input" =~ ^[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}/[0-9]{1,2}$ ]]; then
                log "ERROR" "Format IP invalide: $input (format attendu: 192.168.1.100/24)"
                return 1
            fi
            ;;
        "choice")
            if ! [[ "$input" =~ ^[1-5]$ ]]; then
                log "ERROR" "Choix invalide: $input (doit être entre 1 et 5)"
                return 1
            fi
            ;;
    esac
    return 0
}

# Fonction d'exécution sécurisée
safe_execute() {
    local cmd="$*"
    log "DEBUG" "Exécution: $cmd"
    if ! eval "$cmd"; then
        log "ERROR" "Échec de la commande: $cmd"
        return 1
    fi
    return 0
}

create_directories() {
    log "INFO" "Création des répertoires de configuration..."
    sudo mkdir -p "$CONFIG_DIR" "$BACKUP_DIR"
    sudo chmod 755 "$CONFIG_DIR" "$BACKUP_DIR"
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

# Fonction de détection de l'état réseau
detect_network_status() {
    log "INFO" "Détection de l'état réseau actuel..."
    
    # Variables globales pour l'état réseau
    NETWORK_STATUS="unknown"
    ETHERNET_CONNECTED=false
    WIFI_CONNECTED=false
    INTERNET_ACCESS=false
    CURRENT_IP=""
    CURRENT_SSID=""
    
    # Détecter Ethernet
    if ip link show eth0 2>/dev/null | grep -q "state UP"; then
        ETHERNET_CONNECTED=true
        CURRENT_IP=$(ip addr show eth0 2>/dev/null | grep "inet " | awk '{print $2}' | cut -d/ -f1 | head -1)
        log "INFO" "Ethernet connecté - IP: $CURRENT_IP"
    fi
    
    # Détecter Wi-Fi
    if command -v iwconfig >/dev/null 2>&1; then
        if iwconfig wlan0 2>/dev/null | grep -q "ESSID:"; then
            WIFI_CONNECTED=true
            CURRENT_SSID=$(iwconfig wlan0 2>/dev/null | grep "ESSID:" | cut -d'"' -f2)
            if [[ -z "$CURRENT_IP" ]]; then
                CURRENT_IP=$(ip addr show wlan0 2>/dev/null | grep "inet " | awk '{print $2}' | cut -d/ -f1 | head -1)
            fi
            log "INFO" "Wi-Fi connecté - SSID: $CURRENT_SSID, IP: $CURRENT_IP"
        fi
    fi
    
    # Détecter l'accès Internet
    if ping -c 1 -W 3 8.8.8.8 >/dev/null 2>&1; then
        INTERNET_ACCESS=true
        log "INFO" "Accès Internet détecté"
    else
        log "WARN" "Pas d'accès Internet détecté"
    fi
    
    # Déterminer le statut global
    if $ETHERNET_CONNECTED && $WIFI_CONNECTED; then
        NETWORK_STATUS="both"
    elif $ETHERNET_CONNECTED; then
        NETWORK_STATUS="ethernet"
    elif $WIFI_CONNECTED; then
        NETWORK_STATUS="wifi"
    else
        NETWORK_STATUS="none"
    fi
    
    log "INFO" "Statut réseau: $NETWORK_STATUS"
}

interactive_setup() {
    print_header
    echo -e "${BLUE}Configuration interactive du Raspberry Pi${NC}"
    echo
    
    # Type d'utilisation (choix multiples)
    echo -e "${CYAN}1. Type d'utilisation (choix multiples possibles):${NC}"
    echo "1) Serveur (headless, SSH, performances)"
    echo "2) Bureau/Desktop (interface graphique)"
    echo "3) IoT/Domotique (économie d'énergie, capteurs)"
    echo "4) Développement (outils dev, serveur web)"
    echo "5) Media Center (Kodi, streaming)"
    echo
    echo -e "${YELLOW}Exemples de combinaisons:${NC}"
    echo "• Serveur + Développement: 1,4"
    echo "• IoT + Développement: 3,4"
    echo "• Bureau + Media Center: 2,5"
    echo "• Serveur seul: 1"
    echo
    while true; do
        read -p "Choisissez (ex: 1,4 ou 3,4 ou 1) [1]: " USAGE_INPUT
        USAGE_INPUT=${USAGE_INPUT:-1}
        
        # Valider le format (nombres séparés par des virgules)
        if [[ "$USAGE_INPUT" =~ ^[1-5](,[1-5])*$ ]]; then
            # Convertir en tableau
            IFS=',' read -ra USAGE_TYPES <<< "$USAGE_INPUT"
            
            # Vérifier que chaque choix est valide
            valid=true
            for choice in "${USAGE_TYPES[@]}"; do
                if ! [[ "$choice" =~ ^[1-5]$ ]]; then
                    log "ERROR" "Choix invalide: $choice (doit être entre 1 et 5)"
                    valid=false
                    break
                fi
            done
            
            if $valid; then
                # Déterminer le type principal (le premier choix)
                USAGE_TYPE=${USAGE_TYPES[0]}
                break
            fi
        else
            log "ERROR" "Format invalide. Utilisez des nombres séparés par des virgules (ex: 1,4)"
        fi
    done
    
    # Afficher les usages sélectionnés
    echo -e "\n${GREEN}Usages sélectionnés:${NC}"
    for choice in "${USAGE_TYPES[@]}"; do
        case $choice in
            1) echo "  • Serveur (headless, SSH, performances)" ;;
            2) echo "  • Bureau/Desktop (interface graphique)" ;;
            3) echo "  • IoT/Domotique (économie d'énergie, capteurs)" ;;
            4) echo "  • Développement (outils dev, serveur web)" ;;
            5) echo "  • Media Center (Kodi, streaming)" ;;
        esac
    done
    
    # Configuration réseau avec détection
    echo -e "\n${CYAN}2. Configuration réseau:${NC}"
    
    # Afficher l'état actuel
    echo -e "${YELLOW}État réseau actuel détecté:${NC}"
    case $NETWORK_STATUS in
        "both")
            echo "  ✅ Ethernet connecté (IP: $CURRENT_IP)"
            echo "  ✅ Wi-Fi connecté (SSID: $CURRENT_SSID)"
            ;;
        "ethernet")
            echo "  ✅ Ethernet connecté (IP: $CURRENT_IP)"
            echo "  ❌ Wi-Fi non connecté"
            ;;
        "wifi")
            echo "  ❌ Ethernet non connecté"
            echo "  ✅ Wi-Fi connecté (SSID: $CURRENT_SSID)"
            ;;
        "none")
            echo "  ❌ Aucune connexion réseau détectée"
            ;;
    esac
    
    if $INTERNET_ACCESS; then
        echo "  🌐 Accès Internet: ✅ Fonctionnel"
    else
        echo "  🌐 Accès Internet: ❌ Non disponible"
    fi
    echo
    
    # Proposer des options basées sur l'état actuel
    case $NETWORK_STATUS in
        "both")
            echo "Options disponibles:"
            echo "1) Garder la configuration actuelle (Ethernet + Wi-Fi)"
            echo "2) Ethernet uniquement"
            echo "3) Wi-Fi uniquement"
            echo "4) Reconfigurer Wi-Fi"
            read -p "Choisissez (1-4) [1]: " NETWORK_TYPE
            NETWORK_TYPE=${NETWORK_TYPE:-1}
            ;;
        "ethernet")
            echo "Options disponibles:"
            echo "1) Garder Ethernet uniquement"
            echo "2) Ajouter Wi-Fi"
            echo "3) Reconfigurer Ethernet"
            read -p "Choisissez (1-3) [1]: " NETWORK_TYPE
            NETWORK_TYPE=${NETWORK_TYPE:-1}
            ;;
        "wifi")
            echo "Options disponibles:"
            echo "1) Garder Wi-Fi uniquement"
            echo "2) Ajouter Ethernet"
            echo "3) Reconfigurer Wi-Fi"
            read -p "Choisissez (1-3) [1]: " NETWORK_TYPE
            NETWORK_TYPE=${NETWORK_TYPE:-1}
            ;;
        "none")
            echo "Options disponibles:"
            echo "1) Configurer Wi-Fi"
            echo "2) Configurer Ethernet"
            echo "3) Wi-Fi + Ethernet"
            read -p "Choisissez (1-3) [1]: " NETWORK_TYPE
            NETWORK_TYPE=${NETWORK_TYPE:-1}
            ;;
    esac
    
    # Configuration Wi-Fi si nécessaire
    if [[ $NETWORK_TYPE == "1" && $NETWORK_STATUS == "both" ]] || \
       [[ $NETWORK_TYPE == "2" && $NETWORK_STATUS == "ethernet" ]] || \
       [[ $NETWORK_TYPE == "1" && $NETWORK_STATUS == "wifi" ]] || \
       [[ $NETWORK_TYPE == "3" && $NETWORK_STATUS == "wifi" ]] || \
       [[ $NETWORK_TYPE == "1" && $NETWORK_STATUS == "none" ]] || \
       [[ $NETWORK_TYPE == "3" && $NETWORK_STATUS == "none" ]]; then
        
        if [[ -n "$CURRENT_SSID" && $NETWORK_TYPE != "4" && $NETWORK_TYPE != "3" ]]; then
            echo -e "\n${GREEN}Wi-Fi actuel: $CURRENT_SSID${NC}"
            read -p "Garder cette connexion Wi-Fi? (y/n) [y]: " KEEP_WIFI
            KEEP_WIFI=${KEEP_WIFI:-y}
            
            if [[ $KEEP_WIFI == "y" ]]; then
                WIFI_SSID="$CURRENT_SSID"
                echo "Connexion Wi-Fi actuelle conservée"
            else
                read -p "Nouveau SSID Wi-Fi: " WIFI_SSID
                read -s -p "Mot de passe Wi-Fi: " WIFI_PASSWORD
                echo
            fi
        else
            read -p "SSID Wi-Fi: " WIFI_SSID
            read -s -p "Mot de passe Wi-Fi: " WIFI_PASSWORD
            echo
        fi
        
        # IP statique
        while true; do
            read -p "IP statique (optionnel, format: 192.168.1.100/24): " STATIC_IP
            if [[ -z "$STATIC_IP" ]] || validate_input "$STATIC_IP" "ip"; then
                break
            fi
        done
    fi
    
    # Configuration SSH
    echo -e "\n${CYAN}3. Configuration SSH:${NC}"
    read -p "Autoriser l'authentification par mot de passe? (y/n) [y]: " SSH_PASSWORD_AUTH
    SSH_PASSWORD_AUTH=${SSH_PASSWORD_AUTH:-y}
    
    while true; do
        read -p "Port SSH personnalisé (22 par défaut) [22]: " SSH_PORT
        SSH_PORT=${SSH_PORT:-22}
        if validate_input "$SSH_PORT" "port"; then
            break
        fi
    done
    
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
    
    read -p "Vérifier et corriger les bibliothèques obsolètes? (y/n) [y]: " CHECK_LIBRARIES
    CHECK_LIBRARIES=${CHECK_LIBRARIES:-y}
    
    # Récapitulatif
    echo -e "\n${PURPLE}═══ RÉCAPITULATIF DE LA CONFIGURATION ═══${NC}"
    echo "Types d'usage:"
    for choice in "${USAGE_TYPES[@]}"; do
        case $choice in
            1) echo "  • Serveur headless" ;;
            2) echo "  • Desktop/Bureau" ;;
            3) echo "  • IoT/Domotique" ;;
            4) echo "  • Développement" ;;
            5) echo "  • Media Center" ;;
        esac
    done
    echo "Réseau: $(case $NETWORK_STATUS in 
        "both") echo "Ethernet + Wi-Fi (actuel)" ;;
        "ethernet") echo "Ethernet (actuel)" ;;
        "wifi") echo "Wi-Fi (actuel)" ;;
        "none") echo "À configurer" ;;
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
    
    # Créer un fichier de rollback
    local rollback_script="$BACKUP_DIR/rollback.sh"
    echo "#!/bin/bash" > "$rollback_script"
    echo "# Script de rollback généré le $(date)" >> "$rollback_script"
    echo "echo '🔄 Restauration des configurations originales...'" >> "$rollback_script"
    
    for file in "${files_to_backup[@]}"; do
        if [[ -f $file ]]; then
            local backup_name="$(basename $file).$(date +%Y%m%d_%H%M%S).bak"
            sudo cp "$file" "$BACKUP_DIR/$backup_name"
            log "INFO" "Sauvegardé: $file -> $backup_name"
            
            # Ajouter la commande de rollback
            echo "sudo cp '$BACKUP_DIR/$backup_name' '$file'" >> "$rollback_script"
        fi
    done
    
    echo "echo '✅ Restauration terminée'" >> "$rollback_script"
    chmod +x "$rollback_script"
    log "INFO" "Script de rollback créé: $rollback_script"
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

# Fonction pour vérifier et corriger les bibliothèques obsolètes
check_and_fix_outdated_libraries() {
    log "INFO" "Vérification des bibliothèques obsolètes..."
    
    # Vérifier les daemons utilisant des bibliothèques obsolètes
    if command -v needrestart >/dev/null 2>&1; then
        log "INFO" "Vérification avec needrestart..."
        local outdated_services=$(sudo needrestart -b 2>/dev/null | grep -E "Daemons using outdated libraries" -A 10 | grep -E "^\s*[a-zA-Z]" | wc -l)
        
        if [ "$outdated_services" -gt 0 ]; then
            log "WARN" "Services utilisant des bibliothèques obsolètes détectés"
            
            # Afficher les services concernés
            sudo needrestart -b 2>/dev/null | grep -E "Daemons using outdated libraries" -A 20 | grep -E "^\s*[a-zA-Z]" | while read service; do
                log "WARN" "Service concerné: $service"
            done
            
            # Proposer de redémarrer les services
            log "INFO" "Redémarrage des services pour appliquer les mises à jour..."
            sudo needrestart -r a 2>/dev/null || {
                log "INFO" "Redémarrage manuel des services critiques..."
                sudo systemctl restart ssh
                sudo systemctl restart systemd-resolved
                sudo systemctl restart systemd-logind
            }
        else
            log "INFO" "Aucune bibliothèque obsolète détectée"
        fi
    else
        # Installer needrestart si pas disponible
        log "INFO" "Installation de needrestart pour la gestion des mises à jour..."
        sudo apt install -y needrestart
        
        # Vérifier après installation
        if command -v needrestart >/dev/null 2>&1; then
            log "INFO" "Vérification post-installation..."
            sudo needrestart -b 2>/dev/null | grep -E "Daemons using outdated libraries" -A 10 || log "INFO" "Aucun problème détecté"
        fi
    fi
    
    # Vérification supplémentaire avec lsof
    log "INFO" "Vérification des processus utilisant des bibliothèques supprimées..."
    if command -v lsof >/dev/null 2>&1; then
        local deleted_libs=$(sudo lsof +D /lib /usr/lib 2>/dev/null | grep -E "DEL.*\.so" | wc -l)
        if [ "$deleted_libs" -gt 0 ]; then
            log "WARN" "Processus utilisant des bibliothèques supprimées détectés"
            sudo lsof +D /lib /usr/lib 2>/dev/null | grep -E "DEL.*\.so" | head -5 | while read line; do
                log "WARN" "Bibliothèque supprimée: $line"
            done
        else
            log "INFO" "Aucune bibliothèque supprimée en cours d'utilisation"
        fi
    fi
}

# Fonction pour vérifier la sécurité du système
perform_security_checks() {
    log "INFO" "Vérifications de sécurité du système..."
    
    # Vérifier les mises à jour de sécurité
    if command -v unattended-upgrades >/dev/null 2>&1; then
        log "INFO" "Vérification des mises à jour automatiques de sécurité..."
        if systemctl is-enabled unattended-upgrades >/dev/null 2>&1; then
            log "INFO" "Mises à jour automatiques de sécurité activées"
        else
            log "WARN" "Mises à jour automatiques de sécurité non activées"
            read -p "Activer les mises à jour automatiques de sécurité? (y/n) [y]: " ENABLE_AUTO_UPDATES
            ENABLE_AUTO_UPDATES=${ENABLE_AUTO_UPDATES:-y}
            
            if [[ $ENABLE_AUTO_UPDATES == 'y' ]]; then
                sudo systemctl enable unattended-upgrades
                sudo systemctl start unattended-upgrades
                log "INFO" "Mises à jour automatiques de sécurité activées"
            fi
        fi
    fi
    
    # Vérifier les ports ouverts
    log "INFO" "Vérification des ports ouverts..."
    local open_ports=$(ss -tuln | grep LISTEN | wc -l)
    log "INFO" "Ports en écoute: $open_ports"
    
    # Afficher les ports ouverts (sauf les ports système)
    ss -tuln | grep LISTEN | grep -v -E "127\.0\.0\.1|::1" | while read line; do
        local port=$(echo $line | awk '{print $5}' | cut -d: -f2)
        local service=$(ss -tuln | grep ":$port " | head -1)
        log "INFO" "Port ouvert: $port"
    done
    
    # Vérifier les utilisateurs avec shell
    log "INFO" "Vérification des utilisateurs avec shell..."
    local shell_users=$(grep -E ":/bin/(bash|sh|zsh)$" /etc/passwd | wc -l)
    log "INFO" "Utilisateurs avec shell: $shell_users"
    
    # Vérifier les permissions sensibles
    log "INFO" "Vérification des permissions sensibles..."
    if [ -w /etc/passwd ]; then
        log "WARN" "Fichier /etc/passwd modifiable par l'utilisateur actuel"
    fi
    
    if [ -w /etc/shadow ]; then
        log "WARN" "Fichier /etc/shadow modifiable par l'utilisateur actuel"
    fi
}

configure_boot_config() {
    log "INFO" "Configuration du fichier boot/config.txt..."
    
    local config_file="/boot/firmware/config.txt"
    
    # Base de configuration dans une variable
    local config_content="# Configuration générée par PiStarter

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

# Configuration spécifique selon l'usage"
    
    # Configurations spécifiques selon les usages sélectionnés
    config_content+="

# Configuration selon les usages sélectionnés"
    
    # Vérifier chaque usage sélectionné
    for choice in "${USAGE_TYPES[@]}"; do
        case $choice in
            1) # Serveur
                config_content+="

# Configuration SERVEUR
start_x=0
gpu_mem=16
dtparam=audio=off
hdmi_blanking=1
dtparam=act_led_trigger=none
dtparam=act_led_activelow=off
dtparam=pwr_led_trigger=none
dtparam=pwr_led_activelow=off"
                if [[ $NETWORK_TYPE == "2" ]]; then
                    config_content+="
dtoverlay=pi3-disable-wifi"
                fi
                if [[ $NETWORK_TYPE == "3" ]]; then
                    config_content+="
dtoverlay=pi3-disable-bt"
                fi
                ;;
                
            2) # Desktop
                config_content+="

# Configuration DESKTOP
gpu_mem=128
dtparam=audio=on"
                ;;
                
            3) # IoT
                config_content+="

# Configuration IoT/DOMOTIQUE
start_x=0
gpu_mem=16
dtparam=audio=off
hdmi_blanking=1
# Optimisations énergie
dtparam=act_led_trigger=none
dtparam=pwr_led_trigger=none"
                ;;
                
            4) # Développement
                config_content+="

# Configuration DÉVELOPPEMENT
gpu_mem=64
dtparam=audio=on
# Interfaces pour développement
dtparam=i2c_arm=on
dtparam=spi=on"
                ;;
                
            5) # Media Center
                config_content+="

# Configuration MEDIA CENTER
gpu_mem=128
dtparam=audio=on
# Optimisations vidéo
hdmi_force_hotplug=1
hdmi_drive=2"
                ;;
        esac
    done
    
    # Optimisations selon le modèle de RPi
    if [[ $RPI_MODEL == "4" ]]; then
        config_content+="

# Optimisations RPi 4
arm_freq=1800
over_voltage=6
temp_limit=80
dtparam=sd_overclock=100"
    fi
    
    # Écrire directement le contenu
    echo "$config_content" | sudo tee "$config_file" > /dev/null
    log "INFO" "Configuration boot appliquée"
}

configure_ssh() {
    log "INFO" "Configuration SSH sécurisée..."
    
    local sshd_config="/etc/ssh/sshd_config"
    local password_auth=$([[ $SSH_PASSWORD_AUTH == 'y' ]] && echo 'yes' || echo 'no')
    
    # Configuration SSH dans une variable
    local ssh_config_content="# Configuration SSH générée par PiStarter

Port $SSH_PORT
AddressFamily inet
ListenAddress 0.0.0.0

# Banner de connexion
Banner /etc/ssh/ssh_banner

# Sécurité de base
PermitRootLogin no
StrictModes yes
MaxAuthTries 6
MaxSessions 10
MaxStartups 10:30:60

# Authentification
PubkeyAuthentication yes
AuthorizedKeysFile .ssh/authorized_keys
PasswordAuthentication $password_auth
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
KexAlgorithms curve25519-sha256@libssh.org,diffie-hellman-group16-sha512"
    
    # Tester la configuration en utilisant un fichier temporaire
    local temp_config="/tmp/sshd_config_test"
    echo "$ssh_config_content" > "$temp_config"
    
    if sudo sshd -t -f "$temp_config"; then
        echo "$ssh_config_content" | sudo tee "$sshd_config" > /dev/null
        rm -f "$temp_config"
        log "INFO" "Configuration SSH appliquée"
    else
        log "ERROR" "Configuration SSH invalide"
        rm -f "$temp_config"
        return 1
    fi
}

configure_network() {
    log "INFO" "Configuration réseau intelligente..."
    
    # Vérifier si une configuration Wi-Fi est nécessaire
    local wifi_needed=false
    
    case $NETWORK_STATUS in
        "both")
            if [[ $NETWORK_TYPE == "3" || $NETWORK_TYPE == "4" ]]; then
                wifi_needed=true
            fi
            ;;
        "ethernet")
            if [[ $NETWORK_TYPE == "2" ]]; then
                wifi_needed=true
            fi
            ;;
        "wifi")
            if [[ $NETWORK_TYPE == "3" ]]; then
                wifi_needed=true
            fi
            ;;
        "none")
            if [[ $NETWORK_TYPE == "1" || $NETWORK_TYPE == "3" ]]; then
                wifi_needed=true
            fi
            ;;
    esac
    
    if $wifi_needed && [[ -n $WIFI_SSID ]]; then
        log "INFO" "Configuration Wi-Fi: $WIFI_SSID"
        
        # Vérifier si NetworkManager est disponible
        if command -v nmcli >/dev/null 2>&1; then
            # Configuration Wi-Fi avec NetworkManager
            if sudo nmcli dev wifi connect "$WIFI_SSID" password "$WIFI_PASSWORD"; then
                log "INFO" "Connexion Wi-Fi établie avec succès"
                
                # Configuration IP statique si demandée
                if [[ -n $STATIC_IP ]]; then
                    local connection_name=$(nmcli -t -f NAME,DEVICE con show --active | grep wlan0 | cut -d: -f1)
                    if [[ -n $connection_name ]]; then
                        local gateway=$(ip route | grep default | awk '{print $3}' | head -1)
                        
                        sudo nmcli con modify "$connection_name" \
                            ipv4.method manual \
                            ipv4.addresses "$STATIC_IP" \
                            ipv4.gateway "$gateway" \
                            ipv4.dns "8.8.8.8,1.1.1.1"
                        
                        log "INFO" "IP statique configurée: $STATIC_IP"
                    fi
                fi
            else
                log "ERROR" "Échec de la connexion Wi-Fi"
                return 1
            fi
        else
            log "WARN" "NetworkManager non disponible, configuration Wi-Fi manuelle requise"
            log "INFO" "SSID: $WIFI_SSID"
            if [[ -n $STATIC_IP ]]; then
                log "INFO" "IP statique souhaitée: $STATIC_IP"
            fi
        fi
    else
        log "INFO" "Configuration réseau actuelle conservée"
    fi
    
    # Vérifier la connectivité finale
    sleep 3
    if ping -c 1 -W 3 8.8.8.8 >/dev/null 2>&1; then
        log "INFO" "Connectivité Internet vérifiée"
    else
        log "WARN" "Pas de connectivité Internet détectée après configuration"
    fi
}

install_monitoring() {
    if [[ $INSTALL_MONITORING == 'y' ]]; then
        log "INFO" "Installation du monitoring SSH/réseau..."
        
        # Script de monitoring SSH adaptatif et sécurisé dans une variable
        local monitor_script_content='#!/bin/bash
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
    echo "$(date "+%Y-%m-%d %H:%M:%S") - $1" | tee -a $LOGFILE
}

# Auto-détection de la configuration SSH au démarrage
detect_ssh_configuration() {
    log "INFO" "Auto-détection de la configuration SSH..."
    
    # Détecter le nom du service SSH
    if systemctl list-units --type=service 2>/dev/null | grep -q "ssh.service"; then
        SSH_SERVICE="ssh"
    elif systemctl list-units --type=service 2>/dev/null | grep -q "sshd.service"; then
        SSH_SERVICE="sshd"
    elif systemctl list-units --type=service 2>/dev/null | grep -q "openssh.service"; then
        SSH_SERVICE="openssh"
    else
        SSH_SERVICE="ssh"  # Fallback par défaut
    fi
    
    # Détecter le pattern de processus qui fonctionne
    local patterns=("sshd" "/usr/sbin/sshd" "/usr/bin/sshd")
    for pattern in "${patterns[@]}"; do
        if pgrep -f "$pattern" >/dev/null 2>/dev/null; then
            SSH_PROCESS_PATTERN="$pattern"
            break
        fi
    done
    
    # Fallback si aucun pattern spécifique trouvé
    if [ -z "$SSH_PROCESS_PATTERN" ]; then
        SSH_PROCESS_PATTERN="sshd"
    fi
    
    log "INFO" "Configuration SSH détectée - Service: $SSH_SERVICE, Processus: $SSH_PROCESS_PATTERN"
}

# Vérifier s'\''il y a des sessions SSH actives
check_active_sessions() {
    local active_sessions=$(who 2>/dev/null | wc -l)
    local ssh_sessions=$(ss -tn state established 2>/dev/null | grep :'$SSH_PORT' | wc -l)
    
    if [ $active_sessions -gt 0 ] || [ $ssh_sessions -gt 0 ]; then
        log "INFO" "$active_sessions session(s) utilisateur(s), $ssh_sessions connexion(s) SSH actives - PAS de redémarrage"
        return 1  # Ne pas redémarrer s'\''il y a des sessions
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
    if ! ss -tnlp 2>/dev/null | grep -q ":'$SSH_PORT'"; then
        log "WARNING" "SSH n'\''écoute pas sur le port '$SSH_PORT'"
        ((failures++))
    fi
    
    # Test 3: Y a-t-il un processus SSH ?
    if ! pgrep -f "$SSH_PROCESS_PATTERN" >/dev/null 2>/dev/null; then
        log "WARNING" "Aucun processus SSH trouvé avec le pattern '\''$SSH_PROCESS_PATTERN'\''"
        ((failures++))
    fi
    
    # Test 4: Test de connectivité basique
    if ! timeout 3 nc -z localhost '$SSH_PORT' 2>/dev/null; then
        log "WARNING" "Port '$SSH_PORT' non accessible via nc"
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
    
    # Redémarrage en douceur (reload d'\''abord)
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
    log "INFO" "Configuration: Service=$SSH_SERVICE, Pattern=$SSH_PROCESS_PATTERN, Port='$SSH_PORT'"
    
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
                log "CRITICAL" "Seuil d'\''échec atteint ($CONSECUTIVE_FAILURES)"
                
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
        log "ERROR" "Commande '\''$cmd'\'' manquante"
        exit 1
    fi
done

# Auto-détection et démarrage
detect_ssh_configuration
main_monitoring_loop'
        
        # Écrire le script directement
        echo "$monitor_script_content" | sudo tee /usr/local/bin/ssh-monitor-safe.sh > /dev/null
        
        sudo chmod +x /usr/local/bin/ssh-monitor-safe.sh
        
        # Service systemd dans une variable
        local service_content="[Unit]
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
WantedBy=multi-user.target"
        
        # Écrire le service directement
        echo "$service_content" | sudo tee /etc/systemd/system/ssh-monitor-safe.service > /dev/null
        
        sudo systemctl daemon-reload
        sudo systemctl enable ssh-monitor-safe.service
        log "INFO" "Monitoring SSH adaptatif installé et activé"
    fi
}

install_security() {
    if [[ $INSTALL_FAIL2BAN == 'y' ]]; then
        log "INFO" "Installation de fail2ban..."
        sudo apt install -y fail2ban
        
        # Configuration fail2ban pour SSH dans une variable
        local fail2ban_config="[DEFAULT]
bantime = 3600
findtime = 600
maxretry = 3

[ssh]
enabled = true
port = $SSH_PORT
filter = sshd
logpath = /var/log/auth.log"
        
        # Écrire la configuration directement
        echo "$fail2ban_config" | sudo tee /etc/fail2ban/jail.local > /dev/null
        
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
        sudo usermod -aG docker $DEFAULT_USERNAME
        rm get-docker.sh
        log "INFO" "Docker installé"
    fi
}

install_usage_specific_tools() {
    log "INFO" "Installation des outils spécifiques aux usages sélectionnés..."
    
    for choice in "${USAGE_TYPES[@]}"; do
        case $choice in
            1) # Serveur
                log "INFO" "Installation des outils serveur..."
                local server_packages=(
                    "nginx" "apache2-utils" "htop" "iotop" "ncdu"
                    "rsync" "screen" "tmux" "ufw" "logrotate"
                )
                sudo apt install -y "${server_packages[@]}"
                ;;
                
            2) # Desktop
                log "INFO" "Installation des outils desktop..."
                local desktop_packages=(
                    "lxde" "firefox-esr" "chromium-browser" "vlc"
                    "gimp" "libreoffice" "thunderbird"
                )
                sudo apt install -y "${desktop_packages[@]}"
                ;;
                
            3) # IoT/Domotique
                log "INFO" "Installation des outils IoT..."
                local iot_packages=(
                    "python3-pip" "python3-gpiozero" "python3-rpi.gpio"
                    "i2c-tools" "spi-tools" "wiringpi" "nodejs" "npm"
                )
                sudo apt install -y "${iot_packages[@]}"
                
                # Activer I2C et SPI
                sudo raspi-config nonint do_i2c 0
                sudo raspi-config nonint do_spi 0
                ;;
                
            4) # Développement
                log "INFO" "Installation des outils de développement..."
                local dev_packages=(
                    "git" "vim" "nano" "build-essential" "cmake"
                    "python3-dev" "python3-venv" "nodejs" "npm"
                    "docker.io" "docker-compose" "postgresql-client"
                    "mysql-client" "redis-tools" "curl" "wget"
                )
                sudo apt install -y "${dev_packages[@]}"
                
                # Configuration Git basique
                if ! git config --global user.name >/dev/null 2>&1; then
                    log "INFO" "Configuration Git recommandée après installation"
                fi
                ;;
                
            5) # Media Center
                log "INFO" "Installation des outils Media Center..."
                local media_packages=(
                    "kodi" "kodi-peripheral-joystick" "kodi-pvr-iptvsimple"
                    "vlc" "ffmpeg" "youtube-dl" "transmission-daemon"
                )
                sudo apt install -y "${media_packages[@]}"
                ;;
        esac
    done
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

create_ssh_banner() {
    log "INFO" "Création du message de démarrage SSH personnalisé..."
    
    # Banner SSH dans une variable
    local ssh_banner_content='╔══════════════════════════════════════════════════════════════╗
║                                                              ║
║           🍓 Raspberry Pi - Serveur Configuré 🍓            ║
║                                                              ║
║  📅 Date: $(date "+%A %d %B %Y - %H:%M:%S")                    ║
║  ⏱️  Uptime: $(uptime -p | sed "s/up //")                                    ║
║  🌡️  Température: $(vcgencmd measure_temp | cut -d= -f2)                    ║
║  💾 Mémoire: $(free -h | grep Mem | awk "{print \$3\"/\"\$2}")                    ║
║  💿 Stockage: $(df -h / | tail -1 | awk "{print \$3\"/\"\$2\" (\"\$5\")\"}")                    ║
║                                                              ║
║  🌐 Connexions réseau:                                       ║
║     $(ip addr show | grep -E "inet.*wlan0|inet.*eth0" | awk "{print \"  \" \$NF \": \" \$2}" | head -2 | sed "s/^/     /")                    ║
║                                                              ║
║  🔐 SSH Port: '$SSH_PORT' | Connexions actives: $(ss -tn state established | grep :'$SSH_PORT' | wc -l)                    ║
║                                                              ║
║  ⚙️  Commandes utiles:                                        ║
║     • rpi-status     - Dashboard système complet             ║
║     • ssh-status     - Statut du monitoring SSH              ║
║     • ssh-logs       - Logs du monitoring en temps réel      ║
║     • help           - Aide et commandes disponibles         ║
║                                                              ║
║  🚀 Ce serveur a été configuré avec PiStarter v'$VERSION'              ║
║                                                              ║
╚══════════════════════════════════════════════════════════════╝'
    
    # Écrire le banner
    echo "$ssh_banner_content" | sudo tee /etc/ssh/ssh_banner > /dev/null
    log "INFO" "Banner SSH créé: /etc/ssh/ssh_banner"
}

create_status_script() {
    log "INFO" "Création du script de statut système..."
    
    # Script de statut dans une variable
    local status_script_content='#!/bin/bash
# Script de statut RPi généré par Auto-Configurator

echo "🍓 Raspberry Pi Status Dashboard"
echo "================================"
echo "Date: $(date)"
echo "Uptime: $(uptime -p)"
echo "Température: $(vcgencmd measure_temp)"
echo "Fréquence CPU: $(vcgencmd measure_clock arm | awk -F'\''='\'' '\''{print $2/1000000}'\'') MHz"
echo "Mémoire: $(free -h | grep Mem | awk '\''{print $3 "/" $2}'\'')"
echo "Charge: $(cat /proc/loadavg | awk '\''{print $1, $2, $3}'\'')"
echo "Stockage: $(df -h / | tail -1 | awk '\''{print $3 "/" $2 " (" $5 ")"}'\'')"
echo
echo "🌐 Réseau:"
ip addr show | grep -E "inet.*wlan0|inet.*eth0" | awk '\''{print "  " $NF ": " $2}'\''
echo
echo "🔐 SSH:"
systemctl is-active ssh && echo "  Service: Actif" || echo "  Service: Inactif"
echo "  Port: '$SSH_PORT'"
echo "  Connexions: $(ss -tn state established | grep :'$SSH_PORT' | wc -l)"
echo
if systemctl is-active ssh-monitor-safe >/dev/null 2>&1; then
    echo "📊 Monitoring: Actif"
    echo "  Logs récents:"
    tail -3 /var/log/ssh-monitor-safe.log 2>/dev/null | sed '\''s/^/    /'\''
else
    echo "📊 Monitoring: Inactif"
fi
echo
echo "⚙️ Commandes utiles:"
echo "  rpi-status                    - Ce dashboard"
echo "  sudo systemctl status ssh-monitor-safe  - Statut monitoring"
echo "  sudo tail -f /var/log/ssh-monitor-safe.log  - Logs monitoring"
echo "  sudo journalctl -u ssh-monitor-safe -f     - Logs systemd"'
    
    # Écrire le script directement
    echo "$status_script_content" | sudo tee /usr/local/bin/rpi-status > /dev/null
    
    sudo chmod +x /usr/local/bin/rpi-status
    
    # Script d'aide
    local help_script_content='#!/bin/bash
# Script d'\''aide PiStarter

echo "🍓 PiStarter - Aide et Commandes Utiles"
echo "========================================"
echo
echo "📊 MONITORING SYSTÈME:"
echo "  rpi-status                    - Dashboard système complet"
echo "  ssh-status                    - Statut du monitoring SSH"
echo "  ssh-logs                      - Logs du monitoring en temps réel"
echo "  sudo journalctl -u ssh-monitor-safe -f  - Logs systemd"
echo
echo "🔧 GESTION SYSTÈME:"
echo "  sudo systemctl status ssh     - Statut du service SSH"
echo "  sudo systemctl restart ssh    - Redémarrer SSH"
echo "  sudo systemctl status fail2ban - Statut fail2ban"
echo "  sudo fail2ban-client status   - Statut des prisons"
echo "  sudo needrestart -b           - Vérifier bibliothèques obsolètes"
echo "  sudo needrestart -r a         - Redémarrer services avec libs obsolètes"
echo
echo "🌐 RÉSEAU:"
echo "  ip addr show                  - Adresses IP"
echo "  ss -tuln                      - Ports en écoute"
echo "  ping 8.8.8.8                 - Test connectivité"
echo "  nmcli dev wifi list           - Réseaux Wi-Fi disponibles"
echo
echo "💾 SYSTÈME:"
echo "  vcgencmd measure_temp         - Température CPU"
echo "  vcgencmd measure_clock arm    - Fréquence CPU"
echo "  free -h                       - Utilisation mémoire"
echo "  df -h                         - Utilisation disque"
echo "  htop                          - Moniteur système"
echo
echo "🔐 SÉCURITÉ:"
echo "  sudo ufw status               - Statut firewall"
echo "  sudo last                     - Dernières connexions"
echo "  sudo who                      - Utilisateurs connectés"
echo
echo "📁 FICHIERS IMPORTANTS:"
echo "  /etc/ssh/sshd_config          - Configuration SSH"
echo "  /boot/firmware/config.txt     - Configuration boot"
echo "  /var/log/ssh-monitor-safe.log - Logs monitoring"
echo "  /etc/rpi-autoconfig/backups/  - Sauvegardes"
echo
echo "🆘 EN CAS DE PROBLÈME:"
echo "  sudo /etc/rpi-autoconfig/backups/rollback.sh  - Restaurer config"
echo "  sudo systemctl restart ssh-monitor-safe       - Redémarrer monitoring"
echo "  sudo journalctl -xe                          - Logs système détaillés"
echo
echo "💡 Ce serveur a été configuré avec PiStarter v'$VERSION'"
echo "   Pour plus d'\''aide: https://github.com/PrinMeshia/PiStarter"'
    
    # Écrire le script d'aide
    echo "$help_script_content" | sudo tee /usr/local/bin/help > /dev/null
    sudo chmod +x /usr/local/bin/help
    
    # Alias pour faciliter l'usage
    echo "alias status='rpi-status'" >> /home/$DEFAULT_USERNAME/.bashrc
    echo "alias ssh-logs='sudo tail -f /var/log/ssh-monitor-safe.log'" >> /home/$DEFAULT_USERNAME/.bashrc
    echo "alias ssh-status='sudo systemctl status ssh-monitor-safe'" >> /home/$DEFAULT_USERNAME/.bashrc
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
    echo "• Types d'usage:"
    for choice in "${USAGE_TYPES[@]}"; do
        case $choice in
            1) echo "  - Serveur" ;;
            2) echo "  - Desktop" ;;
            3) echo "  - IoT" ;;
            4) echo "  - Développement" ;;
            5) echo "  - Media Center" ;;
        esac
    done
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
    echo "• Banner SSH: /etc/ssh/ssh_banner"
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
    detect_network_status
    
    # Configuration interactive
    interactive_setup
    
    # Exécution des étapes
    log "INFO" "Début de la configuration automatique"
    backup_original_configs
    update_system
    
    if [[ $CHECK_LIBRARIES == 'y' ]]; then
        check_and_fix_outdated_libraries
    fi
    
    perform_security_checks
    configure_boot_config
    configure_ssh
    configure_network
    install_monitoring
    install_security  
    install_optional_tools
    install_usage_specific_tools
    apply_system_optimizations
    create_ssh_banner
    create_status_script
    finalize_installation
}

# Gestion des signaux
trap 'log "ERROR" "Installation interrompue"; exit 1' SIGINT SIGTERM

# Démarrage du script
main "$@"
