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

        transport = client.get_transport()
        ssh_banner = transport.get_banner()
        exec_banner = ""
        if verbose:
            try:
                stdin, stdout, stderr = client.exec_command("whoami")
                exec_banner = stdout.read().decode().strip()
            except Exception:
                exec_banner = "(whoami failed)"

        if verbose:
            print("\033[92m[+] Success:\033[0m", f"{username}@{host}:{password}", end="")
            if ssh_banner:
                print(f"  --> Banner: {ssh_banner.strip()}", end="")
            if exec_banner:
                print(f"  --> whoami: {exec_banner.strip()}", end="")
            print()  # Newline
        else:
            print("\033[92m[+] Success:\033[0m", f"{username}@{host}:{password}")

        client.close()
        return True

    except paramiko.ssh_exception.SSHException as e:
        if verbose:
            if 'kex' in str(e).lower() or 'host key' in str(e).lower():
                print(f"[!] Algorithm negotiation failed on {host}: {e}")
            else:
                print(f"[!] SSH exception on {host}: {e}")
    except paramiko.AuthenticationException:
        if verbose:
            print(f"[-] Auth failed: {username}@{host}:{password}")
    except socket.timeout:
        if verbose:
            print(f"[!] Timeout on {host}")
    except socket.error as e:
        if verbose:
            print(f"[!] Socket error on {host}: {e}")
    return False
