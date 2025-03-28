import socket
import ssl
import argparse
import getpass

TIMEOUT = 5

def build_simple_bind(username='', password='', msg_id=1):
    username_bytes = username.encode()
    password_bytes = password.encode()

    def ber_len(data):
        if len(data) < 0x80:
            return bytes([len(data)])
        else:
            length = len(data)
            length_bytes = []
            while length > 0:
                length_bytes.insert(0, length & 0xFF)
                length >>= 8
            return bytes([0x80 | len(length_bytes)]) + bytes(length_bytes)

    msg = b''
    msg += b'\x02\x01' + bytes([msg_id])
    bind_req = (
        b'\x02\x01\x03' +
        b'\x04' + ber_len(username_bytes) + username_bytes +
        b'\x80' + ber_len(password_bytes) + password_bytes
    )
    msg += b'\x60' + ber_len(bind_req) + bind_req
    full = b'\x30' + ber_len(msg) + msg
    return full

def parse_ldap_result(data):
    if len(data) < 8 or data[0] != 0x30:
        return None
    try:
        result_code = data[data.index(b'\x0a\x01') + 2]
        return result_code
    except Exception:
        return None

def send_ldap_bind(ip, sni_hostname, port, use_ldaps, username, password):
    try:
        with socket.create_connection((ip, port), timeout=TIMEOUT) as raw_sock:
            sock = raw_sock
            if use_ldaps:
                context = ssl._create_unverified_context()
                sock = context.wrap_socket(raw_sock, server_hostname=sni_hostname)

            msg = build_simple_bind(username, password)
            sock.sendall(msg)
            resp = sock.recv(4096)
            code = parse_ldap_result(resp)
            return {
                "status": "success",
                "code": code,
                "raw": resp
            }
    except Exception as e:
        return {
            "status": "error",
            "error": f"{type(e).__name__}: {e}"
        }

def run_checks(ip, hostname, username, password):
    print(f"Checking {ip} ({hostname})...")
    plain_result = send_ldap_bind(
        ip=ip,
        sni_hostname=hostname,
        port=389,
        use_ldaps=False,
        username=username,
        password=password
    )

    if plain_result["status"] == "success" and plain_result["code"] == 0:
        print("  [VULNERABLE] Signing NOT required")
    else:
        print("  [NOT VULNERABLE] LDAP signing appears to be enforced")

    tls_result = send_ldap_bind(
        ip=ip,
        sni_hostname=hostname,
        port=636,
        use_ldaps=True,
        username=username,
        password=password
    )

    if tls_result["status"] == "success":
        print("  [VULNERABLE] Channel binding NOT required")
    else:
        print("  [INCONCLUSIVE] LDAPS bind failed — could not validate channel binding")
        print(f"    Error: {tls_result['error']}")

def load_host_list(args):
    hosts = []

    if args.hosts:
        hosts += [h.strip() for h in args.hosts.split(",") if h.strip()]

    if args.hosts_file:
        try:
            with open(args.hosts_file, 'r') as f:
                file_hosts = [line.strip() for line in f if line.strip()]
                hosts += file_hosts
        except Exception as e:
            print(f"Failed to read hosts file: {e}")

    parsed = []
    for entry in hosts:
        if ':' not in entry:
            print(f"Invalid host format (expected IP:HOSTNAME): {entry}")
            continue
        ip, hostname = entry.split(":", 1)
        parsed.append((ip.strip(), hostname.strip()))

    return parsed

def main():
    parser = argparse.ArgumentParser(description="Check LDAP signing and channel binding enforcement")
    parser.add_argument("-u", "--username", required=True, help="LDAP username")
    parser.add_argument("-p", "--password", help="LDAP password (prompted if not provided)", default=None)
    parser.add_argument("--hosts", help="Comma-separated list of IP:HOSTNAME pairs")
    parser.add_argument("--hosts-file", help="File with IP:HOSTNAME pairs, one per line")

    args = parser.parse_args()

    if not args.hosts and not args.hosts_file:
        print("You must specify --hosts or --hosts-file")
        return

    if args.password is None:
        args.password = getpass.getpass("Password: ")

    targets = load_host_list(args)

    for ip, hostname in targets:
        run_checks(ip, hostname, args.username, args.password)

if __name__ == "__main__":
    main()
