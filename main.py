from toolkit.portscanner import PortScanner
from toolkit.bruteforcer import BruteForcer
from toolkit.utils import load_passwords

def main():
    print("=== Penetration Testing Toolkit ===")
    choice = input("Choose module (1: PortScanner, 2: BruteForcer): ")
    if choice == '1':
        target = input("Enter target host/IP: ")
        ports = input("Enter ports (comma-separated) or leave blank: ")
        port_list = [int(p.strip()) for p in ports.split(',')] if ports else None
        scanner = PortScanner(target, port_list)
        results = scanner.scan()
        print(f"Open ports: {results}")
    elif choice == '2':
        host = input("Enter SSH host/IP: ")
        username = input("Enter username: ")
        pwd_file = input("Enter password file path: ")
        passwords = load_passwords(pwd_file)
        bruteforcer = BruteForcer(host, username, passwords)
        bruteforcer.brute_force_ssh()
    else:
        print("Invalid choice.")

if __name__ == "__main__":
    main()
