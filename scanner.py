import socket
import json
import csv
from scapy.all import IP, TCP, ICMP, sr1
import threading
import nmap
import ipaddress
from concurrent.futures import ThreadPoolExecutor
from typing import List, Dict

def scan_port(ip: str, port: int, open_ports: List[int]) -> None:
    try:
        packet = IP(dst=ip)/TCP(dport=port, flags="S")
        response = sr1(packet, timeout=1, verbose=0)
        if response and response.haslayer(TCP) and response.getlayer(TCP).flags == 0x12:
            open_ports.append(port)
    except Exception as e:
        print(f"Erreur lors du scan du port {port} sur {ip}: {str(e)}")

def scan_ports(ip: str, ports: range) -> List[int]:
    open_ports = []
    max_threads = min(50, len(ports))  # Limite le nombre de threads
    
    with ThreadPoolExecutor(max_workers=max_threads) as executor:
        futures = [executor.submit(scan_port, ip, port, open_ports) for port in ports]
        for future in futures:
            try:
                future.result()
            except Exception as e:
                print(f"Erreur dans l'exécution du thread: {str(e)}")
    
    return sorted(open_ports)

def detect_service_version(ip: str, port: int) -> str:
    try:
        nm = nmap.PortScanner()
        nm.scan(ip, str(port), arguments='-sV')
        for host in nm.all_hosts():
            for proto in nm[host].all_protocols():
                lport = nm[host][proto].get(port, {}).get('product', 'Unknown')
                return lport
    except Exception as e:
        print(f"Erreur lors de la détection du service sur {ip}:{port}: {str(e)}")
    return "Unknown"

def save_to_csv(data: List[Dict], filename: str) -> None:
    try:
        with open(filename, mode='w', newline='') as file:
            writer = csv.writer(file)
            writer.writerow(["IP", "Port", "Service"])
            for item in data:
                writer.writerow([item["ip"], item["port"], item["service"]])
    except Exception as e:
        print(f"Erreur lors de la sauvegarde en CSV: {str(e)}")

def save_to_json(data: List[Dict], filename: str) -> None:
    try:
        with open(filename, 'w') as file:
            json.dump(data, file, indent=4)
    except Exception as e:
        print(f"Erreur lors de la sauvegarde en JSON: {str(e)}")

def ping_sweep(ip_range: str) -> List[str]:
    try:
        network = ipaddress.ip_network(ip_range, strict=False)
        alive_hosts = []
        for ip in network.hosts():
            ip_str = str(ip)
            packet = IP(dst=ip_str)/ICMP()
            response = sr1(packet, timeout=1, verbose=0)
            if response:
                alive_hosts.append(ip_str)
                print(f"Hôte actif trouvé: {ip_str}")
        return alive_hosts
    except Exception as e:
        print(f"Erreur lors du ping sweep: {str(e)}")
        return []

def validate_ports(start_port: int, end_port: int) -> bool:
    if not (0 <= start_port <= 65535 and 0 <= end_port <= 65535):
        print("Les ports doivent être compris entre 0 et 65535")
        return False
    if start_port > end_port:
        print("Le port de début doit être inférieur ou égal au port de fin")
        return False
    return True

def main():
    try:
        ip_to_scan = input("Entrez l'adresse IP ou la plage d'adresses IP à scanner (ex: 192.168.1.1/24): ")
        start_port = int(input("Entrez le port de début à scanner: "))
        end_port = int(input("Entrez le port de fin à scanner: "))
        output_format = input("Choisissez le format de sortie (csv/json): ").lower()

        if not validate_ports(start_port, end_port):
            return

        try:
            ipaddress.ip_network(ip_to_scan, strict=False)
        except ValueError:
            print("Format d'adresse IP invalide")
            return

        ports_to_scan = range(start_port, end_port + 1)
        print(f"Démarrage du scan sur la plage {ip_to_scan}...")
        
        alive_hosts = ping_sweep(ip_to_scan)
        if not alive_hosts:
            print("Aucun hôte actif trouvé dans la plage d'adresses IP.")
            return

        results = []
        total_hosts = len(alive_hosts)
        for idx, ip in enumerate(alive_hosts, 1):
            print(f"\nScanning de l'hôte {ip} ({idx}/{total_hosts})...")
            open_ports = scan_ports(ip, ports_to_scan)
            for port in open_ports:
                print(f"Port ouvert trouvé: {ip}:{port}")
                service = detect_service_version(ip, port)
                results.append({"ip": ip, "port": port, "service": service})

        if not results:
            print("Aucun port ouvert trouvé.")
            return

        filename = f"scan_results_{ip_to_scan.replace('/', '_')}"
        if output_format == "csv":
            save_to_csv(results, f"{filename}.csv")
            print(f"Résultats sauvegardés dans {filename}.csv")
        elif output_format == "json":
            save_to_json(results, f"{filename}.json")
            print(f"Résultats sauvegardés dans {filename}.json")
        else:
            print("Format de sortie non pris en charge. Veuillez choisir entre csv et json.")

    except ValueError as e:
        print(f"Erreur de saisie: {str(e)}")
    except KeyboardInterrupt:
        print("\nScan interrompu par l'utilisateur.")
    except Exception as e:
        print(f"Une erreur inattendue s'est produite: {str(e)}")

if __name__ == "__main__":
    main()
