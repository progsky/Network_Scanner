import scapy.all as scapy
import argparse
import json
import csv
import sys
from concurrent.futures import ThreadPoolExecutor
from tabulate import tabulate
from colorama import Fore, Style, init

init(autoreset=True)

def scan(ip):
    arp_request = scapy.ARP(pdst=ip)
    broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
    arp_request_broadcast = broadcast / arp_request
    answered = scapy.srp(arp_request_broadcast, timeout=3, verbose=False)[0]
    return [{"ip": e[1].psrc, "mac": e[1].hwsrc} for e in answered]

def print_result(results, output_format):
    if output_format == "table":
        print(tabulate(results, headers="keys", tablefmt="fancy_grid"))
    elif output_format == "json":
        print(json.dumps(results, indent=2))
    elif output_format == "csv":
        writer = csv.DictWriter(sys.stdout, fieldnames=["ip", "mac"])
        writer.writeheader()
        writer.writerows(results)

def get_arguments():
    parser = argparse.ArgumentParser(description="Fast ARP network scanner")
    parser.add_argument("-t", "--target", dest="target", help="Target IP / IP range (e.g. 192.168.0.1/24)", required=True)
    parser.add_argument("-f", "--format", dest="format", choices=["table", "json", "csv"], default="table", help="Output format")
    parser.add_argument("-p", "--parallel", dest="parallel", type=int, default=1, help="Parallel scans (default: 1)")
    return parser.parse_args()

def parallel_scan(targets, threads):
    with ThreadPoolExecutor(max_workers=threads) as executor:
        results = []
        for res in executor.map(scan, targets):
            results.extend(res)
        return results

if __name__ == "__main__":
    args = get_arguments()
    targets = [args.target]  # можно расширить для списка подсетей
    results = parallel_scan(targets, args.parallel)
    if results:
        print(Fore.GREEN + f"[+] Found {len(results)} devices")
        print_result(results, args.format)
    else:
        print(Fore.RED + "[-] No devices found")
