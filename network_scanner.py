#!/usr/bin/env python3
import argparse
import csv
import json
import sys
import ipaddress
from concurrent.futures import ThreadPoolExecutor

import scapy.all as scapy
from tabulate import tabulate
from colorama import Fore, Style, init

init(autoreset=True)

BANNER = r"""
███████╗ █████╗ ███████╗████████╗     █████╗ ██████╗ ██████╗ 
██╔════╝██╔══██╗╚══███╔╝╚══██╔══╝    ██╔══██╗██╔══██╗██╔══██╗
███████╗███████║  ███╔╝    ██║       ███████║██████╔╝██████╔╝
╚════██║██╔══██║ ███╔╝     ██║       ██╔══██║██╔═══╝ ██╔═══╝ 
███████║██║  ██║███████╗   ██║       ██║  ██║██║     ██║     
╚══════╝╚═╝  ╚═╝╚══════╝   ╚═╝       ╚═╝  ╚═╝╚═╝     ╚═╝     
           FAST  ARP  SCANNER
"""

def detect_local_subnet():
    """Try to detect the local subnet automatically."""
    try:
        iface = scapy.conf.iface
        ip = scapy.get_if_addr(iface)
        mask = scapy.get_if_netmask(iface)
        network = ipaddress.IPv4Network(f"{ip}/{mask}", strict=False)
        return str(network)
    except Exception:
        return None

def scan(ip: str):
    arp_request = scapy.ARP(pdst=ip)
    broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
    arp_request_broadcast = broadcast / arp_request
    answered, _ = scapy.srp(arp_request_broadcast, timeout=2, verbose=False)
    return [{"ip": e[1].psrc, "mac": e[1].hwsrc} for e in answered]

def print_result(results: list, output_format: str):
    if not results:
        print(Fore.RED + "[-] No devices found")
        return
    print(Fore.GREEN + f"[+] Found {len(results)} devices")
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
    parser.add_argument(
        "-t", "--target",
        help="Target IP / IP range (e.g. 192.168.0.1/24 or multiple separated by commas). If omitted, local subnet will be used."
    )
    parser.add_argument(
        "-f", "--format", choices=["table", "json", "csv"],
        default="table", help="Output format"
    )
    parser.add_argument(
        "-p", "--parallel", type=int, default=1,
        help="Number of parallel scans (default: 1)"
    )
    return parser.parse_args()

def parallel_scan(targets: list, threads: int):
    with ThreadPoolExecutor(max_workers=threads) as executor:
        results = []
        for res in executor.map(scan, targets):
            results.extend(res)
        return results

def main():
    print(Fore.CYAN + BANNER + Style.RESET_ALL)
    args = get_arguments()

    if args.target:
        targets = [t.strip() for t in args.target.split(",") if t.strip()]
    else:
        local_net = detect_local_subnet()
        if not local_net:
            print(Fore.RED + "[-] Could not detect local subnet. Please specify -t.")
            sys.exit(1)
        print(Fore.YELLOW + f"[i] Using detected local subnet: {local_net}")
        targets = [local_net]

    results = parallel_scan(targets, args.parallel)
    print_result(results, args.format)

if __name__ == "__main__":
    main()
