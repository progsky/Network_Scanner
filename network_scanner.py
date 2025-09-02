#!/usr/bin/env python3
import argparse
import csv
import json
import sys
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

def scan(ip: str):
    """Send ARP requests to the given IP or range and return a list of devices."""
    arp_request = scapy.ARP(pdst=ip)
    broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
    arp_request_broadcast = broadcast / arp_request
    answered, _ = scapy.srp(arp_request_broadcast, timeout=3, verbose=False)
    return [{"ip": e[1].psrc, "mac": e[1].hwsrc} for e in answered]

def print_result(results: list, output_format: str):
    """Print scan results in the chosen format."""
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
    """Parse CLI arguments."""
    parser = argparse.ArgumentParser(description="Fast ARP network scanner")
    parser.add_argument(
        "-t", "--target", required=True,
        help="Target IP / IP range (e.g. 192.168.0.1/24)"
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
    """Run scans in parallel for multiple targets."""
    with ThreadPoolExecutor(max_workers=threads) as executor:
        results = []
        for res in executor.map(scan, targets):
            results.extend(res)
        return results

def main():
    print(Fore.CYAN + BANNER + Style.RESET_ALL)
    args = get_arguments()
    targets = [args.target]
    results = parallel_scan(targets, args.parallel)
    print_result(results, args.format)

if __name__ == "__main__":
    main()
