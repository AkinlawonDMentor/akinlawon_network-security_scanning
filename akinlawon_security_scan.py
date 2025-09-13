import scapy.all as scapy
import nmap
from datetime import datetime



def banner():
    print("\n======================================")
    print(" Infra Security Scan by \033[1mAkin-Eni\033[0m")
    print("======================================\n")


def scan_network(ip_range):
    print(f"[+] Discovering hosts in network: {ip_range}")
    arp_req = scapy.ARP(pdst=ip_range)
    broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
    arp_req_broadcast = broadcast/arp_req
    answered_list = scapy.srp(arp_req_broadcast, timeout=2, verbose=False)[0]
    
    active_hosts = []
    for sent, received in answered_list:
        active_hosts.append(received.psrc)
    return active_hosts


def detect_vlan(target_ip):
    dot1q_packet = scapy.Ether(dst="ff:ff:ff:ff:ff:ff") / scapy.Dot1Q(vlan=100) / scapy.IP(dst=target_ip)
    ans, unans = scapy.srp(dot1q_packet, timeout=2, verbose=False)

    if ans:
        return "[!] VLAN tagging detected"
    else:
        return "[-] No VLAN response"


def detect_firewall(ip):
    nm = nmap.PortScanner()
    nm.scan(ip, arguments="-sA -p 80,443")  
    result = []
    if ip in nm.all_hosts():
        for proto in nm[ip].all_protocols():
            for port in nm[ip][proto]:
                state = nm[ip][proto][port]['state']
                if state == "filtered":
                    result.append(f"[!] Firewall detected on port {port}")
                elif state == "unfiltered":
                    result.append(f"[-] No firewall on port {port}")
                else:
                    result.append(f"[?] Port {port} state: {state}")
    return result


def detect_acl(ip):
    nm = nmap.PortScanner()
    nm.scan(ip, arguments="-p 22,80,443,3389")  
    result = []
    if ip in nm.all_hosts():
        for proto in nm[ip].all_protocols():
            for port in nm[ip][proto]:
                state = nm[ip][proto][port]['state']
                if state == "filtered":
                    result.append(f"[!] Possible ACL restriction → Port {port} filtered")
                elif state == "closed":
                    result.append(f"[-] Port {port} closed (no service)")
                elif state == "open":
                    result.append(f"[+] Port {port} open")
                else:
                    result.append(f"[?] Port {port} state: {state}")
    return result


if __name__ == "__main__":
    banner()
    target_range = input("Enter target network (e.g., 192.168.1.0/24): ").strip()
    print(f"\n[***] Infra Scan Started on {target_range} at {datetime.now()} [***]\n")

    active_hosts = scan_network(target_range)
    print(f"[+] Active Hosts found in {target_range}: {len(active_hosts)}")

    for host in active_hosts:
        print(f"\n--- Scanning Host: {host} ---")
        
        vlan_result = detect_vlan(host)
        print(vlan_result)

        fw_results = detect_firewall(host)
        for res in fw_results:
            print(res)

        acl_results = detect_acl(host)
        for res in acl_results:
            print(res)

    print(f"\n[***] Infra Scan Completed at {datetime.now()} [***]\n")
