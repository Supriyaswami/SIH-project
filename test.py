from scapy.all import *
from collections import Counter

packets = rdpcap("captures/vpn.pcapng")

print("=" * 50)
print("NETWORK ANALYSIS REPORT")
print("=" * 50)

print(f"\nTotal Packets: {len(packets)}")

tcp_count = 0
udp_count = 0
ipv4_count = 0
ipv6_count = 0

source_ips = []
destination_ips = []

for pkt in packets:

    if IP in pkt:
        ipv4_count += 1
        source_ips.append(pkt[IP].src)
        destination_ips.append(pkt[IP].dst)

    if IPv6 in pkt:
        ipv6_count += 1

    if TCP in pkt:
        tcp_count += 1

    if UDP in pkt:
        udp_count += 1

print("\n===== PROTOCOLS =====")
print("IPv4 :", ipv4_count)
print("IPv6 :", ipv6_count)
print("TCP  :", tcp_count)
print("UDP  :", udp_count)

print("\n===== TOP SOURCE IPs =====")

for ip, count in Counter(source_ips).most_common(5):
    print(ip, "->", count)

print("\n===== TOP DESTINATION IPs =====")

for ip, count in Counter(destination_ips).most_common(5):
    print(ip, "->", count)

    esp_count = 0
ah_count = 0

ike500 = 0
nat4500 = 0

for pkt in packets:

    if IP in pkt:

        if pkt[IP].proto == 50:
            esp_count += 1

        elif pkt[IP].proto == 51:
            ah_count += 1

    if UDP in pkt:

        if pkt[UDP].sport == 500 or pkt[UDP].dport == 500:
            ike500 += 1

        if pkt[UDP].sport == 4500 or pkt[UDP].dport == 4500:
            nat4500 += 1

print("\n===== IPSEC ANALYSIS =====")

print("ESP Packets :", esp_count)
print("AH Packets  :", ah_count)
print("UDP 500     :", ike500)
print("UDP 4500    :", nat4500)

if esp_count > 0 or ike500 > 0 or nat4500 > 0:
    print("\nVPN DETECTED : Possible IPsec")
else:
    print("\nVPN DETECTED : No IPsec Indicators")