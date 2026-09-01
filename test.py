from scapy.all import rdpcap

packets = rdpcap("captures/vpn.pcapng")

print("Total Packets:", len(packets))