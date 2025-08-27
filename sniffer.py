from scapy.all import *

interface = "wlan0"  
probeReqs = []

def sniffProbes(pkt):
    if pkt.haslayer(Dot11ProbeReq):
        if pkt.info:  
            ssid = pkt.info.decode(errors="ignore")
            src_mac = pkt.addr2  
            if ssid not in probeReqs:
                probeReqs.append(ssid)
                print(f"[+] Device {src_mac} is probing for SSID: {ssid}")

sniff(iface=interface, prn=sniffProbes, store=0)
