from scapy.all import AsyncSniffer, Dot11, Dot11Beacon

class NetworkScanner:
    def __init__(self, interface, on_ap_found, on_client_found):
        self.interface = interface
        self.on_ap_found = on_ap_found
        self.on_client_found = on_client_found
        self.sniffer = None
        self.known_aps = dict()
        self.known_clients = dict()
        self.start_time = None

    def start(self):
        self.sniffer = AsyncSniffer(
            iface=self.interface,
            monitor=True,
            prn=self._handle_packet,
            filter="wlan subtype beacon or wlan type data"
        )
        self.sniffer.start()

    def stop(self):
        if self.sniffer:
            self.sniffer.stop()

    def _handle_packet(self, packet):
        if not packet.haslayer(Dot11):
            return

        if packet.haslayer(Dot11Beacon):
            self._handle_beacon_packet(packet)
            return

        if packet.type == 2:
            self._handle_data_packet(packet)
            return
        
    def _handle_beacon_packet(self, packet):
        bssid = packet.addr2
        if not self.known_aps.get(bssid):
            ssid = packet.info.decode()
            self.known_aps[bssid] = ssid
            self.on_ap_found(bssid, ssid)
            print(f"[+] Found AP: {ssid} ({bssid})")

    def _handle_data_packet(self, packet):
        is_to_ds = 'to-DS' in packet.FCfield
        is_from_ds = 'from-DS' in packet.FCfield

        if is_to_ds == is_from_ds:
            return
        
        client_mac = packet.addr2 if is_to_ds else packet.addr1
        ap_bssid = packet.addr1 if is_to_ds else packet.addr2

        if not (client_mac and ap_bssid):
            return
        if client_mac.lower() == "ff:ff:ff:ff:ff:ff":
            return

        if client_mac in self.known_clients and self.known_clients.get(client_mac) == ap_bssid:
            return

        self.known_clients[client_mac] = ap_bssid
        self.on_client_found(client_mac, ap_bssid)
        print(f"[+] Found Client: {client_mac} associated with AP: {ap_bssid}")