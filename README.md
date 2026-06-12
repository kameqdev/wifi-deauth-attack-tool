# WiFi Deauth Attak Tool
Tool for testing and researching risks associated with WiFi deauthentication attack.

It contains python tool for performing the attack and automated script for patching firmware on Raspberry Pi 3B with bcm43430a1 WiFi Chip.

### Disclaimer
This project is for academic and research use only, in controlled and legal laboratory environments. Using it to perform unauthorized attacks is illegal in many jurisdictions.

## Requirements
- Device supporting monitor mode
- Python 3.8+
- Python packages: scapy, textual

## Patching firmware to enable monitor mode
For Raspberry Pi with bcm43430a1 WiFi Chip, there is an [`nexmon_init.sh`](https://github.com/kameqdev/wifi-deauth-attack-tool/blob/main/nexmon_init.sh) script automating patching firmware using [Nexmon](https://github.com/seemoo-lab/nexmon).

To then activate monitor mode, you can use [`nexmon_enable.sh`](https://github.com/kameqdev/wifi-deauth-attack-tool/blob/main/nexmon_enable.sh)

## Usage
1. Put your Wi‑Fi interface into monitor mode.
2. Run the app as root:
   sudo python3 deauth_tool.py
3. In the UI:
   - Select an Access Point or Client
   - Press `d` to send deauthentication frames
   - `r` - rescan, `q` - quit

Default parameters:
- interface: mon0
- packet count: 100
- interval: 0.1 s
