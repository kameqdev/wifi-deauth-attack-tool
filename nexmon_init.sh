#!/bin/bash

kernel=$(uname -r)

if [[ $kernel != 6.1.* ]]; then
    echo "This script is designed for kernel version 6.1.x"
    exit 1
fi

apt install xxd
rfkill unblock all

# Steps from Nexmon repo 
apt-get update && apt-get upgrade -y
apt install raspberrypi-kernel-headers git libgmp3-dev gawk qpdf bison flex make autoconf libtool texinfo -y
git clone https://github.com/seemoo-lab/nexmon.git
cd nexmon
cd buildtools/isl-0.10
./configure
make
make install
ln -s /usr/local/lib/libisl.so /usr/lib/arm-linux-gnueabihf/libisl.so.10
cd ../../buildtools/mpfr-3.1.4
autoreconf -f -i
./configure
make
make install
ln -s /usr/local/lib/libmpfr.so /usr/lib/arm-linux-gnueabihf/libmpfr.so.4
cd ../..
source setup_env.sh
make
cd patches/bcm43430a1/7_45_41_46/nexmon/
make
make backup-firmware
make install-firmware
cd ../../../../utilities/nexutil/
make && make install
apt-get remove wpasupplicant
iw dev wlan0 set power_save off

# Make the RPI3 load the modified driver after reboot
mv /lib/modules/$kernel/kernel/drivers/net/wireless/broadcom/brcm80211/brcmfmac/brcmfmac.ko.xz /lib/modules/$kernel/kernel/drivers/net/wireless/broadcom/brcm80211/brcmfmac/brcmfmac.ko.xz.orig
cp /home/pi/nexmon/patches/driver/brcmfmac_6.1.y-nexmon/brcmfmac.ko /lib/modules/$kernel/kernel/drivers/net/wireless/broadcom/brcm80211/brcmfmac/
cd /lib/modules/$kernel/kernel/drivers/net/wireless/broadcom/brcm80211/brcmfmac/
xz brcmfmac.ko

reboot