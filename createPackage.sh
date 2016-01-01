#!/bin/bash
#run this script as sudo

cd knockserver-1.0 && find * -type f ! -regex '^DEBIAN/.*' -exec md5sum {} \; > DEBIAN/md5sums
cd ../ && dpkg-deb -b knockserver-1.0/ knockserver-1.0_amd64.deb
