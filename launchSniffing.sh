#!/bin/bash

echo --- SNIFFING NETWORK WITH WIRESHARK---

#We empty the previous file
>sauvegarde.pcap

#STart sniffing the network in order to recover connections
tshark -w ./sauvegarde.pcap
echo --- PCAP FILE SAVED ---
exit 0
