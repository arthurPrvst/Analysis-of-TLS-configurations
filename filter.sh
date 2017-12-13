#!/bin/bash

echo --- FILTRAGE QUI NE GARDE QUE CLIENT/SERVER HELLO ---
echo --- Resultats dans plaintextResult.txt ---
>plaintextResult.txt
>resultExcelWireshark.csv

tshark -r ./sauvegarde.pcap -V ssl.handshake.type in {1 2} > plaintextResult.txt
echo --- Parsing with Awk resultExcelWireshark ---
awk -f parserAwk plaintextResult.txt > resultExcelWireshark.csv
echo --- SUCCESS ---
exit 0
