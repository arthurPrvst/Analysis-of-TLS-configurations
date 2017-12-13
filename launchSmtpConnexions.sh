#!/bin/bash

echo --- LAUNCHING CONNECTIONS ---

#Recovery of mail servers that has been found thanks to DNS's MX fields
fichier="./MailServers/listeIpWithoutDuplicate.txt"
IFS=$'\n'       #field separator 

for ligne in $(<$fichier)
do
   ligneIp=$(echo $ligne | tr "|" "\n")	
   ip=($ligneIp)
   dns=$(echo $ligneIp |cut -f 2 -d ' ')
   openssl s_client -starttls smtp -connect $ip:25 -servername $dns & < /dev/null #no more input after the connection
   sleep 1;
done

echo ALL CONNECTIONS HAS BEEN ESTABLISHED

exit 0
