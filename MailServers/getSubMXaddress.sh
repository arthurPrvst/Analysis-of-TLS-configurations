#!/bin/bash

#Empty files
>listeSansChariot.txt
>listeIp.txt
>temp.txt
#Save MX paquet from the DNS query
fileSource="targetDomainNames.txt"
fileTemp="temp.txt"
varSeparateur="|"
IFS=$'\n'       #field separator
tr -d '\r' < top1m.csv > topMillionSansChariot.txt #remove carriage return




for ligne in $(<$fileSource)
do  
    # ---------- RECOVERING NAMES -----------------------------------------
    varRes=$(dig +short $ligne MX) 
    for word in $varRes
    do
	echo $word | cut -d' ' -f2- >>temp.txt
    done
    # ---------------------------------------------------------------------------


    # ----------- RECOVERING IP ADSRESS FOREACH NAME ------------
	for nom in $(<$fileTemp)
	do  
	  varAddresseIp=$(dig +short $nom)
          arr=($varAddresseIp)
	  for i in "${arr[@]}"
	  do
	        varPremiereIp=$i
		if [[ $varPremiereIp =~ ^[0-9]+.*$ ]]; then
		#est bien uen adresse IP
			echo $varPremiereIp$varSeparateur$ligne
		  	echo $varPremiereIp$varSeparateur$ligne >> listeIp.txt 
		 fi
		 
	  done	
	done
    #------------------------------------------------------------------------------
    #nslookup -q=mx $ligne >> listeIp.txt

    >temp.txt	
done

#---------- Deleting duplicates ----------------------
cat "listeIp.txt" |sort | uniq > listeIpWithoutDuplicate.txt

exit 0
