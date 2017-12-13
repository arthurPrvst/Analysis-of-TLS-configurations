#!/usr/bin/env bash

fichier="./MailServers/listeIpWithoutDuplicate.txt"
port=":25"
>resultDeprecatedCipher.txt
nbInconnu=0
echo Cipher list de $(openssl version).

for ligne in $(<$fichier)
do
    ligneIp=$(echo $ligne | tr "|" "\n")	
    ip=($ligneIp)
    ipPort=$ip$port
    dns=$(echo $ligneIp |cut -f 2 -d ' ')
    
    #ciphersuites list without good ones
    ciphers=$(openssl ciphers 'ALL:!HIGH:eNULL:COMPLEMENTOFALL:EXP:EXPORT:EXPORT40:EXPORT56:SSLv2:SSLv3' | sed -e 's/:/ /g')

    for cipher in ${ciphers[@]}
    do
        if [[ $nbInconnu < 4 ]] ; then
            echo -n Test $ligneIp " : " $cipher...
            
            result=$(echo -n | timeout 10s openssl s_client -starttls smtp -cipher "$cipher" -connect $ipPort -servername $dns 2>&1) #No response within 15sec => FAIL

            if [[ "$result" =~ ":error:" ]] ; then
            error=$(echo -n $result | cut -d':' -f6)
            echo NO \($error\)
            let "nbInconnu=0"
            else
                if [[ "$result" =~ "Cipher is ${cipher}" || "$result" =~ "Cipher    :" ]] ; then
                    echo OUI
                    let "nbInconnu=0"
                    echo $ligneIp " : " $cipher >> resultDeprecatedCipher.txt
                else
                    echo UNKNOWN RESPONSE
                    let "nbInconnu++"
                    echo $nbInconnu
                    echo $result
                fi
            fi
        else
          let "nbInconnu=0"
          break
        fi
    done 
done

exit 0
