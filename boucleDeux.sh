#!/usr/bin/env bash

port=":25"
nbInconnu=0

ligne=$1

    ligneIp=$(echo $ligne | tr "|" "\n")	
    ip=($ligneIp)
    ipPort=$ip$port
    dns=$(echo $ligneIp |cut -f 2 -d ' ')
    
    #ciphersuites list without good ones (
    ciphers=$(openssl ciphers 'ALL:eNULL:COMPLEMENTOFALL:EXP:EXPORT:EXPORT40:EXPORT56:SSLv2:SSLv3' | sed -e 's/:/ /g')

    for cipher in ${ciphers[@]}
    do
        if [[ $nbInconnu < 4 ]] ; then
            echo -n Test $ligneIp " : " $cipher...
            
            result=$(echo -n | timeout 15s openssl s_client -starttls smtp -cipher "$cipher" -connect $ipPort -servername $dns 2>&1) #no answer after within 15 sec => FAIL

            if [[ "$result" =~ ":error:" ]] ; then
            error=$(echo -n $result | cut -d':' -f6)
            echo NO \($error\)
            let "nbInconnu=0"
            else
                if [[ "$result" =~ "Cipher is ${cipher}" || "$result" =~ "Cipher    :" ]] ; then
                    echo OUI
                    let "nbInconnu=0"
                    echo $ligneIp " : " $cipher >> resultDeprecatedCipherParallel.txt
                else
                    echo UNKNOWN RESPONSE
                    let "nbInconnu++" #incrementation
                    echo $nbInconnu
                    echo $result
                fi
            fi
        else
          let "nbInconnu=0"
          break
        fi
    done 

 
