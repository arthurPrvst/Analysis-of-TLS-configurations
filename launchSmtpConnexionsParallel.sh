 #!/usr/bin/env bash
echo --- LAUNCHING CONNECTIONS ---

cat ./MailServers/listeIpWithoutDuplicate.txt | parallel --no-notice -j0 --workdir $PWD ./smtpConnexions.sh

echo ALL CONNECTIONS HAS BEEN ESTABLISHED

exit 0

