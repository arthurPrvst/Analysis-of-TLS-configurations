#!/usr/bin/env bash

cat ./MailServers/listeIpWithoutDuplicate.txt | parallel --no-notice -j0 --workdir $PWD ./boucleDeux.sh

exit 0
