# Analysis-of-TLS-configurations

Analysis of SSL/TLS configurations on mail servers.
These analysis on mail servers has been done on Cisco's server list, in order to have a global vision of how the TLS protocol is used among smtp servers.
I am the co-author of an article in MISC computer security magazine (MISC n°96). This article presents all my results and their analysis. [See the MISC article](https://boutique.ed-diamond.com/anciens-numeros/1304-misc-96.html). 

## How to run your own experiment
### Recovering a set of servers
First of all, you have to recover a list of servers. For mail servers, this can be done sendind DNS queries on domain name.
You can use for example the tool [dig](http://manpages.ubuntu.com/manpages/precise/man1/dig.1.html).
If you are working with domain name with several mail servers, you should shuffle your list in order to be as discret as possible during your future tests.

You can also use the script ```getSubMXaddress.sh``` in the folder "MailServers".

### Simulation of a client connection
This explain can launch "normal" connections to servers. Thanks to that, you will be able to know which ciphersuites, TLS version, extensions and compression if any, has been chosen during the TLS handshake with a server.

Before starting any connection with TLS, you should start sniffing the network in order to capture paquets you need. Use the script ```launchSniffing.sh```. Output from wireshark (or rather tshark in our case) is saved in the file sauvegarde.pcap

You are now able to launch connections. You can use ```launchSmtpConnexions.sh``` or ```launchSmtpConnexionsParallel.sh``` if you want to launch a TLS connection on a huge server list (this script use [GnuParallel](https://www.gnu.org/software/parallel/)).

Once connections are done, you have to parse a first time sauvegarde.pcap in order to filter only ClientHello and ServerHello paquets : launch ```filter.sh```. Once done, a file called resultExcelWireshark.csv is created. You can know use the [Gawk](https://www.gnu.org/software/gawk/) parser ```parserAwk```. After this step, you have all information needed in a .csv file. If you want to display these result on a webpage with diagrams, use a web server and launch ```index.php``` witch is in the folder "WebDisplay".

### Recovering all cipher suites allowed by servers
The purpose of this section is to discover whether or not, a server accept deprecated cipher suites. In order to propose bad cipher suites one by one to a server in order to know if the server accepts it, you have to recompile an older openssl version (which contain bad cipher suites with DES, RC4, EXPORT ...). I recompiled OpenSSL 1.0.2 from January 2015 for my test. It his available of the folder "OpenSSL\_Recompiled".

You can now launch connections with an not up to date openssl version. As the previous step, you can use ```launchDeprecatedCiphers.sh``` or ```launchDeprecatedCiphersParallel.sh``` if you want to launch a TLS connection on a huge server list (this script use [GnuParallel](https://www.gnu.org/software/parallel/)). 

Results are available in the file "resultDeprecatedCipher.txt" and you can you my PHP parser to display results with diagramms on a webpage. Use a web server and launch ```index.php``` witch is in the folder "webDisplay".


### Test vulnerability of servers with [testssl.sh](https://testssl.sh/)
First of all, download [testssl.sh](https://github.com/drwetter/testssl.sh/) and put it into the "TestVulnerabilty" folder.
In order to test vulnerability of servers and their behavior, you can use the script ```launchTestMXParallelbehavior.sh``` available in the "TestVulnerabily" folder.
By behavior, I mean the behavior that a server can have facing a client connection. Here are the two possible behaviors :
1. The server scans the list provided by the client and chooses the first cipher suite it supports. In this case, we say that the server’s behavior is "courteous".
2. The server goes through its list of preferences and takes the first sequence
Which is in the client list. In this second case, we say that the server’s
behavior is "directive".

Result are available in the ```result.csv file```. As always ou can you my PHP parser to display results with diagramms on a webpage. Use a web server and launch ```index.php``` witch is in the folder "webDisplay".

## Hierarchy of folders

* Current folder : contains all scripts to launch connections with TLS, and contains Gawk parser.
* MailServers folder : contains the script to get ip adress of smtp servers, and contains files containing ip adresses, domain names...
* TestVulnerabilty folder : contains script to launch testssl.sh and get vulnerability and behaviors of servers.
* WebDisplay folder : contains all PHP classes that parse and display data.
* OpenSSL_Recompiled folder : contains openssl 1.0.2

## Further informations

* Get smtp servers : ```dig +short domainname MX``` and then ```dig +short name```
* Get the version of openssl : ```openssl version```
* Get all cipher suites available in openssl : ```openssl ciphers -v```
* Launch connection on a smtp server : ```openssl s_client -connect -starttls smtp ipaddress:25 -servername name```
* Recompile openssl - [Click here](https://askubuntu.com/questions/893155/simple-way-of-enabling-sslv2-and-sslv3-in-openssl)


## Authors

* **Arthur Provost** 


## License

This project is licensed under the MIT License.


## Acknowledgments

* Olivier Levillain (ANSSI)
* Gildas Avoine (EMSEC research team at IRISA)
* Cristina Onete
