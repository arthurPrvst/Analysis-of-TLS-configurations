<?php
require_once __DIR__ . '/CipherSuite.class.php';
require_once __DIR__ . '/DNS.class.php';

class LecteurWireshark
{
    private $nomFichierCsv = null;
    //private $nomFichierListeIpDns = null;
    private $row = 1;
    private $array = null;
    private $NbServeurs = 0;
    private $cipherSuites = array();
    private $allDns = array();  //array of DNS objects (represented with a DNS name, an array of IP Addresses and an array of cipherSuites)
    private $allReadyDone = array(); // look's like $currentIP."|".$currentDNs

    //TLS versions
    private $ssl2 = 0;
    private $ssl3 = 0;
    private $tls10 = 0;
    private $tls11 = 0;
    private $tls12 = 0;


    //KeyExchange Algorithms
    private $rsa = 0;
    private $dhe = 0;
    private $ecdhe = 0;
    private $ecdh = 0;
    private $dh = 0;

    //Authentification (signature algorithms)
    private $rsa_signature = 0;
    private $ecdsa_signature = 0;
    private $dss_signature = 0;


    //Cipher
    private $troisdesEde = 0;
    private $aes128 = 0;
    private $aes256 = 0;
    private $camellia256 = 0;
    private $rc4 = 0;
    private $seed = 0;
    private $idea = 0;

    //Bloc Modes
    private $cbc = 0;
    private $gcm = 0;
    private $aes128CBC = 0;
    private $aes256CBC = 0;
    private $aes128GCM = 0;
    private $aes256GCM = 0;

    //Hash functions
    private $sha = 0;
    private $md5 = 0;
    private $sha256 = 0;
    private $sha384 = 0;

    //allow Export
    private $export = 0;

    //allow Compression
    private $compression = 0;

    //Extensions
    private $renego = 0;
    private $ecPointFormat = 0;
    private $sessionTicket = 0;
    private $heartbeatExtension = 0;
    private $elliptic_curves = 0;
    private $signatureAlgo = 0;
    private $server_name = 0;

    private $assoDnsIndex = array();

    //Cluster of cipher suites
    private $nbHigh = 0; //green
    private $nbMedium = 0; //orange
    private $nbLow = 0; //red
    private $mustnotClass = ['_DES_','NULL','MD5','RC4' ,'EXPORT','EXP','CK','PSK','FIPS','RC2','KRB5','SSL'];     //Attribute of MUST NOT CLASS
    private $shouldnotClass = ['SEED', '3DES', 'IDEA','SHA_','TLS_RSA','ADH','AECDH','ADHE','SCSV','AECDHE'];     //Attribute of SHOULD NOT CLASS


    public function __construct($nomFichierCsv)
    {
        $this->nomFichierCsv = $nomFichierCsv;
        $this->read($this->nomFichierCsv);
        foreach ($this->getCipherSuites() as $cipherobj) {
            $this->computeCluster($cipherobj);
        }
    }

    /**
     * Parsing the csv file given in parameter
     */
    public function read($nom)
    {
        if (($handle = fopen($nom, "r")) !== FALSE) {

            $data = fgetcsv($handle, 1000, ";"); //skip the first line
            $y = 0;
            $nbClientHello = 0;
            $nbDns = 0;
            while (($data = fgetcsv($handle, 1000, ";")) !== FALSE) {
                $cipher = "";
                $y++;

                for ($i = 0; $i < count($data); $i++) {//optimisation
                    $data[$i] = strtoupper($data[$i]);
                }

                if (count($data) >= 13 && $data[2] == "CLIENTHELLO") { // LOOK CLIENTHELLO
                    $tab = explode(":", $data[12]);
                    $nbClientHello++;

                    if (count($tab) == 2) {
                        $nomDeDomaine = $tab[1];
                        $addresseIp = $data[1];

                        if (!array_key_exists($nomDeDomaine, $this->assoDnsIndex)) { //if this DNS name doesn't exists
                            $this->assoDnsIndex[$nomDeDomaine] = $nbDns;
                            array_push($this->allDns, new DNS($nomDeDomaine, $addresseIp)); // ... we create it
                            $nbDns++;
                        } else {
                            $index = $this->assoDnsIndex[$nomDeDomaine];
                            $this->allDns[$index]->setIp($addresseIp); // ... we add to this DNS an other ip address
                        }
                    }

                } elseif (count($data) >= 12 && $data[2] == "SERVERHELLO") { // LOOK SERVERHELLO / //AKA has all mandatory informations to parse (extensions not needed)
                    $this->NbServeurs = $this->NbServeurs + 1;

                    //BEGIN PARSING ---------------------------------------------------------------
                    $currentIp = $data[0];
                    $cipher .= $this->parseProtoVersion($data[3]);
                    $cipher .= "_" . $data[4];
                    $isRSAorNot = $this->parseKeyExchangeAlgo($data[4]);
                    $res = $this->parseSignature($data[5], $isRSAorNot);
                    $cipher .= $res;

                    $this->parseExport($data[6]);
                    $cipher .= "_" . "WITH_" . $data[7];
                    $wasAesOrCamellia = $this->parseCipher($data[7]);   //WAS AES if $wasAesOrCamellia==1    // WAS CAMELLIA if $wasAesOrCamellia == 2
                    $cipher .= "_" . $data[8];
                    $wasAes128OrAes256 = $this->parseLength($data[8], $wasAesOrCamellia);
                    $cipher .= "_" . $data[9];
                    $this->parseBlockMode($data[9], $wasAes128OrAes256);
                    $isSHA1 = $this->parseHashFunction($data[10]);
                    if ($isSHA1 == "0") { //NOT SHA
                        $cipher .= "_" . $data[10];
                    } else { //SHA
                        $cipher .= "_" . $data[10] . "_";
                    }
                    $this->parseCompression($data[11]);
                    $this->parseExtension($data);

                    //END PARSING -------------------------------------------------------------------

                    if ($cipher != "_") {
                        $allreadySaved = 0;
                        foreach ($this->cipherSuites as $cipherSuiteObj) {      // <------------ Sauvegarde CipherSuite
                            if (($cipherSuiteObj->getNomCipherSuite()) == $cipher) {
                                $cipherSuiteObj->incrementThisCipher();
                                $allreadySaved = 1;
                                break;
                            }
                        }
                        //L'ajoute dans le tableau cipherSuites si il n'existe pas
                        if ($allreadySaved == 0) {
                            $cip = new CipherSuite($cipher);
                            array_push($this->cipherSuites, $cip);
                        }

                        $currentDns = "";
                        if ($nbClientHello >= 30) {
                            for ($i = $nbDns - 1; $i >= $nbDns - 30; $i--) { //regarde seulement les 30 derniers sauvegardés
                                $dnsObj = $this->allDns[$i];
                                if (array_key_exists($currentIp, $dnsObj->getIps()) && !array_key_exists($currentIp . "|" . $dnsObj->getNom(), $this->allReadyDone)) {
                                    $dnsObj->setCiphers($cipher);
                                    $currentDns = $dnsObj->getNom();
                                    break;
                                }
                            }
                        } else {
                            for ($i = 0; $i < $nbClientHello; $i++) {
                                $dnsObj = $this->allDns[$i];
                                if (array_key_exists($currentIp, $dnsObj->getIps()) && !array_key_exists($currentIp . "|" . $dnsObj->getNom(), $this->allReadyDone)) {
                                    $dnsObj->setCiphers($cipher);
                                    $currentDns = $dnsObj->getNom();
                                    break;
                                }
                            }
                        }

                        $done = $currentIp . "|" . $currentDns;
                        $this->allReadyDone[$done] = 1;

                    } else {
                        $this->NbServeurs = $this->NbServeurs - 1;
                    }
                } //END OF HELLO PAQUET
                unset($data);
            } //END WHILE LOOP
            fclose($handle);
        } //END OPENNING FILE

    }

    public function generateVariablesArray()
    {
        $res = array();
        array_push($res, $this->getNbServeurs());
        array_push($res, $this->getSsl2());
        array_push($res, $this->getSsl3());
        array_push($res, $this->getTls10());
        array_push($res, $this->getTls11());
        array_push($res, $this->getTls12());

        array_push($res, $this->getRsa());
        array_push($res, $this->getDhe());
        array_push($res, $this->getEcdhe());
        array_push($res, $this->getEcdh());

        array_push($res, $this->getTroisdesEde());
        array_push($res, $this->getAes128());
        array_push($res, $this->getAes256());
        array_push($res, $this->getCamellia256());
        array_push($res, $this->getRc4());
        array_push($res, $this->getSeed());
        array_push($res, $this->getIdea());

        array_push($res, $this->getCbc());
        array_push($res, $this->getGcm());

        array_push($res, $this->getMd5());
        array_push($res, $this->getSha());
        array_push($res, $this->getSha256());
        array_push($res, $this->getSha384());

        array_push($res, $this->getExport());

        array_push($res, $this->getCompression());
        array_push($res, $this->getRenego());
        array_push($res, $this->getHeartbeatExtension());
        array_push($res, $this->getSessionTicket());
        array_push($res, $this->getEcPointFormat());
        array_push($res, $this->getEllipticCurves());
        array_push($res, $this->getSignatureAlgo());
        array_push($res, $this->getServerName());

        return $res;
    }

    public function writeDNSandCipher()
    {

        $dnsFile = fopen("./resultWireshark/dnsPHP.txt", 'a+');
        $concatDns = "";
        foreach ($this->allDns as $dnsObj) {      // <------------ Sauvegarde DNS
            $concatDns = $dnsObj->getNom() . "/";
            foreach ($dnsObj->getCiphers() as $cipher) {
                $concatDns .= " " . $cipher;
            }
            $concatDns .= "/" . $dnsObj->getNbCipherOfThisDns() . "\n";
            fwrite($dnsFile, $concatDns);
        }
        fclose($dnsFile);


        $cipherFile = fopen("./resultWireshark/cipherPHP.txt", 'a+');
        foreach ($this->cipherSuites as $cipherSuiteObj) {      // <------------ Sauvegarde CipherSuite
            $concat = $cipherSuiteObj->getNomCipherSuite() . ":" . $cipherSuiteObj->getCountOfThisCipher() . "\n";
            fwrite($cipherFile, $concat);
        }
        fclose($cipherFile);
    }

    public function parseProtoVersion($data)
    {
        if (strpos($data, "TLS 1.2") !== FALSE) {
            $this->tls12 = $this->tls12 + 1;
            return "TLS";
        } elseif (strpos($data, "TLS 1.0") !== FALSE) {
            $this->tls10 = $this->tls10 + 1;
            return "TLS";
        } elseif (strpos($data, "TLS 1.1") !== FALSE) {
            $this->tls11 = $this->tls11 + 1;
            return "TLS";
        } elseif (strpos($data, "SSL 3.0") !== FALSE) {
            $this->ssl3 = $this->ssl3 + 1;
            return "SSL";
        } elseif (strpos($data, "SSL 2.0") !== FALSE) {
            $this->ssl2 = $this->ssl2 + 1;
            return "SSL";
        }
        return 0;
    }

    public function parseKeyExchangeAlgo($data)
    {
        if (strpos($data, "ECDHE") !== FALSE) {
            $this->ecdhe = $this->ecdhe + 1;
            return 0;
        } elseif (strpos($data, "DHE") !== FALSE) {
            $this->dhe = $this->dhe + 1;
            return 0;
        } elseif (strpos($data, "RSA") !== FALSE) {
            $this->rsa = $this->rsa + 1;
            return 1; //say that it was RSA
        } elseif (strpos($data, "ECDH") !== FALSE) {
            $this->ecdh = $this->ecdh + 1;
            return 0;
        } elseif (strpos($data, "DH") !== FALSE) {
            $this->dh = $this->dh + 1;
            return 0;
        }
        return 0;
    }

    function parseSignature($data, $isRSAorNot)
    {
        $res = "";
        if (strpos($data, "RSA") !== FALSE) {
            $res .= "_" . $data;
            $this->rsa_signature = $this->rsa_signature + 1;
        } elseif ($isRSAorNot == 1) { //if it is RSA key exchange algo
            $this->rsa_signature = $this->rsa_signature + 1;
        } elseif (strpos($data, "ECDSA") !== FALSE) {
            $res .= "_" . $data;
            $this->ecdsa_signature = $this->ecdsa_signature + 1;
        } elseif (strpos($data, "DSS") !== FALSE) {
            $res .= "_" . $data;
            $this->dss_signature = $this->dss_signature + 1;
        }
        return $res;
    }

    public function parseExport($data)
    {
        if (!(strpos($data, "_") !== FALSE)) {
            $this->export = $this->export + 1;
        }
    }

    public function parseCipher($data)
    {
        if (strpos($data, "AES") !== FALSE) {
            return 1; //WAS AES
        } elseif (strpos($data, "3DES") !== FALSE) {
            $this->troisdesEde = $this->troisdesEde + 1;
        } elseif (strpos($data, "CAMELLIA") !== FALSE) {
            return 2; //WAS CAMELLIA
        } elseif (strpos($data, "RC4") !== FALSE) {
            $this->rc4 = $this->rc4 + 1;
        } elseif (strpos($data, "SEED") !== FALSE) {
            $this->seed = $this->seed + 1;
        } elseif (strpos($data, "IDEA") !== FALSE) {
            $this->idea = $this->idea + 1;
        }
        return 0; //Was something standard
    }

    function parseLength($data, $wasAesCamellia)
    {
        if ((strpos($data, "256") !== FALSE)) {
            if ($wasAesCamellia == 1) { //was AES
                $this->aes256 = $this->aes256 + 1;
                return 2; //was aes256
            } elseif ($wasAesCamellia == 2) { // was CAMELLIA
                $this->camellia256 = $this->camellia256 + 1;
                return 0;
            }
        } elseif ((strpos($data, "128") !== FALSE)) {
            if ($wasAesCamellia == 1) { //was AES
                $this->aes128 = $this->aes128 + 1;
                return 1; //was aes128
            }
        }
        return 0;
    }

    function parseBlockMode($data, $aes128Oraes256)
    {
        if ((strpos($data, "GCM") !== FALSE)) {
            if ($aes128Oraes256 == 1) {
                $this->aes128GCM = $this->aes128GCM + 1;
            } elseif ($aes128Oraes256 == 2) {
                $this->aes256GCM = $this->aes256GCM + 1;
            }
            $this->gcm = $this->gcm + 1;
        } elseif ((strpos($data, "CBC") !== FALSE)) {
            if ($aes128Oraes256 == 1) {
                $this->aes128CBC = $this->aes128CBC + 1;
            } elseif ($aes128Oraes256 == 2) {
                $this->aes256CBC = $this->aes256CBC + 1;
            }
            $this->cbc = $this->cbc + 1;
        }
    }

    function parseHashFunction($data)
    {
        if ((strpos($data, "SHA384") !== FALSE)) {
            $this->sha384 = $this->sha384 + 1;
            return "0";
        } elseif ((strpos($data, "SHA256") !== FALSE)) {
            $this->sha256 = $this->sha256 + 1;
            return "0";
        } elseif ((strpos($data, "SHA") !== FALSE)) {
            $this->sha = $this->sha + 1;
            return "1";
        } elseif ((strpos($data, "MD5") !== FALSE)) {
            $this->md5 = $this->md5 + 1;
            return "0";
        }
        return 0;
    }

    function parseCompression($data)
    {
        if (!(strpos($data, "NO") !== FALSE)) {
            $this->compression = $this->compression + 1;
        }
    }

    function parseExtension($data)
    {
        $lengthOfArray = count($data);

        if ($lengthOfArray > 12) { // There is some extensions
            $length = min($lengthOfArray, 20);
            for ($i = 12; $i < $length; $i++) {
                if ((strpos($data[$i], "SESSIONTICKET") !== FALSE)) {
                    $this->sessionTicket = $this->sessionTicket + 1;
                } elseif ((strpos($data[$i], "EC_POINT_FORMATS") !== FALSE)) {
                    $this->ecPointFormat = $this->ecPointFormat + 1;
                } elseif ((strpos($data[$i], "HEARTBEAT") !== FALSE)) {
                    $this->heartbeatExtension = $this->heartbeatExtension + 1;
                } elseif ((strpos($data[$i], "SERVER_NAME") !== FALSE)) {
                    $this->server_name = $this->server_name + 1;
                } elseif ((strpos($data[$i], "RENEGOTIATION_INFO") !== FALSE)) {
                    $this->renego = $this->renego + 1;
                } elseif ((strpos($data[$i], "ELLIPTIC_CURVES") !== FALSE)) {
                    $this->elliptic_curves = $this->elliptic_curves + 1;
                } elseif ((strpos($data[$i], "SIGNATURE_ALGORITHMS") !== FALSE)) {
                    $this->signatureAlgo = $this->signatureAlgo + 1;
                }
            }
        }
    }

    public function computeCluster($cipherobj)
    {
        $isLow = 0;
        $isMedium = 0;
        foreach ($this->mustnotClass as $element) {
            if (strpos($cipherobj->toString(), $element) !== FALSE) {
                $this->nbLow = $this->nbLow + $cipherobj->getCountOfThisCipher();
                $isLow = 1;
                break;
            }
        }
        if($isLow == 0) {
            foreach ($this->shouldnotClass as $element) {
                if (strpos($cipherobj->toString(), $element) !== FALSE) {
                    $this->nbMedium = $this->nbMedium + $cipherobj->getCountOfThisCipher();
                    $isMedium = 1;
                    break;
                }
            }
        }

        if($isLow == 0 && $isMedium == 0) { //n'est ni low ni medium
            $this->nbHigh = $this->nbHigh + $cipherobj->getCountOfThisCipher();
        }
    }

    /**
     * @return int
     */
    public function getNbHigh()
    {
        return $this->nbHigh;
    }

    /**
     * @return int
     */
    public function getNbMedium()
    {
        return $this->nbMedium;
    }

    /**
     * @return int
     */
    public function getNbLow()
    {
        return $this->nbLow;
    }

    /**
     * @return int
     */
    public function getAes128CBC()
    {
        return $this->aes128CBC;
    }

    /**
     * @return int
     */
    public function getAes256CBC()
    {
        return $this->aes256CBC;
    }

    /**
     * @return int
     */
    public function getAes128GCM()
    {
        return $this->aes128GCM;
    }

    /**
     * @return int
     */
    public function getAes256GCM()
    {
        return $this->aes256GCM;
    }


    /**
     * @return int
     */
    public function getRsaSignature()
    {
        return $this->rsa_signature;
    }

    /**
     * @return int
     */
    public function getEcdsaSignature()
    {
        return $this->ecdsa_signature;
    }

    /**
     * @return int
     */
    public function getDssSignature()
    {
        return $this->dss_signature;
    }

    /**
     * @return int
     */
    public function getNbDNSwithDiffConfig()
    {
        $res = 0;
        foreach ($this->allDns as $dnsObj) {
            if ($dnsObj->getNbDiffCipherOfThisDns() > 1) {
                $res = $res + 1;
            }
        }
        return $res;
    }

    public function getAverageNbOfMxPerDns()
    {
        $res = 0;
        foreach ($this->allDns as $dnsObj) {
            $res = $res + count($dnsObj->getIps());
        }
        $res = $res / count($this->allDns);
        return number_format($res, 2);
    }

    /**
     * @return array
     */
    public function getAllDns()
    {
        return $this->allDns;
    }

    /**
     * @return int
     */
    public function getRc4()
    {
        return $this->rc4;
    }

    /**
     * @return int
     */
    public function getSeed()
    {
        return $this->seed;
    }

    /**
     * @return int
     */
    public function getIdea()
    {
        return $this->idea;
    }

    /**
     * @return int
     */
    public function getCompression()
    {
        return $this->compression;
    }

    /**
     * @return int
     */
    public function getRenego()
    {
        return $this->renego;
    }

    /**
     * @return int
     */
    public function getEcPointFormat()
    {
        return $this->ecPointFormat;
    }

    /**
     * @return int
     */
    public function getEllipticCurves()
    {
        return $this->elliptic_curves;
    }

    /**
     * @return int
     */
    public function getSignatureAlgo()
    {
        return $this->signatureAlgo;
    }

    /**
     * @return int
     */
    public function getSessionTicket()
    {
        return $this->sessionTicket;
    }

    /**
     * @return int
     */
    public function getHeartbeatExtension()
    {
        return $this->heartbeatExtension;
    }

    /**
     * Fonction qui affiche le resultat du parsage
     */
    function displayCiphers()
    {//Affichage
        foreach ($this->cipherSuites as $cipher) {
            $res = $cipher->toString();
            echo $res . " ==> <b>" . ($cipher->getCountOfThisCipher()) * 100 / $this->NbServeurs . "%</b></br>";
        }
    }

    /**
     * @return int
     */
    public function getNbServeurs()
    {
        return $this->NbServeurs;
    }

    /**
     * @return int
     */
    public function getSsl2()
    {
        return $this->ssl2;
    }

    /**
     * @return int
     */
    public function getSsl3()
    {
        return $this->ssl3;
    }

    /**
     * @return int
     */
    public function getTls10()
    {
        return $this->tls10;
    }

    /**
     * @return int
     */
    public function getTls11()
    {
        return $this->tls11;
    }

    /**
     * @return int
     */
    public function getTls12()
    {
        return $this->tls12;
    }

    /**
     * @return int
     */
    public function getRsa()
    {
        return $this->rsa;
    }

    /**
     * @return int
     */
    public function getDhe()
    {
        return $this->dhe;
    }

    /**
     * @return int
     */
    public function getEcdhe()
    {
        return $this->ecdhe;
    }

    /**
     * @return int
     */
    public function getTroisdesEde()
    {
        return $this->troisdesEde;
    }

    /**
     * @return array
     */
    public function getCipherSuites()
    {
        return $this->cipherSuites;
    }

    /**
     * @return int
     */
    public function getAes128()
    {
        return $this->aes128;
    }

    /**
     * @return int
     */
    public function getAes256()
    {
        return $this->aes256;
    }

    /**
     * @return int
     */
    public function getCamellia256()
    {
        return $this->camellia256;
    }

    /**
     * @return int
     */
    public function getCbc()
    {
        return $this->cbc;
    }

    /**
     * @return int
     */
    public function getGcm()
    {
        return $this->gcm;
    }

    /**
     * @return int
     */
    public function getSha()
    {
        return $this->sha;
    }

    /**
     * @return int
     */
    public function getMd5()
    {
        return $this->md5;
    }

    /**
     * @return int
     */
    public function getSha256()
    {
        return $this->sha256;
    }

    /**
     * @return int
     */
    public function getSha384()
    {
        return $this->sha384;
    }

    /**
     * @return int
     */
    public function getExport()
    {
        return $this->export;
    }

    /**
     * @return int
     */
    public function getServerName()
    {
        return $this->server_name;
    }

    /**
     * @return int
     */
    public function getEcdh()
    {
        return $this->ecdh;
    }

}
