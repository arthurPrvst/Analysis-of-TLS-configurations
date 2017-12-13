<?php
require_once __DIR__ .'/CipherSuite.class.php';

class LecteurTestssl
{
    private $nomFichierCsv = null;
    private $row = 1;
    private $array = null;
    private $cipherSuites = array();

//NB DE SERVEURS TESTÉS
    private $nbServ = 0;


//VERSION MINIMALE ACCEPTÉE PAR SERVEURS
    private $NbVminSSL2 = 0;
    private $NbVminSSL3 = 0;
    private $NbVminTLS1 = 0;
    private $NbVminTLS11 = 0;
    private $NbVminTLS12 = 0;
    private $versionDejaFait = 0;

//TYPE DE CIPHER ACCEPTÉS
    private $cipherNull = 0;
    private $anonymCipherNull = 0;
    private $anonymCipherDH = 0;
    private $cipherLowInf64bits = 0;
    private $cipherDES = 0;
    private $cipher3DES = 0;
    private $courtoi = 0;
    private $cipherExport = 0;
    private $cipherExport40bits = 0;
    private $cipherExport56bits = 0;

//EXTENSIONS ACCEPTÉS PAR SERVEUR
    private $renego = 0;
    private $ecPointFormat = 0;
    private $sessionTicket = 0;
    private $heartbeatExtension = 0;


//FONCTIONS DE HACHAGE PROPOSÉES
    private $sha384 = 0;
    private $sha256 = 0;
    private $sha = 0;
    private $md5 = 0;

//CIPHER PROPOSÉS
    private $proposeAes256 = 0;
    private $proposeAes128 = 0;
    private $proposeRC4 = 0;
    private $propose3DES = 0;
    private $proposeCamellia256 = 0;

//LONGUEURS DE CLÉS PROPOSÉES
    private $proposeLongueur2048 = 0;
    private $proposeLongueur1024 = 0;

//PROTOCOLE PROPOSÉS PAR SERVEUR
    private $protocolProposeSSL2 = 0;
    private $protocolProposeSSL3 = 0;
    private $protocolProposeTLS1 = 0;
    private $protocolProposeTLS11 = 0;
    private $protocolProposeTLS12 = 0;
    private $protocolProposePourCetteInstance = "0";

//MODE PROPOSÉS PAR SERVEUR
    private $proposeCBC = 0;
    private $proposeGCM = 0;

//SERVEURS SENSIBLES A CES ATTAQUES
    private $heartbeatAttaque = 0;
    private $cssAttaque = 0;
    private $secure_renegoAttaque = 0;
    private $sec_client_renegoAttaque = 0;
    private $crimeAttaque = 0;
    private $poodleAttaque = 0;
    private $fallback_scsvAttaque = 0;
    private $freakAttaque = 0;
    private $drownAttaque = 0;
    private $logjamAttaque = 0;
    private $cbc_tls1 = 0;
    private $cbc_ssl3 = 0;
    private $beastAttaque = 0;
    private $rc4Attaque = 0;


    public function __construct($nomFichierCsv)
    {
        $this->nomFichierCsv=$nomFichierCsv;
        $this->read();
    }

    /**
     * fonction qui parse le fichier csv donné en parametre
     */
    public function read()
    {
        if (($handle = fopen($this->nomFichierCsv, "r")) !== FALSE) {

            while (($data = fgetcsv($handle, 1000, ",")) !== FALSE) {
		
		if(isset($data[3])) {
                $severity = $data[3]; //optimisation
		}else{
		$severity = "";
		}

                if(isset($data[4])) {
                    $comments = $data[4];
                }else{
                    $comments = "";
                }

                switch ($data[0]) {
                    //VERSION MINI DU PROTOCOL ACCEPTÉE
                    /*case "sslv2":
                        if ($severity != "OK") {
                            $this->NbVminSSL2++;
                            $this->versionDejaFait = 1;
                        }
                        break;
                    case "sslv3":
                        if ($this->versionDejaFait != 1 && $severity != "OK") {
                            $this->NbVminSSL3++;
                            $this->versionDejaFait = 1;
                        }
                        break;
                    case "tls1":
                        if ($this->versionDejaFait != 1 && $severity != "OK") {
                            $this->NbVminTLS1++;
                            $this->versionDejaFait = 1;
                        }
                        break;
                    case "tls1_1":
                        if ($this->versionDejaFait != 1 && $severity != "OK") {
                            $this->NbVminTLS11++;
                            $this->versionDejaFait = 1;
                        }
                        break;
                    case "tls1_2":
                        if ($this->versionDejaFait != 1 && $severity != "OK") {
                            $this->NbVminTLS12++;
                            $this->versionDejaFait = 1;
                        }
                        break;

                    //TYPE DE CIPHER ACCEPTÉES
                    case "std_NULL":
                        if ($severity != "OK") {
                            $this->cipherNull++;
                        }
                        break;
                    case "std_aNULL":
                        if ($severity != "OK") {
                            $this->anonymCipherNull++;
                        }
                        break;
                    case "std_ADH":
                        if ($severity != "OK") {
                            $this->anonymCipherDH++;
                        }
                        break;
                    case "std_EXPORT40":
                        if ($severity != "OK" && stripos($comments, "not supported by local OpenSSL") == FALSE && stripos($comments, "not tested") == FALSE) {
                            $this->cipherExport40bits++;
                        }
                        break;
                    case "std_EXPORT56":
                        if ($severity != "OK" && stripos($comments, "not supported by local OpenSSL") == FALSE && stripos($comments, "not tested") == FALSE) {
                            $this->cipherExport56bits++;
                        }
                        break;
                    case "std_EXPORT":
                        if ($severity != "OK" && stripos($comments, "not supported by local OpenSSL") == FALSE && stripos($comments, "not tested") == FALSE) {
                            $this->cipherExport++;
                        }
                        break;
                    case "std_LOW":
                        if ($severity != "OK" && stripos($comments, "not supported by local OpenSSL") == FALSE && stripos($comments, "not tested") == FALSE) {
                            $this->cipherLowInf64bits++;
                        }
                        break;
                    case "std_DES":
                        if ($severity != "OK" && stripos($comments, "not supported by local OpenSSL") == FALSE && stripos($comments, "not tested") == FALSE) {
                            $this->cipherDES++;
                        }
                        break;*/
                    /*case "std_MEDIUM":
                        echo "i égal 1";
                        break;*/
                    /*case "std_3DES":
                        if ($severity != "OK" && stripos($comments, "not supported by local OpenSSL") == FALSE && stripos($comments, "not tested") == FALSE) {
                            $this->cipher3DES++;
                        }
                        break;*/
                    /*case "std_HIGH":
                        echo "i égal 2";
                        break;*/
                    case "order":
                        $this->nbServ = $this->nbServ +1;
                        if ($severity == "NOT ok" && stripos($comments, "not supported by local OpenSSL") == FALSE && stripos($comments, "not tested") == FALSE) {
                            $this->courtoi++;
                        }
                        break;
                    case "order_proto":
                        if (stripos($comments, "TLS1.2") != FALSE) {
                            $this->protocolProposeTLS12++;
                            $this->protocolProposePourCetteInstance = "TLS1.2";
                        } else if (stripos($comments, "TLS1.1") != FALSE) {
                            $this->protocolProposeTLS11++;
                            $this->protocolProposePourCetteInstance = "TLS1.1";
                        } else if (stripos($comments, "SSL2") != FALSE) {
                            $this->protocolProposeSSL2++;
                            $this->protocolProposePourCetteInstance = "SSL2";
                        } else if (stripos($comments, "SSL3") != FALSE) {
                            $this->protocolProposeSSL3++;
                            $this->protocolProposePourCetteInstance = "SSL3";
                        } else {
                            $this->protocolProposeTLS1++;
                            $this->protocolProposePourCetteInstance = "TLS1.0";
                        }
                        break;
                    case "order_cipher":
                            if (stripos($comments, "RC4") != FALSE) {    // cipher
                                $this->proposeRC4++;
                            }
                            if (stripos($comments, "AES256") != FALSE) {
                                $this->proposeAes256++;
                            }
                            if (stripos($comments, "AES128") != FALSE) {
                                $this->proposeAes128++;
                            }
                            if (stripos($comments, "3DES") != FALSE) {
                                $this->propose3DES++;
                            }
                            if (stripos($comments, "CAMELLIA256") != FALSE) {
                                $this->proposeCamellia256++;
                            }
                            if (stripos($comments, "SHA384 ") != FALSE) {   //fct de hachages
                                $this->sha384++;
                            }
                            if (stripos($comments, "SHA256 ") != FALSE) {
                                $this->sha256++;
                            }
                            if (stripos($comments, "SHA ") != FALSE) {
                                $this->sha++;
                            }
                            if (stripos($comments, "SHA,") != FALSE) {
                                $this->sha++;
                            }
                            if (stripos($comments, "MD5") != FALSE) {
                                $this->md5++;
                            }
                            if (stripos($comments, "CBC") != FALSE) {           //mode
                                $this->proposeCBC++;
                            }
                            if (stripos($comments, "GCM") != FALSE) {
                                $this->proposeGCM++;
                            }

                            //Incremente le nb de la cipherSuite si il est deja présent
                            $allreadySaved = 0;
                            if(strpos($comments,":") != FALSE) {
                                $pieces = explode(":", $comments);
                                $cip2 = $comments;
                                $cip = $pieces[1];
                                if (stripos($cip, ",")) {
                                    $cip2 = explode(",", $cip);
                                    $cip = $cip2[0];
                                } elseif (stripos($cip, "(")) {
                                    $cip2 = explode("(", $cip);
                                    $cip = $cip2[0];
                                }
                                foreach ($this->cipherSuites as $cipherSuiteObj) {
                                    if (($cipherSuiteObj->getNomCipherSuite()) == $cip) {
                                        $cipherSuiteObj->incrementThisCipher();
                                        $allreadySaved = 1;
                                        break;
                                    }
                                }
                                //L'ajoute dans le tableau cipherSuites si il n'existe pas
                                if ($allreadySaved == 0) {
                                    $cipher = new CipherSuite($cip);
                                    array_push($this->cipherSuites, $cipher);
                                }
                            }
                        break;
                    /*case "tls_extensions":
                        if ($severity == "INFO" && stripos($comments, "not supported by local OpenSSL") == FALSE && stripos($comments, "not tested") == FALSE) {
                            if (stripos($comments, "renegotiation info") != FALSE) {
                                $this->renego++;
                            }
                            if (stripos($comments, "EC point formats") != FALSE) {
                                $this->ecPointFormat++;
                            }
                            if (stripos($comments, "session ticke") != FALSE) {
                                $this->sessionTicket++;
                            }
                            if (stripos($comments, "heartbeat") != FALSE) {
                                $this->heartbeatExtension++;
                            }
                        }
                        break;*/
                    case (preg_match("/[.]*key_size[.]*/", $data[0]) ? $data[0] : !$data[0]):
                        if (stripos($comments, "2048")) {
                            $this->proposeLongueur2048++;
                        }
                        if (stripos($comments, "1024")) {
                            $this->proposeLongueur1024++;
                        }
                        break;

                    //ATTAQUES SUR LESQUELLES LE SERVEUR EST VULNERABLE
                    case "heartbleed": //stripos insensible a la casse
                        if ($severity != "OK" && strpos($comments, "not supported by local OpenSSL") == FALSE && stripos($comments, "not tested") == FALSE) {
                            $this->heartbeatAttaque++;
                        }
                        break;
                    case "ccs":
                        if ($severity != "OK" && strpos($comments, "not supported by local OpenSSL") == FALSE && stripos($comments, "not tested") == FALSE) {
                            $this->cssAttaque++;
                        }
                        break;
                    case "secure_renego":
                        if ($severity != "OK" && strpos($comments, "not supported by local OpenSSL") == FALSE && stripos($comments, "not tested") == FALSE) {
                            $this->secure_renegoAttaque++;
                        }
                        break;
                    case "sec_client_renego":
                        if ($severity != "OK" && strpos($comments, "not supported by local OpenSSL") == FALSE && stripos($comments, "not tested") == FALSE) {
                            $this->sec_client_renegoAttaque++;
                        }
                        break;
                    case "crime":
                        if ($severity != "OK" && strpos($comments, "not supported by local OpenSSL") == FALSE && stripos($comments, "not tested") == FALSE) {
                            $this->crimeAttaque++;
                        }
                        break;
                    case "poodle_ssl":
                        if ($severity != "OK" && strpos($comments, "not supported by local OpenSSL") == FALSE && stripos($comments, "not tested") == FALSE) {
                            $this->poodleAttaque++;
                        }
                        break;
                    case "fallback_scsv":
                        if ($severity != "OK" && strpos($comments, "not supported by local OpenSSL") == FALSE && stripos($comments, "not tested") == FALSE) {
                            $this->fallback_scsvAttaque++;
                        }
                        break;
                    case "freak":
                        if ($severity != "OK" && strpos($comments, "not supported by local OpenSSL") == FALSE && stripos($comments, "not tested") == FALSE) {
                            $this->freakAttaque++;
                        }
                        break;
                    case "drown":
                        if ($severity != "OK" && strpos($comments, "not supported by local OpenSSL") == FALSE && stripos($comments, "not tested") == FALSE) {
                            $this->drownAttaque++;
                        }
                        break;
                    case "logjam":
                        if ($severity != "OK" && strpos($comments, "not supported by local OpenSSL") == FALSE && stripos($comments, "not tested") == FALSE) {
                            $this->logjamAttaque++;
                        }
                        break;
                    case "cbc_tls1":
                        if ($severity != "OK" && strpos($comments, "not supported by local OpenSSL") == FALSE && stripos($comments, "not tested") == FALSE) {
                            $this->cbc_tls1++;
                        }
                        break;
                    case "cbc_ssl3":
                        if ($severity != "OK" && strpos($comments, "not supported by local OpenSSL") == FALSE && stripos($comments, "not tested") == FALSE) {
                            $this->cbc_ssl3++;
                        }
                        break;
                    case "beast":
                        if ($severity != "OK" && strpos($comments, "not supported by local OpenSSL") == FALSE && stripos($comments, "not tested") == FALSE) {
                            $this->beastAttaque++;
                        }
                        break;
                    case "rc4":
                        if ($severity != "OK" && strpos($comments, "not supported by local OpenSSL") == FALSE && stripos($comments, "not tested") == FALSE) {
                            $this->rc4Attaque++;
                        }
                        break;
                }
            }
            fclose($handle);
        }
    }

    /**
     * Fonction qui affiche le resultat du parsage
     */
    function  display()
    {//Affichage
        echo "--------------------------------------------------------------------------------------------------------------------------------------------------------" . "</br>";
        echo "Nombre de serveurs testés : " . $this->nbServ . "</br>";
        echo "Nb serveurs courtois : " . $this->courtoi . "</br>";
        echo "--------------------------------------------------------------------------------------------------------------------------------------------------------" . "</br>";
        echo "Ce que les serveurs acceptent ..." . "</br>" . "</br>";
        echo "Nb acceptent version min SSL2: " . $this->NbVminSSL2 . "|" . "Nb acceptent version min SSL3: " . $this->NbVminSSL3 . "|" . "Nb acceptent version min TLS1.0: " . $this->NbVminTLS1 . "|" . "Nb acceptent version min TLS1.1: " . $this->NbVminTLS11 . "|" . "Nb acceptent version min TLS1.2: " . $this->NbVminTLS12 . "</br>";
        echo "Nb acceptent cipher NULL : " . $this->cipherNull . "|" . "Nb acceptent cipher NULL anonymes : " . $this->anonymCipherNull . "|" . "Nb acceptent cipher DH anonymes: " . $this->anonymCipherDH . "|" . "Nb acceptent cipher < 64bits: " . $this->cipherLowInf64bits . "|" . "Nb acceptent cipher DES: " . $this->cipherDES . "|" . "Nb acceptent cipher 3DES: " . $this->cipher3DES . "</br>";
        echo "Nb acceptent cipher export <40bits :" . $this->cipherExport40bits . "|" . "Nb acceptent cipher export <56bits :" . $this->cipherExport56bits . "|" . "Nb acceptent les cipher export :" . $this->cipherExport . "</br>";
        echo "--------------------------------------------------------------------------------------------------------------------------------------------------------" . "</br>";
        echo "Ce que les serveurs proposent ..." . "</br>" . "</br>";
        echo "Nb TLS1.2 proposés par serveurs: " . $this->protocolProposeTLS12 . "|" . "Nb TLS1.1 proposés : " . $this->protocolProposeTLS11 . "|" . "Nb TLS1.0 proposés : " . $this->protocolProposeTLS1 . "|" . "Nb SSLV2 proposés : " . $this->protocolProposeSSL2 . "|" . "Nb SLLV3 proposés: " . $this->protocolProposeSSL3 . "</br>";
        echo "Nb proposent RC4 :" . $this->proposeRC4 . "|" . "Nb proposent AES256 :" . $this->proposeAes256 . "|" . "Nb proposent AES128 :" . $this->proposeAes128 . "|" . "Nb proposent 3DES :" . $this->propose3DES . "|" . "Nb proposent CAMELLIA 256 :" . $this->proposeCamellia256 . "</br>";
        echo "Nb proposent SHA1 en hachage :" . $this->sha . "|" . "Nb proposent MD5 en hachage :" . $this->md5 . "</br>";
        echo "Nb proposent clés de 2048 : " . $this->proposeLongueur2048 . "|" . "Nb proposent clés de 1024 : " . $this->proposeLongueur1024 . "</br>";
        echo "Nb proposent mode CBC : " . $this->proposeCBC . "|" . "Nb proposent mode GCM : " . $this->proposeGCM . "</br>";
        echo "--------------------------------------------------------------------------------------------------------------------------------------------------------" . "</br>";
        echo "Extension renegotiation :" . $this->renego . "|" . "Extension ec Point Format :" . $this->ecPointFormat . "|" . "Extension sesion ticket :" . $this->sessionTicket . "|" . "Extension heartbeat :" . $this->heartbeatExtension . "</br>";
        echo "--------------------------------------------------------------------------------------------------------------------------------------------------------" . "</br>";
        echo "Les attaques..." . "</br>" . "</br>";
        echo "Nb vulnérable heartbleed :" . $this->heartbeatAttaque . "|" . "Nb vulnérable css :" . $this->cssAttaque . "|" . "Nb vulnérable secure-renegotiation :" . $this->secure_renegoAttaque . "|" . "Nb vulnérable secure client renegotiation :" . $this->sec_client_renegoAttaque . "</br>";
        echo "Nb vulnérable crime :" . $this->crimeAttaque . "|" . "Nb vulnérable poodle :" . $this->poodleAttaque . "|" . "Nb vulnérable fallback_scsv :" . $this->fallback_scsvAttaque . "|" . "Nb vulnérable freak :" . $this->freakAttaque . "</br>";
        echo "Nb vulnérable drown :" . $this->drownAttaque . "|" . "Nb vulnérable logjam :" . $this->logjamAttaque . "|" . "Nb vulnérable beast :" . $this->beastAttaque . "|" . "Nb vulnérable rc4 :" . $this->rc4Attaque . "</br>";
        echo "--------------------------------------------------------------------------------------------------------------------------------------------------------" . "</br>";
        echo "Les suites utilisées... "."</br></br>";
        foreach ($this->cipherSuites as $cipher){
            $res = $cipher->toString();
            echo $res." ==> <b>".($cipher->getCountOfThisCipher())/$this->nbServ."%</b></br>";
        }
    }

    /**
     * @return int
     */
    public function getNbServ()
    {
        return $this->nbServ;
    }

    /**
     * @return int
     */
    public function getCourtoi()
    {
        return $this->courtoi;
    }

    /**
     * @return int
     */
    public function getHeartbeatAttaque()
    {
        return $this->heartbeatAttaque;
    }

    /**
     * @return int
     */
    public function getCssAttaque()
    {
        return $this->cssAttaque;
    }

    /**
     * @return int
     */
    public function getSecureRenegoAttaque()
    {
        return $this->secure_renegoAttaque;
    }

    /**
     * @return int
     */
    public function getSecClientRenegoAttaque()
    {
        return $this->sec_client_renegoAttaque;
    }

    /**
     * @return int
     */
    public function getCrimeAttaque()
    {
        return $this->crimeAttaque;
    }

    /**
     * @return int
     */
    public function getPoodleAttaque()
    {
        return $this->poodleAttaque;
    }

    /**
     * @return int
     */
    public function getFallbackScsvAttaque()
    {
        return $this->fallback_scsvAttaque;
    }

    /**
     * @return int
     */
    public function getFreakAttaque()
    {
        return $this->freakAttaque;
    }

    /**
     * @return int
     */
    public function getDrownAttaque()
    {
        return $this->drownAttaque;
    }

    /**
     * @return int
     */
    public function getLogjamAttaque()
    {
        return $this->logjamAttaque;
    }

    /**
     * @return int
     */
    public function getBeastAttaque()
    {
        return $this->beastAttaque;
    }
    public function getCbcTls1Attaque(){
        return $this->cbc_tls1;
    }

    public function getCbcSsl3Attaque(){
        return $this->cbc_ssl3;
    }
    /**
     * @return int
     */
    public function getRc4Attaque()
    {
        return $this->rc4Attaque;
    }


}
