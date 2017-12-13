<?php
require_once __DIR__ . '/CipherSuite.class.php';

class LecteurDeprecatedCipher
{
    private $nomFichier = null;
    private $deprecatedParam = array();
    private $deprecatedCipherSuite = array();
    private $dnsIp = array();


    public function __construct($nomFich)
    {
        $this->nomFichier = $nomFich;
        $this->deprecatedParameters();
        $this->read();
    }

    public function read()
    {
        $handle = fopen($this->nomFichier, 'r');

        if ($handle) {
            while (!feof($handle)) {
                /*Reads the current line*/
                $buffer = fgets($handle);
                $tab = preg_split('/\s+/', $buffer);

                if (count($tab) == 5) {
                    $cipherSuite = $tab[3];
                    if(!array_key_exists($tab[0].$tab[1], $this->getDnsIp())){ //if it doesn't exist
                        $this->dnsIp[$tab[0].$tab[1]]=1;
                    }

                    foreach ($this->deprecatedParam as $param) {
                        if (strpos($cipherSuite, $param) !== FALSE) {

                            $allreadySaved = 0;
                            foreach ($this->deprecatedCipherSuite as $cipherSuiteObj) {
                                if (($cipherSuiteObj->getNomCipherSuite()) == $cipherSuite) {
                                    $cipherSuiteObj->incrementThisCipher();
                                    $allreadySaved = 1;
                                    break;
                                }
                            }
                            //Add it to the cipher suites table if it doesn't already exist
                            if ($allreadySaved == 0) {
                                $cip = new CipherSuite($cipherSuite);
                                array_push($this->deprecatedCipherSuite, $cip);
                            }

                            break;
                        }
                    }
                }
            }
            fclose($handle);
        }
    }

    function deprecatedParameters()
    {
        array_push($this->deprecatedParam, "DES");
        array_push($this->deprecatedParam, "RC4");
        array_push($this->deprecatedParam, "SEED");
        array_push($this->deprecatedParam, "3DES");
        array_push($this->deprecatedParam, "IDEA");
        array_push($this->deprecatedParam, "NULL");
        array_push($this->deprecatedParam, "MD5");
        array_push($this->deprecatedParam, "EXPORT");
        array_push($this->deprecatedParam, "EXP");
        array_push($this->deprecatedParam, "CK");
        array_push($this->deprecatedParam, "PSK");
        array_push($this->deprecatedParam, "FIPS");
        array_push($this->deprecatedParam, "RC2");
        array_push($this->deprecatedParam, "SCSV");
        array_push($this->deprecatedParam, "KRB5");
        array_push($this->deprecatedParam, "AECDH");
        array_push($this->deprecatedParam, "ADH");
    }

    function getNbTestedServers(){
        return count($this->dnsIp);
    }

    /**
     * @return array
     */
    public function getDeprecatedCipherSuite()
    {
        return $this->deprecatedCipherSuite;
    }

    function displayDeprecatedCipherSuite(){
        foreach ($this->deprecatedCipherSuite as $depreCipher){
            echo $depreCipher->toString()." with ".$depreCipher->getCountOfThisCipher()." entities "."</br>";
        }
    }

    /**
     * @return array
     */
    public function getDnsIp()
    {
        return $this->dnsIp;
    }

}
