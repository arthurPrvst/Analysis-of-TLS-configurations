<?php

class CipherSuite
{
    private $nomCipherSuite = null;
    private $countOfThisCipher = 0;

    public function __construct($nomCipher)
    {
        $this->nomCipherSuite=$nomCipher;
        $this->countOfThisCipher = $this->countOfThisCipher +1;
    }

    /**
     * @return null
     */
    public function getNomCipherSuite()
    {
        return $this->nomCipherSuite;
    }

    /**
     * @param null $nomCipherSuite
     */
    public function setNomCipherSuite($nomCipherSuite)
    {
        $this->nomCipherSuite = $nomCipherSuite;
    }

    /**
     * @return int
     */
    public function getCountOfThisCipher()
    {
        return $this->countOfThisCipher;
    }

    /**
     * increment the number of the cipher
     */
    public function incrementThisCipher()
    {
        $this->countOfThisCipher = $this->countOfThisCipher+1;
    }

    public function toString(){
        return "Cipher Suite : ".$this->nomCipherSuite." with ".$this->countOfThisCipher." entities";
    }

}
