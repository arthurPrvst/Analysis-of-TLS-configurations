<?php

class DNS
{
    private $nomDns = null;
    private $ips = array (); //array of ip of his servers
    private $ciphers = array(); //array of Cipher String
    private $nbCiphers = 0;

    public function __construct($nom,$ip)
    {
        $this->nomDns = $nom;
        $this->ips[$ip]=1;
    }

    /**
     * @return null
     */
    public function getNom()
    {
        return $this->nomDns;
    }

    /**
     * @return array
     */
    public function getIps()
    {
        return $this->ips;
    }

    public function setIp($ip){
        $this->ips[$ip]=1;
    }

    /**
     * @return array
     */
    public function getCiphers()
    {
        return $this->ciphers;
    }

    /**
     * @param $ciph
     */
    public function setCiphers($ciph)
    {
        if(!in_array($ciph,$this->ciphers)){
            array_push($this->ciphers, $ciph);
        }
        $this->nbCiphers = $this->nbCiphers+1;
    }

    public function getNbDiffCipherOfThisDns(){
        return count($this->ciphers);
    }

    public function getNbCipherOfThisDns(){
        return $this->nbCiphers;
    }




}