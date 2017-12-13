<?php

class LecteurCorpus
{
    private $nomFichier = null;
    private $extension = array(); // .com .fr .net .org ... meaning the origin of the DNS
    private $top20Extension = array(); // .com .fr .net .org ... meaning the origin of the DNS where >= 1000 entites
    private $pastop20Extension = array();
    private $extensionOrigin = array(
        "com" => "Commercial",
        "net" => "Network",
        "br" => "Brazil",
        "org" => "Non-commercial",
        "ru" => "Russia",
        "it" => "Italy",
        "de" => "Germany",
        "uk" => "United kingdom",
        "cn" => "China",
        "edu" => "Education",
        "io" => "Indian Ocean",
        "fr" => "France",
        "jp" => "Japan",
        "tv" => "Video",
        "nl" => "Netherlands",
        "pl" => "Poland",
        "co" => "Colombia",
        "info" => "Information",
        "us" => "USA",
        "ca" => "Canada",
    );

    public function __construct($nomFich)
    {
        $this->nomFichier = $nomFich;
        $this->read();
        $this->filterExtension();
        //$this->displayOrigin($this->top20Extension);
    }

    public function read()
    {
        $handle = fopen($this->nomFichier, 'r');

        if ($handle) {
            while (!feof($handle)) {
                /*On lit la ligne courante*/
                $buffer = fgets($handle);
                $tab = explode(".",$buffer);
                $ext = $tab[count($tab)-1];//last part of the exploded string
                if(array_key_exists($ext, $this->extension)){
                    $this->extension[$ext]= $this->extension[$ext] +1;
                }else{
                    $this->extension[$ext]= 1;
                }
            }
            fclose($handle);
        }
    }

    public function filterExtension(){
        foreach ($this->extension as $key => $value){
            if($value>=4524){
                $this->top20Extension[rtrim($key)]=$value;
            }else{
                $this->pastop20Extension[rtrim($key)]=$value;
            }
        }
        arsort($this->top20Extension); //tri decroissant
    }

    public function displayOrigin($tab){
        $nb = 0;
        foreach ($tab as $key => $value){
            echo $key." : ".$value."<br>";
            $nb = $nb +$value;
        }
        echo "Nombre de DNS: ".$nb;
    }

    /**
     * @return array
     */
    public function getTop20Extension()
    {
        return $this->top20Extension;
    }

    /**
     * @return array
     */
    public function getExtensionOrigin()
    {
        return $this->extensionOrigin;
    }


    public function getNbDNSnotTop20(){
        $nb = 0;
        foreach($this->pastop20Extension as $key => $value){
            $nb = $nb +$value;
        }
        return $nb;
    }
}