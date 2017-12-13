<?php
require __DIR__ . '/LecteurTestssl.class.php';
require __DIR__ . '/LecteurWireshark.class.php';
require __DIR__ . '/LecteurDeprecatedCipher.class.php';
$display = array();
if (!empty($_POST)) {
    if (($handle = fopen($_POST["nomFichier"], "r")) !== FALSE) { //Si le lien vers le fichier est OK
        $type = $_POST["type"];

        if (stripos($type, "wireshark") !== FALSE) {
            $lecteurWireshark = new LecteurWireshark("resultExcelWireshark.csv");
            ?>
            <!-- RECOVER DATAS -->
            <input type="hidden" id="nbServeurs" value="<?php echo $lecteurWireshark->getNbServeurs(); ?>"/>
            <input type="hidden" id="nbSSL2" value="<?php echo $lecteurWireshark->getSsl2(); ?>"/>
            <input type="hidden" id="nbSSL3" value="<?php echo $lecteurWireshark->getSsl3(); ?>"/>
            <input type="hidden" id="nbTLS10" value="<?php echo $lecteurWireshark->getTls10(); ?>"/>
            <input type="hidden" id="nbTLS11" value="<?php echo $lecteurWireshark->getTls11(); ?>"/>
            <input type="hidden" id="nbTLS12" value="<?php echo $lecteurWireshark->getTls12(); ?>"/>

            <input type="hidden" id="rsa" value="<?php echo $lecteurWireshark->getRsa(); ?>"/>
            <input type="hidden" id="dhe" value="<?php echo $lecteurWireshark->getDhe(); ?>"/>
            <input type="hidden" id="ecdhe" value="<?php echo $lecteurWireshark->getEcdhe(); ?>"/>
            <input type="hidden" id="ecdh" value="<?php echo $lecteurWireshark->getEcdh(); ?>"/>

            <input type="hidden" id="rsa_signature" value="<?php echo $lecteurWireshark->getRsaSignature(); ?>"/>
            <input type="hidden" id="ecdsa_signature" value="<?php echo $lecteurWireshark->getEcdsaSignature(); ?>"/>
            <input type="hidden" id="dss_signature" value="<?php echo $lecteurWireshark->getDssSignature(); ?>"/>


            <input type="hidden" id="troisDesEde" value="<?php echo $lecteurWireshark->getTroisdesEde(); ?>"/>
            <input type="hidden" id="aes128" value="<?php echo $lecteurWireshark->getAes128(); ?>"/>
            <input type="hidden" id="aes256" value="<?php echo $lecteurWireshark->getAes256(); ?>"/>
            <input type="hidden" id="camellia256" value="<?php echo $lecteurWireshark->getCamellia256(); ?>"/>
            <input type="hidden" id="rc4" value="<?php echo $lecteurWireshark->getRc4(); ?>"/>
            <input type="hidden" id="seed" value="<?php echo $lecteurWireshark->getSeed(); ?>"/>
            <input type="hidden" id="idea" value="<?php echo $lecteurWireshark->getIdea(); ?>"/>


            <input type="hidden" id="cbc" value="<?php echo $lecteurWireshark->getCbc(); ?>"/>
            <input type="hidden" id="gcm" value="<?php echo $lecteurWireshark->getGcm(); ?>"/>


            <input type="hidden" id="md5" value="<?php echo $lecteurWireshark->getMd5(); ?>"/>
            <input type="hidden" id="sha" value="<?php echo $lecteurWireshark->getSha(); ?>"/>
            <input type="hidden" id="sha256" value="<?php echo $lecteurWireshark->getSha256(); ?>"/>
            <input type="hidden" id="sha384" value="<?php echo $lecteurWireshark->getSha384(); ?>"/>

            <input type="hidden" id="export" value="<?php echo $lecteurWireshark->getExport(); ?>"/>

            <input type="hidden" id="compression" value="<?php echo $lecteurWireshark->getCompression(); ?>"/>
            <input type="hidden" id="renego" value="<?php echo $lecteurWireshark->getRenego(); ?>"/>
            <input type="hidden" id="heartbeat" value="<?php echo $lecteurWireshark->getHeartbeatExtension(); ?>"/>
            <input type="hidden" id="sessionticket" value="<?php echo $lecteurWireshark->getSessionTicket(); ?>"/>
            <input type="hidden" id="ecpointsformats" value="<?php echo $lecteurWireshark->getEcPointFormat(); ?>"/>
            <input type="hidden" id="elliptic_curves" value="<?php echo $lecteurWireshark->getEllipticCurves(); ?>"/>
            <input type="hidden" id="signature_algorithms" value="<?php echo $lecteurWireshark->getSignatureAlgo(); ?>"/>
            <input type="hidden" id="server_name" value="<?php echo $lecteurWireshark->getServerName(); ?>"/>

            <input type="hidden" id="nbDNSWithDiffConfig" value="<?php echo $lecteurWireshark->getNbDNSwithDiffConfig(); ?>"/>
            <input type="hidden" id="nbDns" value="<?php echo count($lecteurWireshark->getAllDns()); ?>"/>

            <?php $array = $lecteurWireshark->getCipherSuites();
            $nbCipher = count($array);
            ?><input type="hidden" id="nbciphersuite" value="<?php echo $nbCipher; ?>"/><?php
            $i = 0;
            foreach ($array as $cipher) {
                ?><input type="hidden" id="cipher<?php echo $i ?>" value="<?php echo $cipher->toString(); ?>"/>
                <?php
                $i++;
            }
            ?>

            <?php

        } elseif (stripos($type, "deprecated") !== FALSE) {
            $lecteurDeprecated = new LecteurDeprecatedCipher("resultDeprecatedCipherParallel.txt");


        } elseif (stripos($type, "testssl") !== FALSE) {
            $lecteurTestSSLMX = new LecteurTestssl("result.csv");


        }
    }
}
?>