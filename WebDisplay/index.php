<!DOCTYPE html>
<html>
<head>
    <meta http-equiv="Content-Type" content="text/html; charset=UTF-8"/>
    <meta name="viewport" content="width=device-width, initial-scale=1, maximum-scale=1.0, user-scalable=no"/>
    <meta name="theme-color" content="#2196F3">
    <title>Analyse SSL/TLS connexions</title>
    <link rel="icon" type="image/png" href="img/fav.png"/>
    <!-- CSS  -->
    <link href="min/plugin-min.css" type="text/css" rel="stylesheet">
    <link href="min/custom-min.css" type="text/css" rel="stylesheet">
    <!--Import Google Icon Font-->
    <link href="http://fonts.googleapis.com/icon?family=Material+Icons" rel="stylesheet"/>
    <!--Import materialize.css-->
    <link type="text/css" rel="stylesheet" href="css/materialize.min.css" media="screen,projection"/>
    <!--Import my css -->
    <link type="text/css" rel="stylesheet" href="css/main.css" media="screen,projection"/>
    <!-- Import icons -->
    <link href="https://fonts.googleapis.com/icon?family=Material+Icons" rel="stylesheet"/>
</head>
<body id="top" class="scrollspy">

<?php
require __DIR__ . '/LecteurCorpus.class.php';
require __DIR__ . '/LecteurTestssl.class.php';
require __DIR__ . '/LecteurWireshark.class.php';
require __DIR__ . '/LecteurDeprecatedCipher.class.php';
ini_set('max_execution_time', 0); // REMOVES 30SEC PHP.INIT PAGE LOAD RESTRICTION
ini_set('memory_limit', '-1');  // REMOVES MEMORY RESTRICTION

$lecteurCorpus = new LecteurCorpus('./topMillionSansChariot.txt');
$lecteurWireshark = new LecteurWireshark("./resultWireshark.csv");
$lecteurDeprecated = new LecteurDeprecatedCipher("finalDeprecatedParallel.txt");
$lecteurTestSSLMX = new LecteurTestssl("./result.csv");

?>
<!-- Pre Loader -->
<div id="loader-wrapper">
    <div id="loader"></div>

    <div class="loader-section section-left"></div>
    <div class="loader-section section-right"></div>

</div>


<!--Navigation-->
<div class="navbar-fixed">
    <nav id="nav_f" class="default_color" role="navigation">
        <div class="container">
            <div class="nav-wrapper">
                <a href="#" id="logo-container" class="brand-logo">EMSEC - IRISA</a>
                <ul class="right hide-on-med-and-down">
                    <li><a href="https://www.irisa.fr/emsec/">Work</a></li>
                    <li><a href="https://www.irisa.fr/fr/equipes/emsec">Team</a></li>
                    <li><a href="https://twitter.com/emsec35">Twitter</a></li>
                </ul>
                <ul id="nav-mobile" class="side-nav">
                    <li><a href="https://www.irisa.fr/emsec/">Work</a></li>
                    <li><a href="https://www.irisa.fr/fr/equipes/emsec">Team</a></li>
                    <li><a href="https://twitter.com/emsec35">Twitter</a></li>
                </ul>
                <a href="#" data-activates="nav-mobile" class="button-collapse"><i class="mdi-navigation-menu"></i></a>
            </div>
        </div>
    </nav>
</div>

<!--Purpose of the work-->
<div class="section no-pad-bot" id="index-banner">
    <div class="container center-align">
        <h2 class="white-text text-darken-2"> A User Interface and Tools to analyse smtp server's SSL/TLS configurations.</h2>
        <h1 class="text_h center header cd-headline letters type">
            <span>I Analyse </span>
            <span class="cd-words-wrapper waiting">
                <b class="is-visible">Cipher Suites</b>
                <b>Vulnerabilites</b>
            </span>
        </h1>
    </div>
</div>

<!--Intro-->
<div id="intro" class="section scrollspy">
    <div class="container">
        <div class="row">
            <div class="col s12">
                <h5 class="center header text_h2"> In order to analyse your collected data, the work is divided in three steps. The first one will show you <span class="span_h2"> Cipher Suite </span>
                    negociated by servers,
                    and some useful statistics on these Cipher Suites. The second one will show you all <span class="span_h2"> deprecated Cipher Suites </span> allowed by tested
                    servers.
                    And the last one, will show you some statistics on <span class="span_h2"> vulnerabilities </span> (HeartBleed...).</br>
                    All tools are available below ! </h5>
            </div>

            <div class="col s12 m4 l4">
                <div class="center promo promo-example">
                    <img src="img/wireshark.png" width="100px"/>
                    <h5 class="promo-caption">Analysis of the negotiated Cipher Suites</h5>
                    <p class="light center">For this part, you have to launch your SSL / TLS connections on your server list, and capture the packets with Wireshark. You must give
                        the file "resultExcelWireshark.csv" in the input below to start the analysis. All scripts are available here. Follow the readme.</p>
                </div>

            </div>
            <div class="col s12 m4 l4">
                <div class="center promo promo-example">
                    <h3 class="blue-text">Deprecated Ciphers</h3></br>
                    <h5 class="promo-caption">Analysis of the deprecated Cipher Suites allowed</h5>
                    <p class="light center">For this part, you have to launch each cipher allowed by your openssl version on each server of your list. You must give the file
                        "resultSslscan.txt" in the input below to start the analysis. All scripts are available here. Follow the readme.</p>
                </div>
            </div>
            <div class="col s12 m4 l4">
                <div class="center promo promo-example">
                    <img src="img/vulnerabilites.png" width="120px"/></br></br>
                    <h5 class="promo-caption">Analysis of vulnerabilites</h5>
                    <p class="light center">This part uses testssl.sh shell script which his available here. This page undertakes the analysis of the results. You must give the
                        file "resultTestssl.txt" in the input below to start the analysis. All scripts are available here. Follow the readme.</p>
                </div>
            </div>
        </div>
    </div>
</div>
<!-- ------------------------------------------------------- ORIGIN      ------------------------------------------------------------------------- -->
<div class="section scrollspy" id="sslscan">
    <div class="container center-align">
        <h3 class="header text_b">Analysis the Corpus</h3>

        <div class="container">
            <div class="row">
                <div class="col s6">
                    <table class="centered striped">
                        <thead>
                        <tr>
                            <th>Origin</th>
                            <th>Extension</th>
                            <th>Rank</th>
                            <th>Presence in Cisco's list (%)</th>
                            <th>Number of DNS</th>
                        </tr>
                        </thead>

                        <tbody>
                        <?php
                        $i = 1;
                        $extensionOrigin = $lecteurCorpus->getExtensionOrigin();
                        foreach ($lecteurCorpus->getTop20Extension() as $key => $value) {
                            ?>
                            <tr><td><?php echo $extensionOrigin[$key] ?></td>
                                <td><?php echo $key ?></td>
                                <td><?php echo $i ?></td>
                                <td><?php echo round($value * 100 / 1000000, 2)." %" ?></td>
                                <td><?php echo $value ?></td>
                            </tr>
                            <?php $i++;
                            if ($i > 20) {
                                break;
                            };
                        } ?>
                        <tr>
                            <td>Others</td>
                            <td> - </td>
                            <td> - </td>
                            <td><?php echo round($lecteurCorpus->getNbDNSnotTop20() * 100 / 1000000, 2) ." %"?></td>
                            <td><?php echo $lecteurCorpus->getNbDNSnotTop20() ?></td>
                        </tr>
                        <tr>
                            <td>Total</td>
                            <td> - </td>
                            <td> - </td>
                            <td>100%</td>
                            <td>1 000 000</td>
                        </tr>
                        </tbody>
                    </table>
                </div>
            </div>
        </div><?php
        ?>
    </div>
</div>
<!-- ------------------------------------------------------- WIRESHARK ---------------------------------------------------------------------------- -->
<div class="section scrollspy" id="wireshark"> <!-- class blue lighten-5 -->
    <div class="container center-align">
        <h3 class="header text_b">Analysis of negociated SSL/TLS connections</h3>

        <!-- RECOVER DATAS -->
        <input type="hidden" id="nbLow" value="<?php echo $lecteurWireshark->getNbLow(); ?>"/>
        <input type="hidden" id="nbMedium" value="<?php echo $lecteurWireshark->getNbMedium(); ?>"/>
        <input type="hidden" id="nbHigh" value="<?php echo $lecteurWireshark->getNbHigh(); ?>"/>

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
        <input type="hidden" id="aes128cbc" value="<?php echo $lecteurWireshark->getAes128CBC(); ?>"/>
        <input type="hidden" id="aes256cbc" value="<?php echo $lecteurWireshark->getAes256CBC(); ?>"/>
        <input type="hidden" id="aes128gcm" value="<?php echo $lecteurWireshark->getAes128GCM(); ?>"/>
        <input type="hidden" id="aes256gcm" value="<?php echo $lecteurWireshark->getAes256GCM(); ?>"/>


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
        <div class="row">
            <div class="col s6" style="margin-top: 150px">
                <div style="max-width:300px; max-height:300px; margin: auto">
                    <canvas id="high_medium_low" width="100" height="100"></canvas>
                    <table class="bordered centered highlight">
                        <thead>
                        <tr>
                            <th>Low cipher suites</th>
                            <th>Medium cipher suites</th>
                            <th>High cipher suites</th>
                        </tr>
                        </thead>
                        <tbody>
                        <tr>
                            <td><?php echo round($lecteurWireshark->getNbLow() * 100 / $lecteurWireshark->getNbServeurs(), 4) . "%" ?></td>
                            <td><?php echo round($lecteurWireshark->getNbMedium() * 100 / $lecteurWireshark->getNbServeurs(), 4) . "%" ?></td>
                            <td><?php echo round($lecteurWireshark->getNbHigh() * 100 / $lecteurWireshark->getNbServeurs(), 4) . "%" ?></td>
                        </tr>
                        </tbody>
                    </table>
                </div>
            </div>
            <div class="col s6" style="margin-top: 150px">
                <div style="max-width:300px; max-height:300px; margin: auto">
                    <canvas id="repartitionPays" width="100" height="100"></canvas>
                    <table class="bordered centered highlight">
                        <thead>
                        <tr>
                            <th>.com</th>
                            <th>.net</th>
                            <th>.org</th>
                            <th>.fr</th>
                        </tr>
                        </thead>
                        <tbody>
                        <tr>
                            <td><?php echo round($lecteurWireshark->getRsa() * 100 / $lecteurWireshark->getNbServeurs(), 4) . "%" ?></td>
                            <td><?php echo round($lecteurWireshark->getDhe() * 100 / $lecteurWireshark->getNbServeurs(), 4) . "%" ?></td>
                            <td><?php echo round($lecteurWireshark->getEcdh() * 100 / $lecteurWireshark->getNbServeurs(), 4) . "%" ?></td>
                            <td><?php echo round($lecteurWireshark->getEcdhe() * 100 / $lecteurWireshark->getNbServeurs(), 4) . "%" ?></td>
                        </tr>
                        </tbody>
                    </table>
                </div>
            </div>
        </div>


        <div style="max-width:100%; max-height:1200px; margin: auto; margin-top: 300px;">
            <canvas id="highciphersuite" width="600" height="300"></canvas>
        </div>
        <div style="max-width:100%; max-height:1200px; margin: auto; margin-top: 50px;">
            <canvas id="mediumciphersuite" width="600" height="300"></canvas>
        </div>
        <div style="max-width:100%; max-height:1200px; margin: auto; margin-top: 50px;">
            <canvas id="lowciphersuite" width="600" height="300"></canvas>
        </div>
        <div class="row">
            <div class="col s4" style="margin-top: 150px">
                <div style="max-width:300px; max-height:300px; margin: auto">
                    <canvas id="versionTls" width="100" height="100"></canvas>
                    <table class="bordered centered highlight">
                        <thead>
                        <tr>
                            <th>SSL2.0</th>
                            <th>SSL3.0</th>
                            <th>TLS1.0</th>
                            <th>TLS1.1</th>
                            <th>TLS1.2</th>
                        </tr>
                        </thead>
                        <tbody>
                        <tr>
                            <td><?php echo round($lecteurWireshark->getSsl2() * 100 / $lecteurWireshark->getNbServeurs(), 4) . "%" ?></td>
                            <td><?php echo round($lecteurWireshark->getSsl3() * 100 / $lecteurWireshark->getNbServeurs(), 4) . "%" ?></td>
                            <td><?php echo round($lecteurWireshark->getTls10() * 100 / $lecteurWireshark->getNbServeurs(), 4) . "%" ?></td>
                            <td><?php echo round($lecteurWireshark->getTls11() * 100 / $lecteurWireshark->getNbServeurs(), 4) . "%" ?></td>
                            <td><?php echo round($lecteurWireshark->getTls12() * 100 / $lecteurWireshark->getNbServeurs(), 4) . "%" ?></td>
                        </tr>
                        </tbody>
                    </table>
                </div>
            </div>
            <div class="col s4" style="margin-top: 150px">
                <div style="max-width:300px; max-height:300px; margin: auto">
                    <canvas id="KeyExchangeAlgorithm" width="100" height="100"></canvas>
                    <table class="bordered centered highlight">
                        <thead>
                        <tr>
                            <th>RSA</th>
                            <th>DHE</th>
                            <th>ECDH</th>
                            <th>ECDHE</th>
                        </tr>
                        </thead>
                        <tbody>
                        <tr>
                            <td><?php echo round($lecteurWireshark->getRsa() * 100 / $lecteurWireshark->getNbServeurs(), 4) . "%" ?></td>
                            <td><?php echo round($lecteurWireshark->getDhe() * 100 / $lecteurWireshark->getNbServeurs(), 4) . "%" ?></td>
                            <td><?php echo round($lecteurWireshark->getEcdh() * 100 / $lecteurWireshark->getNbServeurs(), 4) . "%" ?></td>
                            <td><?php echo round($lecteurWireshark->getEcdhe() * 100 / $lecteurWireshark->getNbServeurs(), 4) . "%" ?></td>
                        </tr>
                        </tbody>
                    </table>
                </div>
            </div>
            <div class="col s4" style="margin-top: 150px">
                <div style="max-width:300px; max-height:300px; margin: auto">
                    <canvas id="SignatureAlgorithm" width="100" height="100"></canvas>
                    <table class="bordered centered highlight">
                        <thead>
                        <tr>
                            <th>RSA</th>
                            <th>ECDSA</th>
                            <th>DSS</th>
                        </tr>
                        </thead>
                        <tbody>
                        <tr>
                            <td><?php echo round($lecteurWireshark->getRsaSignature() * 100 / $lecteurWireshark->getNbServeurs(), 4) . "%" ?></td>
                            <td><?php echo round($lecteurWireshark->getEcdsaSignature() * 100 / $lecteurWireshark->getNbServeurs(), 4) . "%" ?></td>
                            <td><?php echo round($lecteurWireshark->getDssSignature() * 100 / $lecteurWireshark->getNbServeurs(), 4) . "%" ?></td>
                        </tr>
                        </tbody>
                    </table>
                </div>
            </div>
            <div class="col s4" style="margin-top: 200px">
                <div style="max-width:300px; max-height:300px; margin: auto">
                    <canvas id="cipher" width="100" height="100"></canvas>
                    <table class="bordered centered highlight">
                        <thead>
                        <tr>
                            <th>IDEA</th>
                            <th>RC4</th>
                            <th>SEED</th>
                            <th>3DES</th>
                        </tr>
                        </thead>
                        <tbody>
                        <tr>
                            <td><?php echo round($lecteurWireshark->getIdea() * 100 / $lecteurWireshark->getNbServeurs(), 4) . "%" ?></td>
                            <td><?php echo round($lecteurWireshark->getRc4() * 100 / $lecteurWireshark->getNbServeurs(), 4) . "%" ?></td>
                            <td><?php echo round($lecteurWireshark->getSeed() * 100 / $lecteurWireshark->getNbServeurs(), 4) . "%" ?></td>
                            <td><?php echo round($lecteurWireshark->getTroisdesEde() * 100 / $lecteurWireshark->getNbServeurs(), 4) . "%" ?></td>
                        </tr>
                        </tbody>
                    </table>
                    <table class="bordered centered highlight">
                        <thead>
                        <tr>
                            <th>AES128 CBC</th>
                            <th>AES256 CBC</th>
                            <th>AES128 GCM</th>
                            <th>AES256 GCM</th>
                        </tr>
                        </thead>
                        <tbody>
                        <tr>
                            <td><?php echo round($lecteurWireshark->getAes128CBC() * 100 / $lecteurWireshark->getNbServeurs(), 4) . "%" ?></td>
                            <td><?php echo round($lecteurWireshark->getAes256CBC() * 100 / $lecteurWireshark->getNbServeurs(), 4) . "%" ?></td>
                            <td><?php echo round($lecteurWireshark->getAes128GCM() * 100 / $lecteurWireshark->getNbServeurs(), 4) . "%" ?></td>
                            <td><?php echo round($lecteurWireshark->getAes256GCM() * 100 / $lecteurWireshark->getNbServeurs(), 4) . "%" ?></td>
                        </tr>
                        </tbody>
                    </table>
                    <table class="bordered centered highlight">
                        <thead>
                        <tr>
                            <th>CAMELLIA256</th>
                        </tr>
                        </thead>
                        <tbody>
                        <tr>
                            <td><?php echo round($lecteurWireshark->getCamellia256() * 100 / $lecteurWireshark->getNbServeurs(), 4) . "%" ?></td>
                        </tr>
                        </tbody>
                    </table>
                </div>

            </div>
            <div class="col s4" style="margin-top: 200px">
                <div style="max-width:300px; max-height:300px; margin: auto">
                    <canvas id="blockmode" width="100" height="100"></canvas>
                    <table class="bordered centered highlight">
                        <thead>
                        <tr>
                            <th>CBC</th>
                            <th>GCM</th>
                        </tr>
                        </thead>
                        <tbody>
                        <tr>
                            <td><?php echo round($lecteurWireshark->getCbc() * 100 / $lecteurWireshark->getNbServeurs(), 4) . "%" ?></td>
                            <td><?php echo round($lecteurWireshark->getGcm() * 100 / $lecteurWireshark->getNbServeurs(), 4) . "%" ?></td>
                        </tr>
                        </tbody>
                    </table>
                </div>
            </div>
            <div class="col s4" style="margin-top: 200px">
                <div style="max-width:300px; max-height:300px; margin: auto">
                    <canvas id="hashfunction" width="100" height="100"></canvas>
                    <table class="bordered centered highlight">
                        <thead>
                        <tr>
                            <th>MD5</th>
                            <th>SHA</th>
                            <th>SHA 256</th>
                            <th>SHA 384</th>
                        </tr>
                        </thead>
                        <tbody>
                        <tr>
                            <td><?php echo round($lecteurWireshark->getMd5() * 100 / $lecteurWireshark->getNbServeurs(), 4) . "%" ?></td>
                            <td><?php echo round($lecteurWireshark->getSha() * 100 / $lecteurWireshark->getNbServeurs(), 4) . "%" ?></td>
                            <td><?php echo round($lecteurWireshark->getSha256() * 100 / $lecteurWireshark->getNbServeurs(), 4) . "%" ?></td>
                            <td><?php echo round($lecteurWireshark->getSha384() * 100 / $lecteurWireshark->getNbServeurs(), 4) . "%" ?></td>
                        </tr>
                        </tbody>
                    </table>
                </div>
            </div>
            <div class="col s4" style="margin-top: 450px">
                <div style="max-width:300px; max-height:300px; margin: auto">
                    <canvas id="exportYesNo" width="100" height="100"></canvas>
                    <table class="bordered centered highlight">
                        <thead>
                        <tr>
                            <th>YES</th>
                            <th>NO</th>
                        </tr>
                        </thead>
                        <tbody>
                        <tr>
                            <td><?php echo round($lecteurWireshark->getExport() * 100 / $lecteurWireshark->getNbServeurs(), 4) . "%" ?></td>
                            <td><?php echo 100 - (round($lecteurWireshark->getExport() * 100 / $lecteurWireshark->getNbServeurs(), 4)) . "%" ?></td>
                        </tr>
                        </tbody>
                    </table>
                </div>
            </div>
            <div class="col s4" style="margin-top: 450px">
                <div style="max-width:300px; max-height:300px; margin: auto">
                    <canvas id="extension" width="100" height="100"></canvas>
                    <table class="bordered centered highlight">
                        <thead>
                        <tr>
                            <th>Compression</th>
                            <th>Elliptic Curves</th>
                            <th>Sign Algo</th>
                            <th>Renegotiation</th>
                        </tr>
                        </thead>
                        <tbody>
                        <tr>
                            <td><?php echo round($lecteurWireshark->getCompression() * 100 / $lecteurWireshark->getNbServeurs(), 4) . "%" ?></td>
                            <td><?php echo round($lecteurWireshark->getEllipticCurves() * 100 / $lecteurWireshark->getNbServeurs(), 4) . "%" ?></td>
                            <td><?php echo round($lecteurWireshark->getSignatureAlgo() * 100 / $lecteurWireshark->getNbServeurs(), 4) . "%" ?></td>
                            <td><?php echo round($lecteurWireshark->getRenego() * 100 / $lecteurWireshark->getNbServeurs(), 4) . "%" ?></td>
                        </tr>
                        </tbody>
                    </table>
                    <table class="bordered centered highlight">
                        <thead>
                        <tr>
                            <th>Server Name</th>
                            <th>Heartbeat</th>
                            <th>Ec Points Formats</th>
                            <th>Session Ticket</th>
                        </tr>
                        </thead>
                        <tbody>
                        <tr>
                            <td><?php echo round($lecteurWireshark->getServerName() * 100 / $lecteurWireshark->getNbServeurs(), 4) . "%" ?></td>
                            <td><?php echo round($lecteurWireshark->getHeartbeatExtension() * 100 / $lecteurWireshark->getNbServeurs(), 4) . "%" ?></td>
                            <td><?php echo round($lecteurWireshark->getEcPointFormat() * 100 / $lecteurWireshark->getNbServeurs(), 4) . "%" ?></td>
                            <td><?php echo round($lecteurWireshark->getSessionTicket() * 100 / $lecteurWireshark->getNbServeurs(), 4) . "%" ?></td>
                        </tr>
                        </tbody>
                    </table>
                </div>
            </div>
            <div class="col s4" style="margin-top: 450px">
                <div style="max-width:300px; max-height:300px; margin: auto">
                    <canvas id="DNSdiffConfig" width="100" height="100"></canvas>
                    <table class="bordered centered highlight">
                        <thead>
                        <tr>
                            <th>DNS with same TLS configurations on its mail servers</th>
                            <th>DNS with different TLS configurations on its mail servers</th>
                        </tr>
                        </thead>
                        <tbody>
                        <tr>
                            <td><?php echo 100 - (round($lecteurWireshark->getNbDNSwithDiffConfig() * 100 / $lecteurWireshark->getNbServeurs(), 4)) . "%" ?></td>
                            <td><?php echo round($lecteurWireshark->getNbDNSwithDiffConfig() * 100 / $lecteurWireshark->getNbServeurs(), 4) . "%" ?></td>
                        </tr>
                        </tbody>
                    </table>
                </div>
            </div>
            <div class="col s4" style="margin-top: 400px">
                <table class="bordered centered highlight">
                    <thead>
                    <tr>
                        <th>Average number of mail servers per DNS</th>
                    </tr>
                    </thead>
                    <tbody>
                    <tr>
                        <td><?php echo $lecteurWireshark->getAverageNbOfMxPerDns(); ?></td>
                    </tr>
                    </tbody>
                </table>
            </div>

        </div>
    </div>
</div>
<!-- ------------------------------------------------------- END WIRESHARK ---------------------------------------------------------------------------- -->


<!-- ------------------------------------------------------- DEPRECATED CIPHERS---------------------------------------------------------------------------- -->
<div class="section scrollspy" id="sslscan">
    <!-- RECOVER DATAS -->
    <?php $arrayDeprecated = $lecteurDeprecated->getDeprecatedCipherSuite();
    $nbCipherDeprecated = count($arrayDeprecated);
    ?><input type="hidden" id="nbciphersuitedeprecated" value="<?php echo $nbCipherDeprecated; ?>"/>
    <input type="hidden" id="nbtestedservers" value="<?php echo $lecteurDeprecated->getNbTestedServers(); ?>"/><?php
    $i = 0;
    foreach ($arrayDeprecated as $cipher) {
        ?><input type="hidden" id="cipherDeprecated<?php echo $i ?>" value="<?php echo $cipher->toString(); ?>"/>
        <?php
        $i++;
    }
    ?>

    <div class="container center-align">
        <h3 class="header text_b">Analysis of deprecated Cipher Suites allowed </h3>
        <div class="row">
            <div class="s12" style="margin-top: 50px;">
                <div style="height: 200px; width: 1200px; margin: auto">
                    <canvas id="mediumciphersuitedeprecated" width="600" height="300"></canvas>
                </div>
            </div>
            <div class="s12" style="margin-top: 450px;">
                <div style="height: 200px; width: 1200px; margin: auto">
                    <canvas id="lowciphersuitedeprecated" width="600" height="300"></canvas>
                </div>
            </div>
        </div>
    </div>
</div>
<!-- ------------------------------------------------------- END DEPRECATED CIPHERS ---------------------------------------------------------------------------- -->


<!-- ------------------------------------------------------- TESTSSL.sh ---------------------------------------------------------------------------- -->
<div class="section scrollspy" style="margin-top: 500px" id="testssl"><!-- class blue lighten-5 -->
    <!-- RECOVER DATAS -->
    <input type="hidden" id="nbServTestssl" value="<?php echo $lecteurTestSSLMX->getNbServ(); ?>"/>
    <input type="hidden" id="nbCourtoi" value="<?php echo $lecteurTestSSLMX->getCourtoi(); ?>"/>
    <input type="hidden" id="nbHeartbleedAttaque" value="<?php echo $lecteurTestSSLMX->getHeartbeatAttaque(); ?>"/>
    <input type="hidden" id="nbCssAttaque" value="<?php echo $lecteurTestSSLMX->getCssAttaque(); ?>"/>
    <input type="hidden" id="nbSecureRenegoAttaque" value="<?php echo $lecteurTestSSLMX->getSecureRenegoAttaque(); ?>"/>
    <input type="hidden" id="nbSecClientRenegoAttaque" value="<?php echo $lecteurTestSSLMX->getSecClientRenegoAttaque(); ?>"/>
    <input type="hidden" id="nbCrimeAttaque" value="<?php echo $lecteurTestSSLMX->getCrimeAttaque(); ?>"/>
    <input type="hidden" id="nbPoodleAttaque" value="<?php echo $lecteurTestSSLMX->getPoodleAttaque(); ?>"/>
    <input type="hidden" id="nbFallbackAttaque" value="<?php echo $lecteurTestSSLMX->getFallbackScsvAttaque(); ?>"/>
    <input type="hidden" id="nbFreackAttaque" value="<?php echo $lecteurTestSSLMX->getFreakAttaque(); ?>"/>
    <input type="hidden" id="nbDrownAttaque" value="<?php echo $lecteurTestSSLMX->getDrownAttaque(); ?>"/>
    <input type="hidden" id="nbLogjamAttaque" value="<?php echo $lecteurTestSSLMX->getLogjamAttaque(); ?>"/>
    <input type="hidden" id="nbBeastAttaque" value="<?php echo $lecteurTestSSLMX->getBeastAttaque(); ?>"/>
    <input type="hidden" id="nbCbcTls1Attaque" value="<?php echo $lecteurTestSSLMX->getCbcTls1Attaque(); ?>"/>
    <input type="hidden" id="nbCbcSsl3Attaque" value="<?php echo $lecteurTestSSLMX->getCbcSsl3Attaque(); ?>"/>
    <input type="hidden" id="nbRC4Attaque" value="<?php echo $lecteurTestSSLMX->getRc4Attaque(); ?>"/>

    <div class="container center-align">
        <h3 class="header text_b">Analysis vulnerabilities of servers </h3>
        <div class="row">
            <div class="col s6" style="margin-top: 50px">
                <div style="max-width:600px; max-height:600px; margin: auto">
                    <canvas id="vulnerabilities" width="100" height="100"></canvas>
                </div>
            </div>
            <div class="col s6" style="margin-top: 50px">
                <div style="max-width:500px; max-height:500px; margin: auto">
                    <canvas id="courtoiOuDirectif" width="100" height="100"></canvas>
                    <table class="bordered centered highlight">
                        <thead>
                        <tr>
                            <th>Has an ordered cipher list</th>
                            <th>Has not an ordered cipher list</th>
                        </tr>
                        </thead>
                        <tbody>
                        <tr>
                            <td><?php echo 100 - (round($lecteurTestSSLMX->getCourtoi() * 100 / $lecteurTestSSLMX->getNbServ(), 4)) . "%" ?></td>
                            <td><?php echo round($lecteurTestSSLMX->getCourtoi() * 100 / $lecteurTestSSLMX->getNbServ(), 4) . "%" ?></td>
                        </tr>
                        </tbody>
                    </table>
                </div>
            </div>
        </div>
    </div>
</div>
<!-- -------------------------------------------------------------- END TESTSSL.sh ------------------------------------------------------------------>


<!--Footer-->
<footer id="contact" class="page-footer default_color scrollspy">

    <div class="container">
        <div class="row">
            <div class="col s12 m6 l6">
                <h5 class="white-text">EMSEC: <i>Embedded Security and Cryptography</i></h5>
                <img src="img/irisa.png" width="300px"/></br>
                <img src="img/emsec.png" width="300px" margin-left="50px"/>
            </div>
            <div class="col s12 m4 l4 offset-l2">
                <h5 class="white-text">Our Team</h5>
                <ul>
                    <li><a class="grey-text text-lighten-3 valign-wrapper" href="https://www.irisa.fr/fr/equipes/emsec"><img class="responsive-img circle" src="img/logoIrisa.png"
                                                                                                                             width="40px">
                            <div class="footerText">Irisa Research Lab</div>
                        </a></li>
                    </br>
                    <li><a class="grey-text text-lighten-3 valign-wrapper" href="https://twitter.com/emsec35"><img class="responsive-img circle" src="img/twitter.png">
                            <div class="footerText">Twitter</div>
                        </a></li>
                </ul>
            </div>
        </div>
    </div>
    <div class="footer-copyright">
        <div class="container ">
            2017 Copyright EMSEC team
            <a class="grey-text text-lighten-4 right" href="#">More Details</a>
        </div>
    </div>
</footer>


<!--  Scripts-->
<script src="min/plugin-min.js"></script>
<script src="min/custom-min.js"></script>

</body>

<script type="text/javascript" src="./js/diagrammes.js"></script>
<script type="text/javascript" src="./js/chargementResultat.js"></script>
<script src="https://cdnjs.cloudflare.com/ajax/libs/Chart.js/2.3.0/Chart.bundle.js"></script> <!-- ChartJs -->
<script src="https://cdnjs.cloudflare.com/ajax/libs/jquery/3.2.1/jquery.js"></script> <!-- JQuery -->
<script type="text/javascript" src="js/materialize.min.js"></script>

</html>
