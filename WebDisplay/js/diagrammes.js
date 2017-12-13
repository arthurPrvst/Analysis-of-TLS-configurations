$(document).ready(function(){
    Chart.plugins.register({
        afterDraw: function(chartInstance) {
            if (chartInstance.config.options.showDatapoints) {
                var helpers = Chart.helpers;
                var ctx = chartInstance.chart.ctx;
                var fontColor = helpers.getValueOrDefault(chartInstance.config.options.showDatapoints.fontColor, chartInstance.config.options.defaultFontColor);

                // render the value of the chart above the bar
                ctx.font = Chart.helpers.fontString(Chart.defaults.global.defaultFontSize, 'normal', Chart.defaults.global.defaultFontFamily);
                ctx.textAlign = 'center';
                ctx.textBaseline = 'bottom';
                ctx.fillStyle = fontColor;

                chartInstance.data.datasets.forEach(function (dataset) {
                    for (var i = 0; i < dataset.data.length; i++) {
                        var model = dataset._meta[Object.keys(dataset._meta)[0]].data[i]._model;
                        var scaleMax = dataset._meta[Object.keys(dataset._meta)[0]].data[i]._yScale.maxHeight;
                        var yPos = (scaleMax - model.y) / scaleMax >= 0.93 ? model.y + 20 : model.y - 5;
                        ctx.fillText(dataset.data[i]+"%", model.x, yPos);
                    }
                });
            }
        }
    });

    generateHighMediumLowRepartition();
    generateVersionTls();
    generateKeyExchangeAlgo();
    generateSignatureAlgo();
    generateCipher();
    generateBlockMode();
    generateHashFunction();
    generateExport();
    generateExtension();
    generateCipherSuite();
    generateDeprecatedCipherSuite();
    generateDNSdiffConfig();
    generateVulnerabilities();
    generateCourtoiDirectif();
});

function arrondi (nb,nbserveurs){
    res = (nb*100)/nbserveurs;
    return Math.round(res*10000)/10000; //quatre chiffres apres la virgule
}

function arrondi2 (nb,nbserveurs){
    res = (nb*100)/nbserveurs;
    return Math.round(res*100)/100; //2 chiffres apres la virgule
}

//Generate byte between 1 and 255
function getRandomColorBytes() {
    return Math.floor((Math.random() * 255) + 1);
}

function generateHighMediumLowRepartition(){
    var nbServ = document.getElementById("nbServeurs").value;
    var low = document.getElementById("nbLow").value;
    var medium = document.getElementById("nbMedium").value;
    var high = document.getElementById("nbHigh").value;


    new Chart(document.getElementById("high_medium_low"), {
        type: 'doughnut',
        data: {
            labels: ["Low security", "Medium security", "High security"],
            datasets: [
                {
                    label: "Distribution of cipher suites",
                    backgroundColor: ["#c45850", "#F4661B", "#5cca7c"],
                    data: [arrondi(low,nbServ), arrondi(medium,nbServ), arrondi(high,nbServ)]
                }
            ]
        },
        options: {
            title: {
                display: true,
                text: 'Distribution of cipher suites (%)'
            }
        }
    });
}

function getCipherClass(cipher){ // There is 3 class: MUST (1) / SHOULD NOT (0) / MUST NOT (-1), with this return values
    var mustnotClass = ['_DES_','NULL','MD5','RC4' ,'EXPORT','EXP','CK','PSK','FIPS','RC2','KRB5','SSL'];     //Attribute of MUST NOT CLASS
    var shouldnotClass = ['SEED', '3DES', 'IDEA','SHA_','TLS_RSA','ADH','AECDH','ADHE','SCSV','AECDHE'];     //Attribute of SHOULD NOT CLASS

    var isMustNot = 0;
    var isShouldNot = 0;
    var cipherUpp = cipher.toUpperCase();
    var cipherUppe = cipherUpp.replace(/-/g, "_");
    var cipherUpper = "_"+cipherUppe;

    mustnotClass.forEach(function(element) {
        if(cipherUpper.indexOf(element) != -1) {
            isMustNot = 1;
            return -1; //Attributes of MUST NOT CLASS FOUND
        }
    });

    shouldnotClass.forEach(function(element) {
        if(cipherUpper.indexOf(element) != -1) {
            isShouldNot =1;
            return 0; //Attributes of MUST NOT CLASS FOUND
        }
    });

   if(isMustNot == 1){
       return -1;
   }
   else if(isShouldNot == 1){
       return 0;
   }else{
       return 1;
   }

}

function generateSignatureAlgo(){
    var nbServeurs = document.getElementById("nbServeurs").value;
    var nbRsaSignature = document.getElementById("rsa_signature").value;
    var nbEcdsaSignature = document.getElementById("ecdsa_signature").value;
    var nbDssSignature = document.getElementById("dss_signature").value;

    new Chart(document.getElementById("SignatureAlgorithm"), {
        type: 'doughnut',
        data: {
            labels: ["RSA", "ECDSA", "DSS"],
            datasets: [
                {
                    label: "Signature Algorithm",
                    backgroundColor: ["#3cba9f", "#5cca7c", "#c45850"],
                    data: [arrondi(nbRsaSignature,nbServeurs), arrondi(nbEcdsaSignature,nbServeurs),arrondi(nbDssSignature,nbServeurs)]
                }
            ]
        },
        options: {
            title: {
                display: true,
                text: 'Signature Algorithm (%)'
            }
        }
    });
}

function generateCourtoiDirectif(){
    var nbServ = document.getElementById("nbServTestssl").value;
    var courtoi = document.getElementById("nbCourtoi").value;
    var tot =100-arrondi(courtoi,nbServ);
    var nbDirectif = Math.round(tot*10000)/10000;

    new Chart(document.getElementById("courtoiOuDirectif"), {
        type: 'doughnut',
        data: {
            labels: ["Has an ordered cipher list", "Has NOT an ordered cipher list"],
            datasets: [
                {
                    label: "Servers following client\'s cipher suites list order (%)",
                    backgroundColor: ["#3cba9f", "#c45850"],
                    data: [nbDirectif, arrondi(courtoi,nbServ)]
                }
            ]
        },
        options: {
            title: {
                display: true,
                text: 'Servers following client\'s cipher suites list order (%)'
            }
        }
    });
}

function generateVulnerabilities(){
    var nbServ = document.getElementById("nbServTestssl").value;
    var heartBleedAttaque = document.getElementById("nbHeartbleedAttaque").value;
    var cssAttaque = document.getElementById("nbCssAttaque").value;
    var secureRenegoAttaque = document.getElementById("nbSecureRenegoAttaque").value;
    var secClientRenegoAttaque = document.getElementById("nbSecClientRenegoAttaque").value;
    var crimeAttaque = document.getElementById("nbCrimeAttaque").value;
    var poodleAttaque = document.getElementById("nbPoodleAttaque").value;
    var fallbackAttaque = document.getElementById("nbFallbackAttaque").value;
    var freackAttaque = document.getElementById("nbFreackAttaque").value;
    var drownAttaque = document.getElementById("nbDrownAttaque").value;
    var logjamAttaque = document.getElementById("nbLogjamAttaque").value;
    var beastAttaque = document.getElementById("nbBeastAttaque").value;
    var beastTlsAttaque = document.getElementById("nbCbcTls1Attaque").value;
    var beastSslAttaque = document.getElementById("nbCbcSsl3Attaque").value;
    var rc4Attaque = document.getElementById("nbRC4Attaque").value;

    new Chart(document.getElementById("vulnerabilities"), {
        type: 'bar',
        data: {
            labels: ["HeartBleed", "CSS", "Secure Renegotiation", "Secure Client Renegotiation", "Poodle", "Fallback SCSV", "Freack", "Drown", "LogJam", "Beast","CBC_TLS1","CBC_SSL3"],
            datasets: [
                {
                    label: "Vulnerabilities ",
                    backgroundColor: ["#c45850", "#c45850","#c45850","#c45850","#F4661B","#c45850","#c45850","#c45850","#c45850","#c45850","#c45850","#c45850"],
                    data: [arrondi2(heartBleedAttaque,nbServ), arrondi2(cssAttaque,nbServ), arrondi2(secureRenegoAttaque,nbServ), arrondi2(secClientRenegoAttaque,nbServ), arrondi2(poodleAttaque,nbServ), arrondi2(fallbackAttaque,nbServ), arrondi2(freackAttaque,nbServ), arrondi2(drownAttaque,nbServ), arrondi2(logjamAttaque,nbServ), arrondi2(beastAttaque,nbServ), arrondi2(beastTlsAttaque,nbServ),arrondi2(beastSslAttaque,nbServ)]
                }
            ]
        },
        options: {
            showDatapoints: true,
            legend: { display: false },
            title: {
                display: true,
                text: 'Vulnerabilities (%)'
            },
            scales: {
                xAxes: [{
                    stacked: false,
                    beginAtZero: true,
                    ticks: {
                        stepSize: 1,
                        min: 0,
                        autoSkip: false
                    }
                }]
            }
        }
    });
}

function generateDNSdiffConfig(){
    var nbDns = document.getElementById("nbDns").value;
    var nbDnsDiffConfig = document.getElementById("nbDNSWithDiffConfig").value;

    new Chart(document.getElementById("DNSdiffConfig"), {
        type: 'doughnut',
        data: {
            labels: ["DNS with different cipher suite", "DNS with same cipher suite"],
            datasets: [
                {
                    label: "Use of Export",
                    backgroundColor: ["#c45850", "#3cba9f"],
                    data: [arrondi(nbDnsDiffConfig,nbDns), 100-arrondi(nbDnsDiffConfig,nbDns)]
                }
            ]
        },
        options: {
            title: {
                display: true,
                text: 'DNS with different Cipher Suite (%)'
            }
        }
    });
}

function generateDeprecatedCipherSuite(){
    var nbServeurs = document.getElementById("nbtestedservers").value;
    var nbCipherSuite = document.getElementById("nbciphersuitedeprecated").value;
    var i;
    var cipherSuites = [];
    var label = [];
    var labelSorted = [];
    var datas = [];
    var datasSorted = [];
    var fillingColors = [];

    for (i = 0; i < nbCipherSuite; i++) { //rempli de tableau de cipher suites: "Cipher Suite : TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384 with 286 entities"
        cipherSuites.push(document.getElementById("cipherDeprecated"+i).value);
        var tab = cipherSuites[i].split(" ");
        label[i]=tab[3];
        datas[i]=arrondi(tab[5],nbServeurs);
    }

    //Sort arrays
    var pos = 0;
    for(var i =0; i<nbCipherSuite; i++) {
        var max = -1;
        var indiceDuMax = -1;
        for (var y = 0; y < nbCipherSuite; y++) {
            if(datas[y]>=max){
                max=datas[y];
                indiceDuMax=y;
            }
        }
        datasSorted[pos]=datas[indiceDuMax];
        labelSorted[pos]=label[indiceDuMax];

        //Generate FillingColor tab according to the class of the cipher suites (MUST (1) / SHOULD NOT (0) / MUST NOT (-1) )
        var res = getCipherClass(labelSorted[pos]);
        if(res == 1){
            fillingColors[i]="#5cca7c"; //Green
        }else if(res == 0){
            fillingColors[i]="#F4661B";//Yellow
        }else if (res == -1){
            fillingColors[i]="#c45850";//Red
        }

        pos++;
        datas[indiceDuMax]=-1;
        label[indiceDuMax]=-1;
    }

    var datasSortedMedium = [];
    var datasSortedLow = [];
    var labelSortedMedium = [];
    var labelSortedLow = [];
    var fillingColorsMedium = [];
    var fillingColorsLow = [];

    var medium = 0;
    var low = 0;
    for(var i =0; i<nbCipherSuite; i++){
        if(fillingColors[i]=="#F4661B"){
            datasSortedMedium[medium]=datasSorted[i];
            labelSortedMedium[medium]=labelSorted[i];
            fillingColorsMedium[medium]=fillingColors[i];
            medium++;
        }else if(fillingColors[i]=="#c45850"){
            datasSortedLow[low]=datasSorted[i];
            labelSortedLow[low]=labelSorted[i];
            fillingColorsLow[low]=fillingColors[i];
            low++;
        }
    }
    new Chart(document.getElementById("mediumciphersuitedeprecated"), {
        type: 'bar',
        data: {
            labels: labelSortedMedium,
            datasets: [
                {
                    label: "Deprecated Cipher Suite",
                    backgroundColor: fillingColorsMedium,
                    data: datasSortedMedium,
                }
            ]
        },
        options: {
            showDatapoints: true,
            legend: { display: false },
            title: {
                display: true,
                text: 'Deprecated cipher suites allowed - Medium security (%)'
            },
            scales: {
                xAxes: [{
                    stacked: false,
                    ticks: {
                        stepSize: 1,
                        min: 0,
                        autoSkip: false
                    }
                }]
            }
        }
    });
    new Chart(document.getElementById("lowciphersuitedeprecated"), {
        type: 'bar',
        data: {
            labels: labelSortedLow,
            datasets: [
                {
                    label: "Deprecated Cipher Suite",
                    backgroundColor: fillingColorsLow,
                    data: datasSortedLow,
                }
            ]
        },
        options: {
            legend: { display: false },
            title: {
                display: true,
                text: 'Deprecated cipher suites allowed - Low security (%)'
            },
            scales: {
                xAxes: [{
                    stacked: false,
                    ticks: {
                        stepSize: 1,
                        min: 0,
                        autoSkip: false
                    }
                }]
            }
        }
    });
}

function generateCipherSuite(){
    var nbServeurs = document.getElementById("nbServeurs").value;
    var nbCipherSuite = document.getElementById("nbciphersuite").value;
    var i;
    var cipherSuites = [];
    var label = [];
    var labelSorted = [];
    var datas = []; //array of %
    var datasSorted = [];
    var fillingColors = [];

    for (i = 0; i < nbCipherSuite; i++) { //rempli de tableau de cipher suites: "Cipher Suite : TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384 with 286 entities"
        cipherSuites.push(document.getElementById("cipher"+i).value);
        var tab = cipherSuites[i].split(" ");
        label[i]=tab[3];
        datas[i]=arrondi(tab[5],nbServeurs);
    }

    //Generate FillingColor tab randomly
    /*for (var y = 0; y < nbCipherSuite; y++) {
        for (var z = 0; z < 4; z++) {
            if (z == 0) {
                fillingColors[y] = 'rgba(' + getRandomColorBytes() + ',';
            } else if (z == 3) {
                fillingColors[y] += 0.6 + ')';
            } else {
                fillingColors[y] += getRandomColorBytes() + ',';
            }
        }
    }*/

    //Sort arrays
    var pos = 0;
    for(var i =0; i<nbCipherSuite; i++) {
        var max = -1;
        var indiceDuMax = -1;
        for (var y = 0; y < nbCipherSuite; y++) {
            if(datas[y]>=max){
                max=datas[y];
                indiceDuMax=y;
            }
        }
        datasSorted[pos]=datas[indiceDuMax];
        labelSorted[pos]=label[indiceDuMax];

        //Generate FillingColor tab according to the class of the cipher suites (MUST (1) / SHOULD NOT (0) / MUST NOT (-1) )
        var res = getCipherClass(labelSorted[pos]);
        if(res == 1){
            fillingColors[i]="#5cca7c"; //Green
        }else if(res == 0){
            fillingColors[i]="#F4661B";//Yellow
        }else if (res == -1){
            fillingColors[i]="#c45850";//Red
        }

        pos++;
        datas[indiceDuMax]=-1;
        label[indiceDuMax]=-1;
    }

    var datasSortedHigh = [];
    var datasSortedMedium = [];
    var datasSortedLow = [];
    var labelSortedHigh = [];
    var labelSortedMedium = [];
    var labelSortedLow = [];
    var fillingColorsHigh = [];
    var fillingColorsMedium = [];
    var fillingColorsLow = [];

    var high = 0;
    var medium = 0;
    var low = 0;
    for(var i =0; i<nbCipherSuite; i++){
        if(fillingColors[i]=="#5cca7c"){ //HIGH
            datasSortedHigh[high]=datasSorted[i];
            labelSortedHigh[high]=labelSorted[i];
            fillingColorsHigh[high]=fillingColors[i];
            high++;
        }else if(fillingColors[i]=="#F4661B"){
            datasSortedMedium[medium]=datasSorted[i];
            labelSortedMedium[medium]=labelSorted[i];
            fillingColorsMedium[medium]=fillingColors[i];
            medium++;
        }else if(fillingColors[i]=="#c45850"){
            datasSortedLow[low]=datasSorted[i];
            labelSortedLow[low]=labelSorted[i];
            fillingColorsLow[low]=fillingColors[i];
            low++;
        }
    }


    new Chart(document.getElementById("highciphersuite"), {
        type: 'bar',
        data: {
            labels: labelSortedHigh,
            datasets: [
                {
                    label: "Cipher Suite",
                    backgroundColor: fillingColorsHigh,
                    data: datasSortedHigh,
                }
            ]
        },
        options: {
            showDatapoints: true,
            legend: { display: false },
            title: {
                display: true,
                text: 'High Cipher Suites (%)'
            },
            scales: {
                xAxes: [{
                    stacked: false,
                    beginAtZero: true,
                    ticks: {
                        stepSize: 1,
                        min: 0,
                        autoSkip: false
                    }
                }]
            }
        }
    });
    new Chart(document.getElementById("mediumciphersuite"), {
        type: 'bar',
        data: {
            labels: labelSortedMedium,
            datasets: [
                {
                    label: "Cipher Suite",
                    backgroundColor: fillingColorsMedium,
                    data: datasSortedMedium,
                }
            ]
        },
        options: {
            showDatapoints: true,
            legend: { display: false },
            title: {
                display: true,
                text: 'Medium Cipher Suites (%)'
            },
            scales: {
                xAxes: [{
                    stacked: false,
                    beginAtZero: true,
                    ticks: {
                        stepSize: 1,
                        min: 0,
                        autoSkip: false
                    }
                }]
            }
        }
    });
    new Chart(document.getElementById("lowciphersuite"), {
        type: 'bar',
        data: {
            labels: labelSortedLow,
            datasets: [
                {
                    label: "Cipher Suite",
                    backgroundColor: fillingColorsLow,
                    data: datasSortedLow,
                }
            ]
        },
        options: {
            showDatapoints: true,
            legend: { display: false },
            title: {
                display: true,
                text: 'Low Cipher Suites (%)'
            },
            scales: {
                xAxes: [{
                    stacked: false,
                    beginAtZero: true,
                    ticks: {
                        stepSize: 1,
                        min: 0,
                        autoSkip: false
                    }
                }]
            }
        }
    });
}

function generateExtension(){
    var nbServeurs = document.getElementById("nbServeurs").value;
    var comp = document.getElementById("compression").value;
    var renego = document.getElementById("renego").value;
    var heartbeat = document.getElementById("heartbeat").value;
    var sessionticket = document.getElementById("sessionticket").value;
    var ecpointsformats = document.getElementById("ecpointsformats").value;
    var elliptic_curves = document.getElementById("elliptic_curves").value;
    var signature_algorithms = document.getElementById("signature_algorithms").value;
    var server_name = document.getElementById("server_name").value;

    new Chart(document.getElementById("extension"), {
        type: 'bar',
        data: {
            labels: ["Compression", "Renegociation", "Heartbeat", "Session Ticket", "Ec Points Formats", "Elliptic Curves", "Signature Algorithms", "Server Name"],
            datasets: [
                {
                    label: "Extension ",
                    backgroundColor: ["#c45850", "#F4661B","#3cba9f","#3cba9f","#3cba9f","#3cba9f","#3cba9f","#3cba9f"],
                    data: [arrondi2(comp,nbServeurs), arrondi2(renego,nbServeurs), arrondi2(heartbeat,nbServeurs), arrondi2(sessionticket,nbServeurs), arrondi2(ecpointsformats,nbServeurs), arrondi2(elliptic_curves,nbServeurs), arrondi2(signature_algorithms,nbServeurs), arrondi2(server_name,nbServeurs)]
                }
            ]
        },
        options: {
            showDatapoints: true,
            legend: { display: false },
            title: {
                display: true,
                text: 'Extension (%)'
            },
            scales: {
                xAxes: [{
                    stacked: false,
                    beginAtZero: true,
                    ticks: {
                        stepSize: 1,
                        min: 0,
                        autoSkip: false
                    }
                }]
            }
        }
    });
}

function generateExport(){
    var nbServeurs = document.getElementById("nbServeurs").value;
    var exp = document.getElementById("export").value;

    new Chart(document.getElementById("exportYesNo"), {
        type: 'doughnut',
        data: {
            labels: ["YES", "NO"],
            datasets: [
                {
                    label: "Use of Export",
                    backgroundColor: ["#c45850", "#3cba9f"],
                    data: [arrondi(exp,nbServeurs), 100-arrondi(exp,nbServeurs)]
                }
            ]
        },
        options: {
            title: {
                display: true,
                text: 'Use of Export (%)'
            }
        }
    });
}

function generateHashFunction(){
    var nbServeurs = document.getElementById("nbServeurs").value;
    var md5 = document.getElementById("md5").value;
    var sha = document.getElementById("sha").value;
    var sha256 = document.getElementById("sha256").value;
    var sha384 = document.getElementById("sha384").value;

    new Chart(document.getElementById("hashfunction"), {
        type: 'doughnut',
        data: {
            labels: ["MD5", "SHA", "SHA 256", "SHA 384"],
            datasets: [
                {
                    label: "Hash Function",
                    backgroundColor: ["#c45850", "#F4661B", "#7FDD4C","#3cba9f"],
                    data: [arrondi(md5,nbServeurs), arrondi(sha,nbServeurs), arrondi(sha256,nbServeurs), arrondi(sha384,nbServeurs)]
                }
            ]
        },
        options: {
            title: {
                display: true,
                text: 'Hash Function (%)'
            }
        }
    });
}

function generateBlockMode(){
    var nbServeurs = document.getElementById("nbServeurs").value;
    var cbc = document.getElementById("cbc").value;
    var gcm = document.getElementById("gcm").value;

    new Chart(document.getElementById("blockmode"), {
        type: 'doughnut',
        data: {
            labels: ["CBC", "GCM"],
            datasets: [
                {
                    label: "Block Mode",
                    backgroundColor: ["#F4661B", "#3cba9f"],
                    data: [arrondi(cbc,nbServeurs), arrondi(gcm,nbServeurs)]
                }
            ]
        },
        options: {
            title: {
                display: true,
                text: 'Block Mode (%)'
            }
        }
    });
}

function generateCipher() {

    var nbServeurs = document.getElementById("nbServeurs").value;
    var troisdesEde = document.getElementById("troisDesEde").value;
    var aes128cbc = document.getElementById("aes128cbc").value;
    var aes256cbc = document.getElementById("aes256cbc").value;
    var aes128gcm = document.getElementById("aes128gcm").value;
    var aes256gcm = document.getElementById("aes256gcm").value;

    var camellia256 = document.getElementById("camellia256").value;
    var rc4 = document.getElementById("rc4").value;
    var seed = document.getElementById("seed").value;
    var idea = document.getElementById("idea").value;

    new Chart(document.getElementById("cipher"), {
        type: 'doughnut',
        data: {
            labels: ["IDEA", "RC4",  "SEED", "3DES EDE", "AES 128 CBC", "AES 256 CBC", "AES 128 GCM","AES 256 GCM", "CAMELLIA 256"],
            datasets: [
                {
                    label: "Cipher",
                    backgroundColor: ["#960018", "#FF0000", "#FF6347", "#c45850", "#F4661B", "#FF8C00","#B0F2B6", "#90EE90","#3cba9f"],
                    data: [ arrondi(idea,nbServeurs), arrondi(rc4,nbServeurs), arrondi(seed,nbServeurs), arrondi(troisdesEde,nbServeurs), arrondi(aes128cbc,nbServeurs), arrondi(aes256cbc,nbServeurs), arrondi(aes128gcm,nbServeurs), arrondi(aes256gcm,nbServeurs), arrondi(camellia256,nbServeurs)]
                }
            ]
        },
        options: {
            title: {
                display: true,
                text: 'Cipher (%)'
            }
        }
    });
}


function generateKeyExchangeAlgo() {

    var nbServeurs = document.getElementById("nbServeurs").value;
    var nbRsa = document.getElementById("rsa").value;
    var nbDhe = document.getElementById("dhe").value;
    var nbEcdhe = document.getElementById("ecdhe").value;
    var nbEcdh = document.getElementById("ecdh").value;


    new Chart(document.getElementById("KeyExchangeAlgorithm"), {
        type: 'doughnut',
        data: {
            labels: ["RSA", "DHE", "ECDHE", "ECDH"],
            datasets: [
                {
                    label: "Key Exchange Algorithm",
                    backgroundColor: ["#c45850", "#7FDD4C", "#3cba9f", "#5cca7c"],
                    data: [arrondi(nbRsa,nbServeurs), arrondi(nbDhe,nbServeurs),arrondi(nbEcdhe,nbServeurs), arrondi(nbEcdh,nbServeurs)]
                }
            ]
        },
        options: {
            title: {
                display: true,
                text: 'Key Exchange Algorithm (%)'
            }
        }
    });
}

function generateVersionTls() {

    var nbServeurs = document.getElementById("nbServeurs").value;
    var nbSSL2 = document.getElementById("nbSSL2").value;
    var nbSSL3 = document.getElementById("nbSSL3").value;
    var nbTLS10 = document.getElementById("nbTLS10").value;
    var nbTLS11 = document.getElementById("nbTLS11").value;
    var nbTLS12 = document.getElementById("nbTLS12").value;

    new Chart(document.getElementById("versionTls"), {
        type: 'doughnut',
        data: {
            labels: ["SSL 2.0", "SSL 3.0", "TLS 1.0", "TLS 1.1", "TLS 1.2"],
            datasets: [
                {
                    label: "SSL/TLS Version",
                    backgroundColor: ["#960018", "#c45850", "#F4661B", "#7FDD4C", "#3cba9f"],
                    data: [arrondi(nbSSL2,nbServeurs), arrondi(nbSSL3,nbServeurs),arrondi(nbTLS10,nbServeurs) ,arrondi(nbTLS11,nbServeurs) , arrondi(nbTLS12,nbServeurs)]
                }
            ]
        },
        options: {
            title: {
                display: true,
                text: 'SSL/TLS Versions (%)'
            }
        }
    });
}

