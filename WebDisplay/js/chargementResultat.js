
$("#formulaireWireshark").submit(function(e){ // On sélectionne le formulaire par son identifiant
        e.preventDefault(); // Le navigateur ne peut pas envoyer le formulaire

        var res = document.getElementById("resultfileWireshark").value;

    $.post(
        'createLecteur.php', // Le fichier cible côté serveur.
        {
            nomFichier : res,
            type : "wireshark"
        },
        nom_fonction_retour, // le nom de la fonction de retour.
        'text' // Format des données reçues.
    );


    function nom_fonction_retour(texte_recu){
        alert("Reception: "+texte_recu);
    }
});

