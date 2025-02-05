// Fonctions utilitaires
function showSpinner() {
    document.getElementById("spinner-container").style.display = "flex";
}

function hideSpinner() {
    document.getElementById("spinner-container").style.display = "none";
}

function showSuccessMessage(title, text) {
    Swal.fire({
        icon: "success",
        title: title,
        text: text,
        timer: 1000,
        showConfirmButton: false,
        toast: true,     
    });
}

function showErrorMessage(title, text) {
    Swal.fire({
        icon: "error",
        title: title,
        text: text,
        confirmButtonText: "OK"
    });
}

function showWarningMessage(title, text) {
    return Swal.fire({
        title: title,
        text: text,
        icon: "warning",
        showCancelButton: true,
        confirmButtonColor: "#3085d6",
        cancelButtonColor: "#d33",
        confirmButtonText: "Oui, continuer"
    });
}

// Récupérer le jeton CSRF depuis le serveur
let csrfToken = '';

async function fetchCsrfToken() {
    try {
        const response = await fetch('/get-csrf-token', { credentials: "include" });
        const data = await response.json();
        
        let csrfField = document.getElementById("csrf_token");
        if (!csrfField) {
            console.error("Erreur: Le champ `csrf_token` est introuvable dans le DOM.");
            return;
        }

        csrfField.value = data.csrf_token;  // Met à jour le champ HTML caché
        csrfToken = data.csrf_token;  // Met à jour la variable globale
        
    } catch (error) {
        console.error("Erreur lors de la récupération du jeton CSRF:", error);
    }
}


document.addEventListener("DOMContentLoaded", async function () {
    await fetchCsrfToken();
    refreshAll();
    checkAuth();
	flatpickr.localize(flatpickr.l10ns.fr);
    // Initialiser Flatpickr sur le champ de date
    flatpickr("#nouvelleJournee", {
        dateFormat: "d-m-Y",  // Format de date
        allowInput: true,     // Permettre la saisie manuelle
        locale: "fr",         // Localisation en français
    });
});



// Fonctions d'authentification
async function login() {
    const usernameField = document.getElementById("username");
    const passwordField = document.getElementById("password");
    const csrfTokenField = document.getElementById("csrf_token");
	await fetchCsrfToken(); // Récupérer un token CSRF avant chaque requête critique
    if (!usernameField || !passwordField || !csrfTokenField) {
        console.error("Erreur: Un des champs du formulaire de connexion est introuvable.");
        showErrorMessage('Erreur','Un problème est survenu. Veuillez recharger la page.');
        return;
    }

    const username = usernameField.value.trim();
    const password = passwordField.value.trim();
    const csrfToken = csrfTokenField.value.trim();

    if (!username || !password) {
        showErrorMessage('Erreur','Veuillez entrer un nom d\'utilisateur et un mot de passe.');
        return;
    }

    showSpinner();
    try {
        const response = await fetch("/login", {
            method: "POST",
            credentials: "include",
            headers: {
                "Content-Type": "application/json",
                "X-CSRF-Token": csrfToken
            },
            body: JSON.stringify({ username, password }),
        });

        if (!response.ok) {
            const errorData = await response.json();
            throw new Error(errorData.message || 'Connexion échouée.');
        }

        const data = await response.json();
        showSuccessMessage('Succès','Connexion réussie !');

        // Récupérer à nouveau le CSRF après connexion
        await fetchCsrfToken();
        checkAuth();
    } catch (error) {
        console.error("Erreur:", error);
        showErrorMessage('Erreur', error.message || 'Une erreur est survenue.' );
    } finally {
        hideSpinner();
    }
}

async function logout() {
    showSpinner();
	await fetchCsrfToken(); // Récupérer un token CSRF avant chaque requête critique
    try {
        const response = await fetch("/logout", {
            method: "POST",
			credentials: "include",
            headers: {
                "X-CSRF-Token": csrfToken
            }
        });
        if (response.ok) {
            showSuccessMessage('Succès','Déconnexion réussie !');

            // Supprimer le rôle de sessionStorage
            sessionStorage.removeItem("role");

            // Rafraîchir les données pour mettre à jour l'affichage
            checkAuth();
        }
    } catch (error) {
        console.error("Erreur:", error);
        showErrorMessage('Erreur','Une erreur est survenue lors de la déconnexion.');
    } finally {
        hideSpinner();
    }
}

// Masquer ou afficher les éléments réservés aux administrateurs
function toggleAdminElements() {
    const isAdmin = sessionStorage.getItem("role") === "admin";

    // Masquer/Afficher le formulaire "Ajouter un joueur"
    const ajouterJoueurSection = document.querySelector("#joueurs .card.mb-3");
    if (ajouterJoueurSection) {
        ajouterJoueurSection.style.display = isAdmin ? "block" : "none";
    }

    // Masquer/Afficher le formulaire "Ajouter une journée"
    const ajouterJourneeSection = document.querySelector("#journees .card.mb-3");
    if (ajouterJourneeSection) {
        ajouterJourneeSection.style.display = isAdmin ? "block" : "none";
    }

    // Masquer/Afficher les boutons de suppression
    const boutonsSuppression = document.querySelectorAll(".btn-danger");
    boutonsSuppression.forEach(bouton => {
        bouton.style.display = isAdmin ? "inline-block" : "none";
    });

    // Masquer/Afficher la section de changement de mot de passe
    const changePasswordSection = document.getElementById("change-password-section");
    if (changePasswordSection) {
        changePasswordSection.style.display = isAdmin ? "block" : "none";
    }

    // Afficher ou masquer les boutons d'import/export CSV
    const exportCsvSection = document.getElementById("export-csv");
    const importCsvSection = document.getElementById("import-csv");
    if (exportCsvSection) exportCsvSection.style.display = isAdmin ? "block" : "none";
    if (importCsvSection) importCsvSection.style.display = isAdmin ? "block" : "none";

    // Masquer/Afficher les onglets "Joueurs" et "Journées"
    const ongletJoueurs = document.querySelector("button[data-bs-target='#joueurs']");
    const ongletJournees = document.querySelector("button[data-bs-target='#journees']");
    if (ongletJoueurs) ongletJoueurs.style.display = isAdmin ? "inline-block" : "none";
    if (ongletJournees) ongletJournees.style.display = isAdmin ? "inline-block" : "none";

    // Si l'utilisateur n'est pas admin et qu'un onglet masqué est actif, basculer vers un autre
    const activeTab = document.querySelector(".nav-link.active");
    if (!isAdmin && (activeTab?.dataset.bsTarget === "#joueurs" || activeTab?.dataset.bsTarget === "#journees")) {
        document.querySelector("button[data-bs-target='#scores']").click(); // Rediriger vers Scores
    }
}

// Fonctions pour les joueurs
async function fetchJoueurs() {
    showSpinner();
    try {
        const response = await fetch("/joueurs");
        const data = await response.json();

        if (!Array.isArray(data)) {
            throw new Error(data.message || "Format de données incorrect.");
        }

        const liste = document.getElementById("listeJoueurs");
        liste.innerHTML = "";
        data.forEach(joueur => {
            const li = document.createElement("li");
            li.className = "list-group-item";
            li.innerHTML = `${joueur.nom}`+ " ";

            if (sessionStorage.getItem("role") === "admin") {
                const btn = document.createElement("button");
                btn.className = "btn btn-danger btn-sm";
                btn.textContent = "❌";
                btn.onclick = () => supprimerJoueur(joueur.id);
                li.appendChild(btn);
            }

            liste.appendChild(li);
        });
    } catch (error) {
        console.error("Erreur:", error);
        showErrorMessage('Erreur',error.message);
    } finally {
        hideSpinner();
    }
}

async function ajouterJoueur() {
    const nom = document.getElementById("nomJoueur").value.trim();
    if (!nom) {
        showErrorMessage('Erreur','Veuillez entrer un nom.');
        return;
    }

    showSpinner();
    try {
        const response = await fetch("/joueurs", {
            method: "POST",
			credentials: "include",
            headers: {
                "Content-Type": "application/json",
                "X-CSRF-Token": csrfToken
            },
            body: JSON.stringify({ nom })
        });

        if (response.ok) {
            showSuccessMessage('Succès','Joueur ajouté avec succès !');
            document.getElementById("nomJoueur").value = "";
            refreshAll();
        } else {
            showErrorMessage('Erreur','Ce joueur existe déjà.');
        }
    } catch (error) {
        console.error("Erreur:", error);
        showErrorMessage('Erreur','Une erreur est survenue lors de l\'ajout du joueur.');
    } finally {
        hideSpinner();
    }
}

async function supprimerJoueur(id) {
    const result = await showWarningMessage('Êtes-vous sûr ?',"Vous ne pourrez pas revenir en arrière !");

    if (result.isConfirmed) {
        showSpinner();
        try {
            const response = await fetch(`/joueurs/${id}`, {
                method: "DELETE",
				credentials: "include",
                headers: {
                    "X-CSRF-Token": csrfToken
                }
            });
            if (response.ok) {
                showSuccessMessage('Succès','Joueur supprimé avec succès !');
                refreshAll();
            } else {
                showErrorMessage('Erreur','Impossible de supprimer le joueur.');
            }
        } catch (error) {
            console.error("Erreur:", error);
            showErrorMessage('Erreur','Une erreur est survenue lors de la suppression du joueur.');
        } finally {
            hideSpinner();
        }
    }
}

async function fetchJournees() {
    showSpinner();
    try {
        const response = await fetch("/journees");
        const data = await response.json();
        const liste = document.getElementById("listeJournees");
        const select = document.getElementById("selectJournee");
        const selectScores = document.getElementById("selectJourneeScores"); // 👈 Ajout de la liste de l'onglet "Scores"

        if (!liste || !select || !selectScores) {
            console.error("⚠️ Un élément de la page est introuvable.");
            return;
        }

        // Réinitialisation des listes
        liste.innerHTML = "";
        select.innerHTML = "<option value=''>Sélectionner une journée</option>";
        selectScores.innerHTML = "<option value=''>Sélectionner une journée</option>"; // 👈 Ajout pour l'onglet Scores

        if (data.length === 0) {
            liste.innerHTML = "<li class='list-group-item text-center'>Aucune journée disponible</li>";
            return;
        }

        const isAdmin = sessionStorage.getItem("role") === "admin";
        data.sort((a, b) => {
            const dateA = new Date(a.date.split('-').reverse().join('-'));
            const dateB = new Date(b.date.split('-').reverse().join('-'));
            return dateB - dateA;
        });

        data.forEach(journee => {
            const li = document.createElement("li");
            li.className = "list-group-item d-flex justify-content-between align-items-center";

            const dateSpan = document.createElement("span");
            dateSpan.textContent = journee.date;
            li.appendChild(dateSpan);

            if (isAdmin) {
                const descriptionInput = document.createElement("input");
                descriptionInput.type = "text";
                descriptionInput.className = "form-control ms-3";
                descriptionInput.style.width = "50%";
                descriptionInput.value = journee.description || "Aucune description";  

                descriptionInput.addEventListener("focus", function () {
                    if (this.value === "Aucune description") {
                        this.value = "";
                    }
                });

                descriptionInput.addEventListener("blur", function () {
                    if (this.value.trim() === "") {
                        this.value = "Aucune description";
                    }
                    modifierDescription(journee.id, this.value);
                });

                li.appendChild(descriptionInput);
            } else {
                const descriptionSpan = document.createElement("span");
                descriptionSpan.className = "ms-3";
                descriptionSpan.textContent = journee.description || "Aucune description";  
                li.appendChild(descriptionSpan);
            }

            if (isAdmin) {
                const btnSupprimer = document.createElement("button");
                btnSupprimer.className = "btn btn-danger btn-sm ms-3";
                btnSupprimer.innerHTML = "❌";
                btnSupprimer.onclick = () => supprimerJournee(journee.id);
                li.appendChild(btnSupprimer);
            }

            liste.appendChild(li);

            // 📌 Ajout du nombre de jeux en tant qu'attribut data
            const option = document.createElement("option");
            option.value = journee.id;
            option.textContent = `${journee.date} - ${journee.description}`;
            option.setAttribute("data-nombre-jeux", journee.nombre_jeux);

            select.appendChild(option);

            // 📌 Ajout aussi dans la liste déroulante de l'onglet "Scores"
            const optionScores = option.cloneNode(true);
            selectScores.appendChild(optionScores);
        });

        // Sélectionner la première journée par défaut et mettre à jour l'affichage
        if (data.length > 0) {
            select.value = data[0].id;
            updateNombreJeuxInput(data[0].nombre_jeux);
            fetchJeuxJournee(data[0].id);

            selectScores.value = data[0].id; // 👈 Sélection automatique dans l'onglet "Scores"
            fetchScores(); // 👈 Charger les scores de la première journée par défaut
        }

    } catch (error) {
        console.error("Erreur:", error);
        showErrorMessage('Erreur','Impossible de charger les journées.');
    } finally {
        hideSpinner();
    }
}


async function ajouterJournee() {
    const dateInput = document.getElementById("nouvelleJournee");
    const date = dateInput.value.trim();

    if (!date) {
        showErrorMessage('Erreur','Veuillez sélectionner une date.');
        return;
    }

    showSpinner();
    try {
        const response = await fetch("/journees", {
            method: "POST",
			credentials: "include",
            headers: {
                "Content-Type": "application/json",
                "X-CSRF-Token": csrfToken
            },
            body: JSON.stringify({ date })
        });

        if (response.ok) {
            showSuccessMessage('Succès','Journée ajoutée avec succès !');
            dateInput.value = "";
            if (dateInput._flatpickr) {
                dateInput._flatpickr.clear();
            }
            await fetchJournees();
            fetchScores();
            fetchClassement();
        } else {
            showErrorMessage('Erreur','Cette journée existe déjà.');
        }
    } catch (error) {
        console.error("Erreur:", error);
        showErrorMessage('Erreur','Une erreur est survenue lors de l\'ajout de la journée.');
    } finally {
        hideSpinner();
    }
}

async function supprimerJournee(journeeId) {
    const result = await showWarningMessage('Êtes-vous sûr ?',"Vous ne pourrez pas revenir en arrière !");

    if (result.isConfirmed) {
        showSpinner();
        try {
            const response = await fetch(`/journees/${journeeId}`, {
                method: "DELETE",
				credentials: "include",
                headers: {
                    "X-CSRF-Token": csrfToken
                }
            });
            if (response.ok) {
                showSuccessMessage('Succès','Journée supprimée avec succès !');
                await fetchJournees();
                document.getElementById("selectJournee").value = "";
                await fetchScores();
                await fetchClassement();
            } else {
                showErrorMessage('Erreur','Impossible de supprimer la journée.');
            }
        } catch (error) {
            console.error("Erreur:", error);
            showErrorMessage('Erreur','Une erreur est survenue lors de la suppression de la journée.');
        } finally {
            hideSpinner();
        }
    }
}

// Fonctions pour les scores
async function fetchScores() {
    showSpinner();
    const select = document.getElementById("selectJourneeScores");
    const journeeId = select.value;

    if (!journeeId) {
        document.getElementById("scoresContent").innerHTML = "<p>Sélectionnez une journée pour voir les scores.</p>";
        hideSpinner();
        return;
    }

    try {
        const response = await fetch(`/scores?journee_id=${journeeId}`);
        const data = await response.json();
        if (!data.scores || data.scores.length === 0) {
            document.getElementById("scoresContent").innerHTML = "<p class='text-center'>Aucun score pour cette journée.</p>";
            hideSpinner();
            return;
        }

        const jeuxNoms = data.jeux_noms;  // 🔥 Liste des vrais noms des jeux
        const scores = data.scores;
        const nombreJeux = jeuxNoms.length;

        // ✅ Construire l'en-tête du tableau avec les vrais noms des jeux
        let tableHTML = `<table class="table table-bordered">
            <thead>
                <tr>
                    <th>Joueur</th>`;
        
        for (let i = 0; i < nombreJeux; i++) {
            tableHTML += `<th>${jeuxNoms[i]}</th>`;  // 🔥 Utiliser les vrais noms des jeux
        }

        tableHTML += `</tr></thead><tbody>`;

        // ✅ Construire les lignes du tableau
        scores.forEach(score => {
            tableHTML += `<tr>
                <td>${score.joueur_nom}</td>`;

            for (let i = 1; i <= nombreJeux; i++) {
                let scoreValue = score[`jeu${i}`] || 0;  // Sécuriser la récupération des scores

                if (sessionStorage.getItem("role") === "admin") {
                    tableHTML += `<td><input type="number" class="form-control" value="${scoreValue}" 
                        onblur="modifierScore(${score.joueur_id}, ${score.journee_id}, this.value, 'jeu${i}')"></td>`;
                } else {
                    tableHTML += `<td>${scoreValue}</td>`;
                }
            }

            tableHTML += `</tr>`;
        });

        tableHTML += "</tbody></table>";
        document.getElementById("scoresContent").innerHTML = tableHTML;
    } catch (error) {
        console.error("Erreur lors de la récupération des scores:", error);
        showErrorMessage('Erreur','Impossible de charger les scores.');
    } finally {
        hideSpinner();
    }
}

async function modifierScore(joueurId, journeeId, valeur, jeu) {
    valeur = parseInt(valeur, 10);
    if (isNaN(valeur)) return;
    showSpinner();
    try {
        const response = await fetch("/scores", {
            method: "PUT",
            credentials: "include",
            headers: {
                "Content-Type": "application/json",
                "X-CSRF-Token": csrfToken
            },
            body: JSON.stringify({ joueur_id: joueurId, journee_id: journeeId, jeu, valeur })
        });

        if (!response.ok) {
            throw new Error("Impossible de mettre à jour le score.");
        }

        showSuccessMessage('Succès','Score mis à jour avec succès !');
        await fetchScores();  // Rafraîchir les scores après mise à jour
		await fetchClassement();
    } catch (error) {
        console.error("❌ Erreur lors de la mise à jour du score :", error);
        showErrorMessage('Erreur','Impossible de mettre à jour le score.');
    } finally {
        hideSpinner();
    }
}

// Fonctions pour le classement
async function fetchClassement() {
    showSpinner();
    try {
        const response = await fetch("/classement");
        const data = await response.json();

        if (!Array.isArray(data)) {
            throw new Error(data.message || "Format de données incorrect.");
        }

        const liste = document.getElementById("classementListe");
        liste.innerHTML = "";
        data.forEach((joueur, index) => {
            const li = document.createElement("li");
            li.className = "list-group-item";
            li.innerHTML = `<strong>${index + 1}. ${joueur.nom}</strong> <span class="badge bg-primary">${joueur.score} pts</span>`;
            liste.appendChild(li);
        });
    } catch (error) {
        console.error("Erreur:", error);
        showErrorMessage('Erreur',error.message);
    } finally {
        hideSpinner();
    }
}

// Fonction pour changer le mot de passe
async function changePassword() {
    await fetchCsrfToken(); 
    const oldPasswordField = document.getElementById("old-password");
    const newPasswordField = document.getElementById("new-password");
    const confirmPasswordField = document.getElementById("confirm-password");

    if (!oldPasswordField || !newPasswordField || !confirmPasswordField) {
        console.error("Erreur: Un des champs du formulaire de changement de mot de passe est introuvable.");
        showErrorMessage('Erreur', 'Un problème est survenu. Veuillez recharger la page.');
        return;
    }

    const oldPassword = oldPasswordField.value.trim();
    const newPassword = newPasswordField.value.trim();
    const confirmPassword = confirmPasswordField.value.trim();

    if (!oldPassword || !newPassword || !confirmPassword) {
        showErrorMessage('Erreur','Veuillez remplir tous les champs.');
        return;
    }

    if (newPassword !== confirmPassword) {
        showErrorMessage('Erreur','Les nouveaux mots de passe ne correspondent pas.');
        return;
    }

    showSpinner();
    try {
        const response = await fetch("/change-password", {
            method: "POST",
            credentials: "include",
            headers: {
                "Content-Type": "application/json",
                "X-CSRF-Token": csrfToken
            },
            body: JSON.stringify({ oldPassword, newPassword })
        });

        const data = await response.json();

        if (!response.ok) {
            console.error("Erreur API:", data);
            throw new Error(data.message || 'Échec du changement de mot de passe.');
        }

        showSuccessMessage('Succès','Mot de passe changé avec succès !');
        oldPasswordField.value = "";
        newPasswordField.value = "";
        confirmPasswordField.value = "";
    } catch (error) {
        console.error("Erreur:", error);
        showErrorMessage('Erreur', error.message || 'Une erreur est survenue.');
    } finally {
        hideSpinner();
    }
}

// Mettre à jour la fonction checkAuth pour gérer l'affichage et les permissions utilisateur
async function checkAuth() {
    try {
        const response = await fetch("/check-auth");

        // Vérification si la réponse est valide
        if (!response.ok) {
            throw new Error(`Erreur serveur: ${response.statusText}`);
        }

        const data = await response.json();

        // Sélection des éléments DOM
        const loginForm = document.getElementById("login-form");
        const logoutSection = document.getElementById("logout-section");
        const changePasswordSection = document.getElementById("change-password-section");
        const loggedInUser = document.getElementById("logged-in-user");
        const adminCsvSection = document.getElementById("admin-csv-export");
        const adminCsvSection2 = document.getElementById("admin-csv-import");

        // Sélectionner toutes les cartes Admin à masquer/afficher (sauf celle du login)
        const adminSections = document.querySelectorAll("#administration .card.mb-3");
        const loginCard = document.querySelector("#administration #login-form").closest(".card.mb-3"); // 📌 Trouver la carte du login

        if (data.authenticated) {
            // Cacher le formulaire de connexion et afficher la déconnexion
            if (loginForm) loginForm.style.display = "none";
            if (logoutSection) logoutSection.style.display = "block";
            if (changePasswordSection) changePasswordSection.style.display = "block";

            // Mettre à jour le texte affichant l'utilisateur connecté
            if (loggedInUser) {
                loggedInUser.textContent = `Connecté en tant que ${data.username}`;
            }

            // Stocker le rôle dans sessionStorage
            sessionStorage.setItem("role", data.role);

            // Afficher les boutons Import/Export CSV si admin
            const isAdmin = data.role === "admin";
            if (adminCsvSection) adminCsvSection.style.display = isAdmin ? "block" : "none";
            if (adminCsvSection2) adminCsvSection2.style.display = isAdmin ? "block" : "none";

            // Afficher toutes les sections admin
            adminSections.forEach(section => {
                section.style.display = "block";
            });

        } else {
            // Afficher le formulaire de connexion et masquer les éléments réservés aux utilisateurs connectés
            if (loginForm) loginForm.style.display = "block";
            if (logoutSection) logoutSection.style.display = "none";
            if (changePasswordSection) changePasswordSection.style.display = "none";

            // Supprimer le rôle du stockage si l'utilisateur est déconnecté
            sessionStorage.removeItem("role");

            // Masquer les boutons Import/Export CSV
            if (adminCsvSection) adminCsvSection.style.display = "none";
            if (adminCsvSection2) adminCsvSection2.style.display = "none";

            // Masquer toutes les cartes Admin sauf la carte du login
            adminSections.forEach(section => {
                if (section !== loginCard) {
                    section.style.display = "none";
                }
            });
        }

        // Appliquer les permissions admin après vérification
        toggleAdminElements();

        // 🔥 Vérifier si l'onglet actif est interdit aux non-admins et rediriger
        const activeTab = document.querySelector(".nav-link.active");
        const isAdmin = sessionStorage.getItem("role") === "admin";
        if (!isAdmin && (activeTab?.dataset.bsTarget === "#joueurs" || activeTab?.dataset.bsTarget === "#journees")) {
            document.querySelector("button[data-bs-target='#scores']").click(); // Rediriger vers "Scores"
        }

        // Rafraîchir les données pour s'assurer que l'affichage est à jour
        refreshAll();
    } catch (error) {
        console.error("Erreur dans checkAuth:", error);
    }
}

async function modifierDescription(journeeId, nouvelleDescription) {
    showSpinner();
    try {

        const response = await fetch(`/journees/${journeeId}/description`, {
            method: "PUT",
            credentials: "include",
            headers: {
                "Content-Type": "application/json",
                "X-CSRF-Token": csrfToken
            },
            body: JSON.stringify({ description: nouvelleDescription })
        });

        if (!response.ok) {
            const errorData = await response.json();
            throw new Error(errorData.message || "Erreur lors de la mise à jour de la description");
        }

		await fetchJournees();
    } catch (error) {
        showErrorMessage('Erreur', 'Impossible de modifier la description.');
    } finally {
		hideSpinner();
    }
}


function exporterCSV() {
    window.location.href = "/export-csv";
}

async function importerCSV() {
    const fileInput = document.getElementById("csvFileInput");
    if (!fileInput.files.length) {
        showErrorMessage("Erreur", "Veuillez sélectionner un fichier CSV.");
        return;
    }

    const file = fileInput.files[0];
    const formData = new FormData();
    formData.append("file", file);

    showSpinner();
    try {
        const response = await fetch("/import-csv", {
            method: "POST",
            credentials: "include",
            headers: { "X-CSRF-Token": csrfToken },
            body: formData
        });

        const data = await response.json();
        if (response.ok) {
            showSuccessMessage("Succès", data.message);
            refreshAll();
        } else {
            showErrorMessage("Erreur",data.message);
        }
    } catch (error) {
        console.error("Erreur:", error);
        showErrorMessage("Erreur","Impossible d'importer le fichier.");
    } finally {
        hideSpinner();
    }
}

async function modifierNombreJeux() {
    const journeeId = document.getElementById("selectJournee").value;
    const nombreJeux = parseInt(document.getElementById("nombreJeux").value, 10);

    if (!journeeId) {
        showErrorMessage("Erreur", "Veuillez sélectionner une journée",);
        return;
    }

    showSpinner();
    try {
        const response = await fetch(`/journees/${journeeId}/nombre-jeux`, {
            method: "PUT",
            headers: { "Content-Type": "application/json", "X-CSRF-Token": csrfToken },
            body: JSON.stringify({ nombre_jeux: nombreJeux })
        });

        if (!response.ok) {
            throw new Error("Erreur lors de la mise à jour");
        }

        showSuccessMessage("Succès", "Nombre de jeux mis à jour et scores ajustés");
        
        // ✅ Rafraîchir la liste des jeux de la journée
        await fetchJeuxJournee(journeeId);

        // ✅ Mettre à jour l'affichage des scores et du classement
        await fetchScores();
        await fetchClassement();

    } catch (error) {
        console.error("Erreur:", error);
        showErrorMessage("Erreur", "Impossible de modifier le nombre de jeux");
    } finally {
        hideSpinner();
    }
}

async function fetchJeux() {
    const response = await fetch("/jeux");
    const jeux = await response.json();
    const listeJeux = document.getElementById("listeJeux");
    listeJeux.innerHTML = "";

    jeux.forEach(jeu => {
        const div = document.createElement("div");
        div.classList.add("mb-2");

        div.innerHTML = `
            <input type="text" class="form-control d-inline w-50" id="jeu-${jeu.id}" value="${jeu.nom}">
            <button class="btn btn-primary ms-2" onclick="modifierNomJeu(${jeu.id})">Modifier</button>
        `;

        listeJeux.appendChild(div);
    });
}

async function modifierNomJeu(journeeId, jeuId) {
    const inputJeu = document.getElementById(`jeu-${jeuId}`);
    if (!inputJeu) {
        console.error("Élément introuvable pour le jeu ID:", jeuId);
        return;
    }

    const nouveauNom = inputJeu.value.trim();
    if (!nouveauNom) {
        showErrorMessage("Erreur", "Le nom du jeu ne peut pas être vide",);
        return;
    }

    showSpinner();
    try {
        const response = await fetch(`/journees/${journeeId}/jeux/${jeuId}`, {
            method: "PUT",
            credentials: "include",
            headers: {
                "Content-Type": "application/json",
                "X-CSRF-Token": csrfToken
            },
            body: JSON.stringify({ nom: nouveauNom })
        });

        if (!response.ok) {
            throw new Error(`Erreur HTTP ${response.status}`);
        }

        showSuccessMessage("Nom modifié 🎮","Le jeu a été renommé avec succès !");

        await fetchJeuxJournee(journeeId); // 🔥 Recharge la liste des jeux après modification

    } catch (error) {
        console.error("Erreur lors de la modification du nom du jeu:", error);
        showErrorMessage("Erreur", "Impossible de modifier le nom du jeu");
    } finally {
        hideSpinner();
    }
}


// Fonction pour récupérer les jeux associés à une journée spécifique
async function fetchJeuxJournee(journeeId) {
    try {
        const response = await fetch(`/journees/${journeeId}/jeux`);
        
        if (!response.ok) {
            const errorText = await response.text();
            console.error("Erreur HTTP:", response.status, errorText);
            throw new Error(`HTTP ${response.status}: ${errorText}`);
        }
        
        const jeux = await response.json();
        
        if (!Array.isArray(jeux)) {
            console.error("Réponse reçue:", jeux);
            throw new Error("Format de réponse incorrect : les jeux doivent être un tableau");
        }
        
        afficherJeuxJournee(jeux, journeeId);
    } catch (error) {
        console.error("Erreur lors de la récupération des jeux de la journée:", error);
    }
}

// Fonction pour afficher les jeux d'une journée avec champs modifiables
function afficherJeuxJournee(jeux, journeeId) {
    const container = document.getElementById("jeuxJourneeContainer");
    container.innerHTML = "";

    jeux.forEach(jeu => {
        const div = document.createElement("div");
        div.classList.add("mb-2");
        div.innerHTML = `
            <input type="text" class="form-control d-inline w-50" id="jeu-${jeu.id}" value="${jeu.jeu_nom}">
            <button class="btn btn-primary ms-2" onclick="modifierNomJeu(${journeeId}, ${jeu.id})">Modifier</button>
        `;
        container.appendChild(div);
    });
}

function onJourneeChange() {
    const select = document.getElementById("selectJournee");
    const selectedOption = select.options[select.selectedIndex];

    if (selectedOption) {
        const journeeId = selectedOption.value;
        const nombreJeux = selectedOption.getAttribute("data-nombre-jeux");
        updateNombreJeuxInput(nombreJeux);
        fetchJeuxJournee(journeeId);
    }
}

function updateNombreJeuxInput(nombreJeux) {
    const inputNombreJeux = document.getElementById("nombreJeux");
    inputNombreJeux.value = nombreJeux || 3; // Par défaut 3 si pas trouvé
}


// Rafraîchir toutes les données
function refreshAll() {
    fetchJoueurs();
    fetchJournees();
    fetchScores();
    fetchClassement();
}