from flask import Flask, request, jsonify, send_from_directory, g, session, Response
from flask_wtf.csrf import CSRFProtect, generate_csrf
from flask_session import Session
import sqlite3
from flask_cors import CORS
from werkzeug.security import generate_password_hash, check_password_hash
import logging
import os
import csv
import tempfile

# Configuration de l'application Flask
app = Flask(__name__, static_folder="frontend")
CORS(app, supports_credentials=True) # Autoriser les requêtes cross-origin (à configurer correctement en production)
app.secret_key = "mysecretkey"  # Clé secrète pour les sessions (à changer en production)

# Configuration de la Session
app.config["SESSION_TYPE"] = "filesystem"
app.config["SESSION_PERMANENT"] = False
app.config["SESSION_FILE_DIR"] = os.path.join(os.getcwd(), "flask_session")  # Assure un répertoire valide
app.config["SESSION_USE_SIGNER"] = True  # Sécurise les sessions en signant les cookies

# Vérifie si le dossier des sessions existe
if not os.path.exists(app.config["SESSION_FILE_DIR"]):
    os.makedirs(app.config["SESSION_FILE_DIR"])

Session(app)
# Initialiser Flask-Session correctement
session_instance = Session()
session_instance.init_app(app)

# Configuration de la protection CSRF
app.config['WTF_CSRF_ENABLED'] = True
app.config['WTF_CSRF_SECRET_KEY'] = "mysecretcsrfkey"  # Clé secrète pour CSRF (à changer en production)
#csrf = CSRFProtect(app)

# Configuration des cookies de session
environment = "development"  # Change en "production" si déployé
debug_mode = environment == "development"
app.config.update(
    SESSION_COOKIE_SECURE=not debug_mode,  # Secure uniquement en production
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE='Lax',
    SESSION_PERMANENT = True
)

# Configuration de la Session
app.config["SESSION_TYPE"] = "filesystem"
app.config["SESSION_PERMANENT"] = False

# Configuration de la journalisation
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Base de données
DATABASE = "database.db"

# Connexion à la base de données
def get_db():
    if "db" not in g:
        g.db = sqlite3.connect(DATABASE)
        g.db.row_factory = sqlite3.Row  # Permet d'obtenir un dictionnaire
        g.db.execute("PRAGMA foreign_keys = ON;")  # Active ON DELETE CASCADE
    return g.db
 
@app.errorhandler(Exception)
def handle_exception(e):
    # Renvoyer une réponse JSON en cas d'erreur
    return jsonify({"message": str(e)}), 500
    
@app.teardown_appcontext
def close_db(exception):
    db = g.pop("db", None)
    if db is not None:
        db.close()

# Initialisation de la base de données
def init_db():
    with get_db() as conn:
        c = conn.cursor()

        # Création de la table des joueurs
        c.execute('''CREATE TABLE IF NOT EXISTS joueurs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            nom TEXT UNIQUE NOT NULL
        )''')

        # Création de la table des journées avec description bien définie
        c.execute('''CREATE TABLE IF NOT EXISTS journees (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            date TEXT UNIQUE NOT NULL,
            nombre_jeux INTEGER DEFAULT 3,
            description TEXT DEFAULT ''
        )''')

        c.execute("""
            CREATE TABLE IF NOT EXISTS journee_jeux (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                journee_id INTEGER,
                jeu_nom TEXT,
                FOREIGN KEY (journee_id) REFERENCES journees(id) ON DELETE CASCADE
            )
        """)
        
        # Création d'une table des jeux pour stocker les noms
        c.execute('''CREATE TABLE IF NOT EXISTS jeux (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            nom TEXT NOT NULL
        )''')

        # Création de la table des scores avec jusqu'à 9 jeux
        c.execute('''CREATE TABLE IF NOT EXISTS scores (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            joueur_id INTEGER NOT NULL,
            journee_id INTEGER NOT NULL,
            jeu1 INTEGER DEFAULT 0,
            jeu2 INTEGER DEFAULT 0,
            jeu3 INTEGER DEFAULT 0,
            jeu4 INTEGER DEFAULT 0,
            jeu5 INTEGER DEFAULT 0,
            jeu6 INTEGER DEFAULT 0,
            jeu7 INTEGER DEFAULT 0,
            jeu8 INTEGER DEFAULT 0,
            jeu9 INTEGER DEFAULT 0,
            FOREIGN KEY (joueur_id) REFERENCES joueurs(id) ON DELETE CASCADE,
            FOREIGN KEY (journee_id) REFERENCES journees(id) ON DELETE CASCADE
        )''')

        # Création de la table des utilisateurs
        c.execute('''CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password TEXT NOT NULL,
            role TEXT CHECK(role IN ('admin', 'user')) NOT NULL DEFAULT 'user'
        )''')

        # Vérifier et insérer un administrateur par défaut
        c.execute("SELECT COUNT(*) FROM users WHERE username = 'admin'")
        if c.fetchone()[0] == 0:
            from werkzeug.security import generate_password_hash
            hashed_password = generate_password_hash("R4NKing!")  # Mot de passe sécurisé
            c.execute("INSERT INTO users (username, password, role) VALUES (?, ?, 'admin')", ("admin", hashed_password))
            print("[INFO] Administrateur 'admin' ajouté avec succès.")

        # Vérifier si des noms de jeux existent, sinon en insérer par défaut
        c.execute("SELECT COUNT(*) FROM jeux")
        if c.fetchone()[0] == 0:
            for i in range(1, 10):
                c.execute("INSERT INTO jeux (nom) VALUES (?)", (f"Jeu {i}",))
            print("[INFO] Jeux par défaut ajoutés.")

        conn.commit()

# Vérifier et mettre à jour la base de données (ex: ajout de la colonne description si manquante)
def update_db_schema():
    conn = get_db()
    c = conn.cursor()

    # Vérifier si la colonne "description" existe déjà
    c.execute("PRAGMA table_info(journees)")
    columns = [row[1] for row in c.fetchall()]
    
    if "description" not in columns:
        print("[INFO] Ajout de la colonne 'description' à la table 'journees'.")
        c.execute("ALTER TABLE journees ADD COLUMN description TEXT DEFAULT ''")
        conn.commit()
    else:
        print("[INFO] La colonne 'description' existe déjà.")

    conn.close()

# Vérifie si l'utilisateur est authentifié et a le rôle admin
def is_admin():
    return "username" in session and session.get("role") == "admin"

# Valider le token CSRF
def validate_csrf():
    csrf_token_client = request.headers.get("X-CSRF-Token")
    csrf_token_session = session.get("csrf_token")
    return csrf_token_client and csrf_token_client == csrf_token_session

# Route pour générer un token CSRF
@app.route('/get-csrf-token', methods=['GET'])
def get_csrf_token():
    token = generate_csrf()
    session['csrf_token'] = token  # Stocker le token dans la session Flask
    session.modified = True  # Force la mise à jour de la session
    return jsonify({'csrf_token': token})

@app.route("/journees/<int:journee_id>/jeux", methods=["GET"])
def get_jeux_journee(journee_id):
    conn = get_db()
    c = conn.cursor()
    c.execute("SELECT id, jeu_nom FROM journee_jeux WHERE journee_id = ?", (journee_id,))
    jeux = [dict(row) for row in c.fetchall()]
    return jsonify(jeux)

# Modifier le nombre de jeux par journée
@app.route("/journees/<int:journee_id>/nombre-jeux", methods=["PUT"])
def modifier_nombre_jeux(journee_id):
    if not is_admin():
        return jsonify({"message": "Accès refusé"}), 403

    data = request.json
    nombre_jeux = data.get("nombre_jeux")

    if not isinstance(nombre_jeux, int) or nombre_jeux < 1 or nombre_jeux > 9:
        return jsonify({"message": "Nombre de jeux invalide"}), 400

    conn = get_db()
    c = conn.cursor()

    # ✅ Mettre à jour le nombre de jeux dans la table journees
    c.execute("UPDATE journees SET nombre_jeux = ? WHERE id = ?", (nombre_jeux, journee_id))

    # ✅ Vérifier le nombre actuel de jeux dans `journee_jeux`
    c.execute("SELECT COUNT(*) FROM journee_jeux WHERE journee_id = ?", (journee_id,))
    jeux_actuels = c.fetchone()[0]

    # ✅ Si trop de jeux, supprimer les surplus
    if jeux_actuels > nombre_jeux:
        c.execute(
            "DELETE FROM journee_jeux WHERE id IN (SELECT id FROM journee_jeux WHERE journee_id = ? ORDER BY id DESC LIMIT ?)",
            (journee_id, jeux_actuels - nombre_jeux)
        )

    # ✅ Si pas assez de jeux, ajouter des nouveaux
    elif jeux_actuels < nombre_jeux:
        jeux_par_defaut = ["2X", "3.3", "SF6", "Tekken", "Mortal Kombat", "CS2", "Chess", "Outer Wilds", "Trop de jeux"]
        jeux_a_ajouter = jeux_par_defaut[jeux_actuels:nombre_jeux]  # Sélectionner les jeux manquants

        for jeu in jeux_a_ajouter:
            c.execute("INSERT INTO journee_jeux (journee_id, jeu_nom) VALUES (?, ?)", (journee_id, jeu))

    # 🔥 Effacer les scores des jeux non utilisés dans `scores`
    jeux_a_effacer = [f"jeu{i}" for i in range(nombre_jeux + 1, 10)]  # Ex: Si 2 jeux, on efface `jeu3` à `jeu9`
    for jeu in jeux_a_effacer:
        c.execute(f"UPDATE scores SET {jeu} = NULL WHERE journee_id = ?", (journee_id,))

    conn.commit()
    return jsonify({"message": "Nombre de jeux mis à jour et anciens scores effacés"})


# Récupérér les jeux
@app.route("/jeux", methods=["GET"])
def get_jeux():
    conn = get_db()
    c = conn.cursor()
    c.execute("SELECT id, nom FROM jeux")
    jeux = [dict(row) for row in c.fetchall()]
    return jsonify(jeux)

# Modifier le nom des jeux
@app.route("/journees/<int:journee_id>/jeux/<int:jeu_id>", methods=["PUT"])
def modifier_nom_jeu_journee(journee_id, jeu_id):
    if not is_admin():
        return jsonify({"message": "Accès refusé"}), 403

    data = request.json
    nouveau_nom = data.get("nom", "").strip()

    if not nouveau_nom:
        return jsonify({"message": "Nom de jeu invalide"}), 400

    conn = get_db()
    c = conn.cursor()

    try:
        # 🔍 Vérifier si ce jeu est bien associé à cette journée
        c.execute("SELECT id FROM journee_jeux WHERE id = ? AND journee_id = ?", (jeu_id, journee_id))
        jeu_existe = c.fetchone()

        if not jeu_existe:
            return jsonify({"message": "Jeu introuvable pour cette journée"}), 404

        print(f"🔹 Modification du jeu ID {jeu_id} pour la journée {journee_id} avec le nouveau nom: {nouveau_nom}")
        c.execute("UPDATE journee_jeux SET jeu_nom = ? WHERE id = ?", (nouveau_nom, jeu_id))
        conn.commit()

        return jsonify({"message": "Nom du jeu mis à jour avec succès"})

    except Exception as e:
        print(f"🔥 ERREUR lors de la modification du jeu ID {jeu_id} pour la journée {journee_id}: {str(e)}")
        return jsonify({"message": f"Erreur serveur: {str(e)}"}), 500


# Routes d'authentification
@app.route("/login", methods=["POST"])
def login():
    logger.info(f"Session avant vérification CSRF: {dict(session)}")
    csrf_token_client = request.headers.get("X-CSRF-Token")
    csrf_token_session = session.get("csrf_token")

    logger.info(f"CSRF Token from client: {csrf_token_client}")
    logger.info(f"CSRF Token in session: {csrf_token_session}")

    if not csrf_token_client or csrf_token_client != csrf_token_session:
        logger.warning("CSRF token mismatch")
        return jsonify({"message": "Token CSRF invalide"}), 403

    data = request.json
    username = data.get("username")
    password = data.get("password")

    logger.info(f"Login attempt for username: {username}")

    if not username or not password:
        logger.warning("Missing username or password")
        return jsonify({"message": "Nom d'utilisateur ou mot de passe manquant"}), 400

    conn = get_db()
    c = conn.cursor()
    c.execute("SELECT * FROM users WHERE username = ?", (username,))
    user = c.fetchone()

    if user and check_password_hash(user["password"], password):
        session["username"] = user["username"]
        session["role"] = user["role"]

        new_csrf_token = generate_csrf()
        session["csrf_token"] = new_csrf_token
        session.modified = True

        logger.info(f"User {username} logged in successfully")
        return jsonify({
            "message": "Connexion réussie",
            "role": user["role"],
            "csrf_token": new_csrf_token
        }), 200
    else:
        logger.warning(f"Failed login attempt for username: {username}")
        return jsonify({"message": "Nom d'utilisateur ou mot de passe incorrect"}), 401
        
@app.route("/logout", methods=["POST"])
def logout():
    if not validate_csrf():
        return jsonify({"message": "Token CSRF invalide"}), 403
    
    session.clear()
    return jsonify({"message": "Déconnexion réussie"}), 200
    
@app.route("/check-auth", methods=["GET"])
def check_auth():
    if "username" in session:
        return jsonify({"authenticated": True, "username": session["username"], "role": session.get("role")}), 200
    else:
        return jsonify({"authenticated": False}), 200

# Routes API
@app.route("/")
def home():
    return send_from_directory("frontend", "index.html")

@app.route("/<path:path>")
def static_files(path):
    return send_from_directory("frontend", path)

@app.route("/joueurs", methods=["GET"])
def get_joueurs():
    try:
        conn = get_db()
        c = conn.cursor()
        c.execute("""
            SELECT j.id, j.nom, 
                   COALESCE(SUM(s.jeu1), 0) AS jeu1, 
                   COALESCE(SUM(s.jeu2), 0) AS jeu2, 
                   COALESCE(SUM(s.jeu3), 0) AS jeu3, 
                   COALESCE(SUM(s.jeu4), 0) AS jeu4, 
                   COALESCE(SUM(s.jeu5), 0) AS jeu5, 
                   COALESCE(SUM(s.jeu6), 0) AS jeu6, 
                   COALESCE(SUM(s.jeu7), 0) AS jeu7, 
                   COALESCE(SUM(s.jeu8), 0) AS jeu8, 
                   COALESCE(SUM(s.jeu9), 0) AS jeu9, 
                   COALESCE(SUM(s.jeu1 + s.jeu2 + s.jeu3 + s.jeu4 + s.jeu5 + s.jeu6 + s.jeu7 + s.jeu8 + s.jeu9), 0) AS total
            FROM joueurs j
            LEFT JOIN scores s ON j.id = s.joueur_id
            GROUP BY j.id, j.nom
        """)
        joueurs = [dict(row) for row in c.fetchall()]
        return jsonify(joueurs)
    except Exception as e:
        return jsonify({"message": str(e)}), 500


@app.route("/joueurs", methods=["POST"])
def ajouter_joueur():
    if not is_admin():
        logger.warning(f"Tentative non autorisée d'ajouter un joueur depuis {request.remote_addr}")
        return jsonify({"message": "Accès refusé"}), 403

    data = request.json
    nom = data.get("nom", "").strip()

    if not nom:
        return jsonify({"message": "Nom invalide"}), 400

    try:
        conn = get_db()
        c = conn.cursor()
        c.execute("INSERT INTO joueurs (nom) VALUES (?)", (nom,))
        joueur_id = c.lastrowid

        # Ajouter des scores à 0 pour toutes les journées existantes
        c.execute("SELECT id FROM journees")
        journees = [row["id"] for row in c.fetchall()]
        
        if journees:
            c.executemany(
                "INSERT INTO scores (joueur_id, journee_id, jeu1, jeu2, jeu3) VALUES (?, ?, 0, 0, 0)",
                [(joueur_id, journee_id) for journee_id in journees]
            )

        conn.commit()
        logger.info(f"Joueur {nom} ajouté avec succès par {session['username']}")
        return jsonify({"message": "Joueur ajouté avec succès et scores mis à jour"}), 201
    except sqlite3.IntegrityError:
        logger.warning(f"Tentative d'ajout d'un joueur existant : {nom}")
        return jsonify({"message": "Ce joueur existe déjà"}), 400

@app.route("/joueurs/<int:joueur_id>", methods=["DELETE"])
def supprimer_joueur(joueur_id):
    if not is_admin():
        logger.warning(f"Tentative non autorisée de supprimer un joueur depuis {request.remote_addr}")
        return jsonify({"message": "Accès refusé"}), 403

    conn = get_db()
    c = conn.cursor()
    c.execute("DELETE FROM scores WHERE joueur_id = ?", (joueur_id,))
    c.execute("DELETE FROM joueurs WHERE id = ?", (joueur_id,))
    conn.commit()
    logger.info(f"Joueur {joueur_id} supprimé avec succès par {session['username']}")
    return jsonify({"message": "Joueur supprimé avec succès"})

@app.route("/journees", methods=["POST"])
def ajouter_journee():
    if not is_admin():
        logger.warning(f"Tentative non autorisée d'ajouter une journée depuis {request.remote_addr}")
        return jsonify({"message": "Accès refusé"}), 403

    data = request.json
    date = data.get("date", "").strip()
    if not date:
        return jsonify({"message": "Date invalide"}), 400

    try:
        conn = get_db()
        c = conn.cursor()

        # Ajouter la journée
        c.execute("INSERT INTO journees (date) VALUES (?)", (date,))
        journee_id = c.lastrowid

        # Ajouter des scores par défaut pour les joueurs existants
        c.execute("SELECT id FROM joueurs")
        joueurs = [row["id"] for row in c.fetchall()]
        if joueurs:
            c.executemany(
                "INSERT INTO scores (joueur_id, journee_id, jeu1, jeu2, jeu3) VALUES (?, ?, 0, 0, 0)",
                [(j, journee_id) for j in joueurs]
            )

        # Ajouter des jeux par défaut à la journée
        jeux_par_defaut = ["2X", "3.3", "SF6"]  # 👈 Change ces noms si nécessaire
        for jeu in jeux_par_defaut:
            c.execute("INSERT INTO journee_jeux (journee_id, jeu_nom) VALUES (?, ?)", (journee_id, jeu))

        conn.commit()
        logger.info(f"Journée {date} ajoutée avec succès avec jeux par défaut par {session['username']}")
        return jsonify({"message": "Journée et jeux ajoutés avec succès"}), 201

    except sqlite3.IntegrityError:
        logger.warning(f"Tentative d'ajout d'une journée existante : {date}")
        return jsonify({"message": "Cette journée existe déjà"}), 400


@app.route("/journees/<int:journee_id>", methods=["DELETE"])
def supprimer_journee(journee_id):
    if not is_admin():
        logger.warning(f"Tentative non autorisée de supprimer une journée depuis {request.remote_addr}")
        return jsonify({"message": "Accès refusé"}), 403

    conn = get_db()
    c = conn.cursor()
    c.execute("DELETE FROM scores WHERE journee_id = ?", (journee_id,))
    c.execute("DELETE FROM journees WHERE id = ?", (journee_id,))
    conn.commit()
    logger.info(f"Journée {journee_id} supprimée avec succès par {session['username']}")
    return jsonify({"message": "Journée et scores supprimés avec succès"})

@app.route("/journees", methods=["GET"])
def get_journees():
    try:
        conn = get_db()
        c = conn.cursor()
        c.execute("SELECT id, date, nombre_jeux, description FROM journees ORDER BY date ASC")
        journees = [dict(row) for row in c.fetchall()]
        return jsonify(journees)
    except Exception as e:
        return jsonify({"message": str(e)}), 500


@app.route("/scores", methods=["PUT"])
def modifier_score():
    if not is_admin():
        logger.warning(f"Tentative non autorisée de modifier un score depuis {request.remote_addr}")
        return jsonify({"message": "Accès refusé"}), 403

    data = request.json
    joueur_id = data.get("joueur_id")
    journee_id = data.get("journee_id")
    jeu = data.get("jeu")  # Ex: "jeu4"
    valeur = data.get("valeur")

    if not all([joueur_id, journee_id, jeu, isinstance(valeur, int)]):
        return jsonify({"message": "Données incomplètes ou invalides"}), 400

    # 📌 Accepter maintenant tous les jeux de jeu1 à jeu9
    if jeu not in [f"jeu{i}" for i in range(1, 10)]:
        return jsonify({"message": "Jeu invalide"}), 400

    try:
        conn = get_db()
        c = conn.cursor()
        c.execute(f"UPDATE scores SET {jeu} = ? WHERE joueur_id = ? AND journee_id = ?", 
                  (valeur, joueur_id, journee_id))
        conn.commit()

        logger.info(f"✅ Score mis à jour : Joueur {joueur_id}, Journée {journee_id}, {jeu} = {valeur}")
        return jsonify({"message": "Score mis à jour avec succès"}), 200
    except Exception as e:
        logger.error(f"❌ Erreur lors de la modification du score : {str(e)}")
        return jsonify({"message": str(e)}), 500

@app.route("/scores", methods=["GET"])
def get_scores():
    conn = get_db()
    c = conn.cursor()
    
    journee_id = request.args.get("journee_id")

    if not journee_id:
        return jsonify({"message": "ID de journée requis"}), 400

    # 🔥 Récupérer les noms des jeux associés à cette journée
    c.execute("SELECT jeu_nom FROM journee_jeux WHERE journee_id = ? ORDER BY id ASC", (journee_id,))
    jeux_noms = [row["jeu_nom"] for row in c.fetchall()]

    # 🔥 Vérifier le nombre de jeux pour la journée
    c.execute("SELECT nombre_jeux FROM journees WHERE id = ?", (journee_id,))
    journee_info = c.fetchone()
    if not journee_info:
        return jsonify({"message": "Journée introuvable"}), 404

    nombre_jeux = journee_info["nombre_jeux"]

    # 🔥 Construire dynamiquement la requête SQL pour récupérer les scores actifs
    colonnes_jeux = [f"s.jeu{i}" for i in range(1, nombre_jeux + 1)]
    query = f"""
        SELECT s.joueur_id, j.nom AS joueur_nom, s.journee_id, d.date AS journee_date, d.nombre_jeux,
               {", ".join(colonnes_jeux)}
        FROM scores s
        JOIN joueurs j ON s.joueur_id = j.id
        JOIN journees d ON s.journee_id = d.id
        WHERE s.journee_id = ?
        ORDER BY d.date ASC, j.nom ASC
    """
    
    c.execute(query, (journee_id,))
    scores = [dict(row) for row in c.fetchall()]

    return jsonify({"scores": scores, "jeux_noms": jeux_noms})


@app.route("/classement", methods=["GET"])
def classement():
    try:
        conn = get_db()
        c = conn.cursor()

        # 🔥 Récupérer le nombre max de jeux existants
        c.execute("SELECT MAX(nombre_jeux) FROM journees")
        max_jeux = c.fetchone()[0] or 2  # Sécurité : min 2 jeux par défaut

        # 🔥 Construire la somme dynamique des scores des jeux actifs
        colonnes_jeux = [f"SUM(COALESCE(s.jeu{i}, 0)) AS jeu{i}" for i in range(1, max_jeux + 1)]
        sum_expression = " + ".join([f"SUM(COALESCE(s.jeu{i}, 0))" for i in range(1, max_jeux + 1)])  # Ex: SUM(jeu1) + SUM(jeu2)

        query = f"""
            SELECT j.id, j.nom, {', '.join(colonnes_jeux)}, 
                   ({sum_expression}) AS score
            FROM joueurs j
            LEFT JOIN scores s ON j.id = s.joueur_id
            GROUP BY j.id, j.nom
            ORDER BY score DESC
        """

        c.execute(query)
        classement = [dict(row) for row in c.fetchall()]
        return jsonify(classement)

    except Exception as e:
        return jsonify({"message": str(e)}), 500

@app.route("/journees/<int:journee_id>/description", methods=["PUT"])
def modifier_description_journee(journee_id):
    if not is_admin():
        return jsonify({"message": "Accès refusé"}), 403

    data = request.json
    nouvelle_description = data.get("description", "").strip()

    conn = get_db()
    c = conn.cursor()
    c.execute("UPDATE journees SET description = ? WHERE id = ?", (nouvelle_description, journee_id))
    conn.commit()

    return jsonify({"message": "Description mise à jour avec succès"})

@app.route("/change-password", methods=["POST"])
def change_password():
    if not validate_csrf():
        return jsonify({"message": "Token CSRF invalide"}), 403

    data = request.json
    old_password = data.get("oldPassword")
    new_password = data.get("newPassword")

    if not old_password or not new_password:
        return jsonify({"message": "Ancien et nouveau mot de passe requis"}), 400

    if "username" not in session:
        return jsonify({"message": "Utilisateur non connecté"}), 401

    conn = get_db()
    c = conn.cursor()
    c.execute("SELECT password FROM users WHERE username = ?", (session["username"],))
    user = c.fetchone()

    if not user or not check_password_hash(user["password"], old_password):
        return jsonify({"message": "Ancien mot de passe incorrect"}), 400

    hashed_password = generate_password_hash(new_password)
    c.execute("UPDATE users SET password = ? WHERE username = ?", (hashed_password, session["username"]))
    conn.commit()

    return jsonify({"message": "Mot de passe changé avec succès"}), 200

@app.route("/export-csv", methods=["GET"])
def export_csv():
    if not is_admin():
        return jsonify({"message": "Accès refusé"}), 403

    conn = get_db()
    c = conn.cursor()

    c.execute("""
        SELECT j.nom AS joueur, d.date AS journee, d.description,
               (SELECT GROUP_CONCAT(jeu_nom, '|') FROM journee_jeux WHERE journee_id = d.id) AS jeux,
               s.jeu1, s.jeu2, s.jeu3, s.jeu4, s.jeu5, s.jeu6, s.jeu7, s.jeu8, s.jeu9,
               COALESCE(s.jeu1, 0) + COALESCE(s.jeu2, 0) + COALESCE(s.jeu3, 0) + COALESCE(s.jeu4, 0) +
               COALESCE(s.jeu5, 0) + COALESCE(s.jeu6, 0) + COALESCE(s.jeu7, 0) + COALESCE(s.jeu8, 0) +
               COALESCE(s.jeu9, 0) AS total
        FROM scores s
        JOIN joueurs j ON s.joueur_id = j.id
        JOIN journees d ON s.journee_id = d.id
        ORDER BY d.date ASC, j.nom ASC
    """)
    rows = c.fetchall()

    def generate():
        yield "Joueur,Journée,Description,Jeux,Jeu1,Jeu2,Jeu3,Jeu4,Jeu5,Jeu6,Jeu7,Jeu8,Jeu9,Total\n"
        for row in rows:
            description = row["description"] if row["description"] else ""
            jeux = row["jeux"] if row["jeux"] else ""
            yield f"{row['joueur']},{row['journee']},{description},\"{jeux}\",{row['jeu1']},{row['jeu2']},{row['jeu3']},{row['jeu4']},{row['jeu5']},{row['jeu6']},{row['jeu7']},{row['jeu8']},{row['jeu9']},{row['total']}\n"

    return Response(generate(), mimetype="text/csv", headers={"Content-Disposition": "attachment; filename=sauvegarde.csv"})

@app.route("/import-csv", methods=["POST"])
def import_csv():
    if not is_admin():
        return jsonify({"message": "Accès refusé"}), 403

    if "file" not in request.files:
        return jsonify({"message": "Aucun fichier fourni"}), 400

    file = request.files["file"]
    if file.filename == "":
        return jsonify({"message": "Nom de fichier invalide"}), 400

    try:
        conn = get_db()
        c = conn.cursor()

        c.execute("DELETE FROM scores")
        c.execute("DELETE FROM joueurs")
        c.execute("DELETE FROM journees")
        c.execute("DELETE FROM journee_jeux")
        conn.commit()

        joueur_map = {}
        journee_map = {}
        jeux_map = {}

        with tempfile.NamedTemporaryFile(delete=False) as temp_file:
            file.save(temp_file.name)
            temp_file.close()

            with open(temp_file.name, newline="", encoding="utf-8") as csvfile:
                reader = csv.DictReader(csvfile)

                for row in reader:
                    joueur_nom = row["Joueur"].strip()
                    journee_date = row["Journée"].strip()
                    description = row["Description"].strip()
                    jeux = row["Jeux"].strip().split("|") if row["Jeux"] else []

                    if joueur_nom not in joueur_map:
                        c.execute("INSERT INTO joueurs (nom) VALUES (?)", (joueur_nom,))
                        joueur_map[joueur_nom] = c.lastrowid

                    if journee_date not in journee_map:
                        c.execute("INSERT INTO journees (date, description, nombre_jeux) VALUES (?, ?, ?)", (journee_date, description, len(jeux)))
                        journee_map[journee_date] = c.lastrowid

                    journee_id = journee_map[journee_date]

                    if journee_id not in jeux_map:
                        jeux_map[journee_id] = set()
                    
                    for jeu in jeux:
                        jeu = jeu.strip()
                        if jeu and jeu not in jeux_map[journee_id]:
                            c.execute("INSERT INTO journee_jeux (journee_id, jeu_nom) VALUES (?, ?)", (journee_id, jeu))
                            jeux_map[journee_id].add(jeu)

                    c.execute("UPDATE journees SET nombre_jeux = ? WHERE id = ?", (len(jeux_map[journee_id]), journee_id))

                    c.execute("INSERT INTO scores (joueur_id, journee_id, jeu1, jeu2, jeu3, jeu4, jeu5, jeu6, jeu7, jeu8, jeu9) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                              (joueur_map[joueur_nom], journee_id, row["Jeu1"], row["Jeu2"], row["Jeu3"], row["Jeu4"], row["Jeu5"], row["Jeu6"], row["Jeu7"], row["Jeu8"], row["Jeu9"]))
        conn.commit()
        return jsonify({"message": "Importation réussie !"}), 200

    except Exception as e:
        return jsonify({"message": str(e)}), 500

if __name__ == "__main__":
    with app.app_context():
        init_db()
    app.run(host="0.0.0.0", port=7654, debug=False)
