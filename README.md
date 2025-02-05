# ⚠️ WARNING: Project in Development

**This project is currently under development and is not yet fully secure or production-ready.**  
Users should deploy and use this software **at their own risk**, especially in environments requiring high security.

# 🏆 Zlade's Ranking System

Zlade's Ranking System is a **tournament management platform** designed to track player rankings, manage match days, and update scores dynamically. This system is ideal for competitive gaming communities, esports leagues, and local tournaments.

## 🌟 Features

✅ **Player & Tournament Management** – Easily add players, create match days, and assign scores.  
✅ **Real-Time Ranking System** – Automatically updates player rankings based on match results.  
✅ **Game Customization** – Modify game names and set the number of games per match day.  
✅ **Admin Panel with Authentication** – Secure access with login, session management, and role-based controls.  
✅ **Score Tracking & History** – View and modify scores for each player across different game days.  
✅ **CSV Export & Import** – Save and restore tournament data easily.  
✅ **Dark-Themed UI** – A sleek and modern interface with **Bootstrap**, **Flatpickr**, and **SweetAlert2** integration.  
✅ **Secure API** – Powered by **Flask**, with CSRF protection, session-based authentication, and secure password hashing.  

---

## ⚙️ Installation Guide

### 🔹 **1. Clone the repository**
```sh
git clone https://github.com/zlade/zranking.git
cd zranking
```

### 🔹 **2. Create and activate a virtual environment**
```sh
python -m venv venv
source venv/bin/activate  # On macOS/Linux
venv\Scripts\activate  # On Windows
```

### 🔹 **3. Install dependencies**
```sh
pip install -r requirements.txt
```

### 🔹 **5. Run the application**
```sh
python app.py
```
🚀 The app will be available at: **`http://localhost:7654`**

---

## 📌 Usage

- **Login as Admin:**  
  - Default username: `admin`  
  - Default password: `R4NKing!`  
- **Manage Players & Match Days**
  - Add players and match days via the **Admin panel**.
- **Track Rankings**
  - Rankings update automatically based on player scores.

---

## 📦 Project Structure

```
/zlade-ranking-system
│── frontend/
│   ├── index.html        # Main UI
│   ├── script.js         # Frontend logic
│── app.py                # Backend Flask app
│── database.db           # SQLite database
│── requirements.txt      # Python dependencies
│── README.md             # Project documentation
│── LICENSE               # License file (GPL v3)
```

---

## 🔒 Security Features

- **CSRF Protection** with Flask-WTF.  
- **Session-based authentication** using Flask-Session.  
- **Password hashing** with `Werkzeug.security`.  

---

## 🛠️ Technology Stack

- **Frontend:** HTML, CSS (Bootstrap), JavaScript  
- **Backend:** Flask (Python)  
- **Database:** SQLite  
- **Security:** CSRF Protection, Flask-Session, Password Hashing  

---

## 📝 License

This project is licensed under the **GPL v3 License**, ensuring that all modifications and redistributions remain **open-source**.

---

## 🤝 Contributing

We welcome contributions! Feel free to **fork the repository**, create a new branch, and submit a **pull request**.  

1. Fork the project  
2. Create your feature branch:  
   ```sh
   git checkout -b feature/new-feature
   ```
3. Commit your changes:  
   ```sh
   git commit -m "Add new feature"
   ```
4. Push to the branch:  
   ```sh
   git push origin feature/new-feature
   ```
5. Open a **Pull Request** on GitHub 🚀

---

## 📬 Contact

For any questions or support, feel free to **open an issue** or reach out!

🔥 **Developed by Zlade**  
📧 **Contact: zlade@zlade.com**  
🌍 **Website: zlade.com**  

---

## 🎮 Happy Ranking! 🏆  
