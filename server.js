const path = require("path");
require("dotenv").config();
const express = require("express");
const mysql = require("mysql2");
const cors = require("cors");
const bcrypt = require("bcrypt");

const app = express();
app.use(express.json());
app.use(cors());
app.use(express.static(path.join(__dirname, "public")));

const db = mysql.createConnection({
    host: "mainline.proxy.rlwy.net",
    user: "root",
    password: "qUbojMMlHIkZYHuvkQUoKJfDlzFLWutU",
    database: "railway",
    port: 23798
});

db.connect(err => {
    if (err) {
        console.error("Błąd MySQL:", err);
    } else {
        console.log("Połączono z MySQL");
    }
});

app.post("/api/register", async (req, res) => {
    const { username, password, role = "user" } = req.body;
    if (!username || !password) {
        return res.status(400).json({ success: false, message: "Wprowadź nazwę użytkownika i hasło!" });
    }

    const checkUserQuery = "SELECT * FROM users WHERE username = ?";
    db.query(checkUserQuery, [username], async (err, results) => {
        if (err) return res.status(500).json({ success: false, message: "Błąd serwera" });
        if (results.length > 0) return res.json({ success: false, message: "Użytkownik już istnieje!" });

        const hashedPassword = await bcrypt.hash(password, 10);
        const insertUserQuery = "INSERT INTO users (username, password, role) VALUES (?, ?, ?)";
        db.query(insertUserQuery, [username, hashedPassword, role], (err) => {
            if (err) return res.status(500).json({ success: false, message: "Błąd rejestracji użytkownika" });
            res.json({ success: true, message: "Użytkownik zarejestrowany!" });
        });
    });
});

app.post("/api/login", (req, res) => {
    const { username, password } = req.body;
    if (!username || !password) {
        return res.status(400).json({ success: false, message: "Podaj nazwę użytkownika i hasło!" });
    }

    const checkUserQuery = "SELECT * FROM users WHERE username = ?";
    db.query(checkUserQuery, [username], async (err, results) => {
        if (err) return res.status(500).json({ success: false, message: "Błąd serwera" });
        if (results.length === 0) return res.json({ success: false, message: "Nieprawidłowe dane logowania!" });

        const user = results[0];
        const isPasswordValid = await bcrypt.compare(password, user.password);
        if (!isPasswordValid) return res.json({ success: false, message: "Nieprawidłowe hasło!" });

        res.json({ success: true, userId: user.id, username: user.username, role: user.role });
    });
});

app.post("/api/keys/assign", (req, res) => {
    const { keyId, username } = req.body;
    if (!keyId || !username) {
        return res.status(400).json({ success: false, message: "Brak danych!" });
    }

    const checkUserQuery = "SELECT id FROM users WHERE username = ?";
    db.query(checkUserQuery, [username], (err, results) => {
        if (err || results.length === 0) {
            return res.status(400).json({ success: false, message: "Nie znaleziono użytkownika!" });
        }

        const userId = results[0].id;

        const checkKeyQuery = "SELECT assignedTo FROM keys_door WHERE keyId = ?";
        db.query(checkKeyQuery, [keyId], (err, keyResults) => {
            if (err || keyResults.length === 0) {
                return res.status(400).json({ success: false, message: "Taki klucz nie istnieje." });
            }

            if (keyResults[0].assignedTo !== null) {
                return res.json({ success: false, message: "Ten klucz jest już przypisany." });
            }

            const assignKeyQuery = "UPDATE keys_door SET assignedTo = ? WHERE keyId = ?";
            db.query(assignKeyQuery, [userId, keyId], (err) => {
                if (err) return res.status(500).json({ success: false, message: "Błąd przypisania klucza" });

                const insertHistoryQuery = "INSERT INTO keys_history (userId, keyId, action) VALUES (?, ?, 'Pobrano')";
                db.query(insertHistoryQuery, [userId, keyId], (err) => {
                    if (err) console.error("Błąd zapisu historii:", err);
                });
                res.json({ success: true, message: "Klucz przypisany!" });
            });
        });
    });
});

app.post("/api/keys/return", (req, res) => {
    const { keyId, username } = req.body;
    if (!keyId || !username) {
        return res.status(400).json({ success: false, message: "Brak danych!" });
    }

    const checkUserQuery = "SELECT id FROM users WHERE username = ?";
    db.query(checkUserQuery, [username], (err, results) => {
        if (err || results.length === 0) {
            return res.json({ success: false, message: "Nie znaleziono użytkownika!" });
        }

        const userId = results[0].id;

        const checkKeyQuery = "SELECT assignedTo FROM keys_door WHERE keyId = ?";
        db.query(checkKeyQuery, [keyId], (err, keyResults) => {
            if (err || keyResults.length === 0) {
                return res.json({ success: false, message: "Taki klucz nie istnieje." });
            }

            if (keyResults[0].assignedTo === null) {
                return res.json({ success: false, message: "Ten klucz nie jest przypisany." });
            }

            const returnKeyQuery = "UPDATE keys_door SET assignedTo = NULL WHERE keyId = ?";
            db.query(returnKeyQuery, [keyId], (err, results) => {
                if (err || results.affectedRows === 0) {
                    return res.json({ success: false, message: "Klucz nie mógł zostać zwrócony." });
                }

                const insertHistoryQuery = "INSERT INTO keys_history (userId, keyId, action) VALUES (?, ?, 'Oddano')";
                db.query(insertHistoryQuery, [userId, keyId], (err) => {
                    if (err) console.error("Błąd zapisu historii:", err);
                });

                res.json({ success: true, message: "Klucz zwrócony!" });
            });
        });
    });
});

app.post("/api/keys/add", (req, res) => {
    const { keyId, keyName } = req.body;

    if (!keyId || !keyName) {
        return res.status(400).json({ success: false, message: "Podaj ID i nazwę klucza." });
    }

    const checkQuery = "SELECT * FROM keys_door WHERE keyId = ?";
    db.query(checkQuery, [keyId], (err, results) => {
        if (err) return res.status(500).json({ success: false, message: "Błąd zapytania." });
        if (results.length > 0) {
            return res.json({ success: false, message: "Klucz o takim ID już istnieje." });
        }

        const insertQuery = "INSERT INTO keys_door (keyId, keyName) VALUES (?, ?)";
        db.query(insertQuery, [keyId, keyName], (err) => {
            if (err) return res.status(500).json({ success: false, message: "Błąd dodawania klucza." });
            res.json({ success: true, message: "Klucz dodany pomyślnie!" });
        });
    });
});

app.get("/api/keys/history", (req, res) => {
    const historyQuery = `
        SELECT h.id, k.keyId, k.keyName, u.username, h.action, h.timestamp
        FROM keys_history h
                 JOIN users u ON h.userId = u.id
                 JOIN keys_door k ON h.keyId = k.keyId
        ORDER BY h.timestamp DESC`;

    db.query(historyQuery, (err, historyResults) => {
        if (err) return res.status(500).json({ success: false, message: "Błąd pobierania historii" });
        res.json({ success: true, history: historyResults });
    });
});

const PORT = process.env.PORT || 5001;
app.listen(PORT, '0.0.0.0', () => console.log(`Serwer działa na portcie ${PORT}`));

app.get("/api", (req, res) => {
    res.send("API działa!");
});
