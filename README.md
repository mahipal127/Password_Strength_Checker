# 🔐 Advanced Password Strength Checker

An intelligent and secure **Password Strength Checker** built using C++ (DSA concepts) that evaluates the strength of a password based on multiple security parameters. This project is designed to promote strong password practices and enhance cybersecurity awareness.

---

## 📌 Features

- 🔤 Checks character diversity:
  - Uppercase, lowercase, digits, and special characters
- 📏 Length-based scoring system
- 📂 Dictionary attack detection using file handling (1000+ common passwords)
- 🔁 Detection of repeated characters (e.g., "aaa", "111")
- 🔍 Sequential pattern detection (e.g., "12345", "abcde")
- ⌨️ Keyboard pattern detection (e.g., "qwerty", "asdf")
- 📊 Entropy calculation for randomness measurement
- 🧠 Smart scoring algorithm with penalties and bonuses
- 💡 Generates suggestions to improve weak passwords

---

## 🧮 Scoring System

The password is evaluated using a custom scoring algorithm:

### ✅ Positive Points
- Uppercase letters → +2
- Lowercase letters → +1
- Numbers → +2
- Special characters → +2
- Length ≥ 12 → +2

### ❌ Negative Points
- Common password (dictionary match) → -3
- Sequential patterns → -2
- Repeated characters → -2
- Keyboard patterns → -2
- Low entropy → -1

---

## 📊 Strength Levels

| Score | Strength Level |
|------|--------------|
| 0–3  | 🔴 Very Weak |
| 4–6  | 🟠 Weak |
| 7–9  | 🟡 Moderate |
| 10–12 | 🟢 Strong |
| 13+  | 🔥 Very Strong |

---

## ⚙️ Tech Stack

- **C++ (Core Logic & DSA)**
- File Handling (Dictionary attack detection)
- STL (unordered_set, vector, string processing)

---

## ▶️ How to Run

```bash
g++ -O2 -std=c++17 -o password_checker main.cpp
./password_checker
