/*
 * ============================================================
 *  Advanced Password Strength Checker — C++ Backend
 *  Author  : Generated for Educational/Portfolio Use
 *  Compile : g++ -O2 -std=c++17 -o password_checker.exe main.cpp
 *  Usage   : echo "YourPassword" | .\password_checker.exe
 *            OR: .\password_checker.exe  (then type password)
 * ============================================================
 *
 * SCORING RULES
 * ─────────────
 *  +2  Uppercase letters present
 *  +2  Lowercase letters present
 *  +2  Digits present
 *  +3  Special characters present
 *  +4  Length ≥ 16  (pushes into Very Strong tier)
 *  +2  Length 12–15
 *  +1  Length 8–11
 *  -2  Length < 8
 *  -3  Exact dictionary match (no substring scan)
 *  -2  Sequential pattern detected  (e.g. "12345", "abcdef", "qwerty")
 *  -2  Repeated character run ≥ 3   (e.g. "aaa", "111")
 *  -2  Keyboard walk detected       (e.g. "asdf", "zxcv")
 *  -1  Entropy < 28 bits (very low randomness)
 *
 *  Max possible score = 13 → all 5 tiers reachable!
 * STRENGTH LEVELS
 * ───────────────
 *   ≤3   Very Weak
 *   4–6  Weak
 *   7–9  Moderate
 *  10–12  Strong
 *  13+    Very Strong
 * ============================================================
 */

#include <iostream>
#include <fstream>
#include <sstream>
#include <string>
#include <unordered_set>
#include <vector>
#include <algorithm>
#include <cmath>
#include <cctype>

// ─────────────────────────────────────────────
//  Helper: convert a string to lowercase
// ─────────────────────────────────────────────
std::string toLower(const std::string& s) {
    std::string result = s;
    for (char& c : result) c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
    return result;
}

// ─────────────────────────────────────────────
//  Main password checker class
// ─────────────────────────────────────────────
class PasswordChecker {
public:
    // ── Data members ──────────────────────────
    std::unordered_set<std::string> commonPasswords; // O(1) lookup via hash set

    // Known keyboard walk patterns (substrings to scan for)
    const std::vector<std::string> keyboardWalks = {
        "qwerty", "asdf", "zxcv", "qwert", "asdfg", "zxcvb",
        "poiuy", "lkjh", "mnbv", "1234567890", "09876",
        "qwertyuiop", "asdfghjkl", "zxcvbnm"
    };

    // Known sequential runs (alphabetic / numeric / common patterns)
    const std::vector<std::string> sequentialPatterns = {
        "abcde", "bcdef", "cdefg", "defgh", "efghi", "fghij",
        "ghijk", "hijkl", "ijklm", "jklmn", "klmno", "lmnop",
        "mnopq", "nopqr", "opqrs", "pqrst", "qrstu", "rstuv",
        "stuvw", "tuvwx", "uvwxy", "vwxyz",
        "12345", "23456", "34567", "45678", "56789", "67890",
        "qwerty", "azerty"
    };

    // ─────────────────────────────────────────
    //  Load common passwords from a text file
    //  into the unordered_set for O(1) lookups
    // ─────────────────────────────────────────
    bool loadDictionary(const std::string& filePath) {
        std::ifstream file(filePath);
        if (!file.is_open()) {
            std::cerr << "[WARNING] Could not open " << filePath
                      << ". Dictionary check will be skipped.\n";
            return false;
        }
        std::string line;
        while (std::getline(file, line)) {
            // Trim carriage return (Windows line endings)
            if (!line.empty() && line.back() == '\r') line.pop_back();
            if (!line.empty()) {
                commonPasswords.insert(toLower(line));
            }
        }
        return true;
    }

    // ─────────────────────────────────────────
    //  Check character composition and return
    //  the corresponding character-set size
    //  (used for entropy calculation)
    // ─────────────────────────────────────────
    int charsetSize(const std::string& password) const {
        bool hasUpper = false, hasLower = false, hasDigit = false, hasSpecial = false;
        for (char c : password) {
            if (std::isupper(static_cast<unsigned char>(c))) hasUpper = true;
            else if (std::islower(static_cast<unsigned char>(c))) hasLower = true;
            else if (std::isdigit(static_cast<unsigned char>(c))) hasDigit = true;
            else                                                   hasSpecial = true;
        }
        int size = 0;
        if (hasUpper)   size += 26;
        if (hasLower)   size += 26;
        if (hasDigit)   size +=  10;
        if (hasSpecial) size +=  32;
        return (size == 0) ? 1 : size;
    }

    // ─────────────────────────────────────────
    //  Entropy = length × log2(charset size)
    // ─────────────────────────────────────────
    double calcEntropy(const std::string& password) const {
        int cs = charsetSize(password);
        return static_cast<double>(password.size()) * std::log2(static_cast<double>(cs));
    }

    // ─────────────────────────────────────────
    //  Detect 3+ consecutive repeated chars
    //  e.g. "aaa", "111", "...---"
    // ─────────────────────────────────────────
    bool hasRepeatedChars(const std::string& password) const {
        int count = 1;
        for (size_t i = 1; i < password.size(); ++i) {
            if (std::tolower(static_cast<unsigned char>(password[i])) ==
                std::tolower(static_cast<unsigned char>(password[i - 1]))) {
                ++count;
                if (count >= 3) return true;
            } else {
                count = 1;
            }
        }
        return false;
    }

    // ─────────────────────────────────────────
    //  Detect keyboard walk patterns
    //  (also checks reversed patterns)
    // ─────────────────────────────────────────
    bool hasKeyboardWalk(const std::string& password) const {
        std::string lower = toLower(password);
        for (const std::string& pattern : keyboardWalks) {
            if (lower.find(pattern) != std::string::npos) return true;
            // Check reversed pattern too
            std::string rev = pattern;
            std::reverse(rev.begin(), rev.end());
            if (lower.find(rev) != std::string::npos) return true;
        }
        return false;
    }

    // ─────────────────────────────────────────
    //  Detect sequential character patterns
    // ─────────────────────────────────────────
    bool hasSequentialPattern(const std::string& password) const {
        std::string lower = toLower(password);
        for (const std::string& pattern : sequentialPatterns) {
            if (lower.find(pattern) != std::string::npos) return true;
        }
        return false;
    }

    // ─────────────────────────────────────────
    //  Check dictionary: EXACT match only.
    //  Substring scanning was too aggressive —
    //  it penalised strong passwords that merely
    //  contained a short common word.
    // ─────────────────────────────────────────
    bool isDictionaryPassword(const std::string& password) const {
        return commonPasswords.count(toLower(password)) > 0;
    }

    // ─────────────────────────────────────────
    //  Core scoring function
    //  Returns the final integer score
    // ─────────────────────────────────────────
    int calcScore(const std::string& password) const {
        int score = 0;

        // ── Character type contributions ──────
        bool hasUpper = false, hasLower = false, hasDigit = false, hasSpecial = false;
        for (char c : password) {
            if      (std::isupper(static_cast<unsigned char>(c))) hasUpper   = true;
            else if (std::islower(static_cast<unsigned char>(c))) hasLower   = true;
            else if (std::isdigit(static_cast<unsigned char>(c))) hasDigit   = true;
            else                                                   hasSpecial = true;
        }
        if (hasUpper)   score += 2; // +2 uppercase
        if (hasLower)   score += 2; // +2 lowercase  (was +1)
        if (hasDigit)   score += 2; // +2 digits
        if (hasSpecial) score += 3; // +3 special characters  (was +2)

        // ── Length scoring ────────────────────
        int len = static_cast<int>(password.size());
        if      (len >= 16) score += 4; // +4 very long passwords
        else if (len >= 12) score += 2; // +2 for long passwords
        else if (len >= 8)  score += 1; // +1 medium length
        else                score -= 2; // -2 short passwords

        // ── Dictionary attack check ───────────
        if (isDictionaryPassword(password)) score -= 3;

        // ── Sequential pattern check ──────────
        if (hasSequentialPattern(password)) score -= 2;

        // ── Repeated characters check ─────────
        if (hasRepeatedChars(password)) score -= 2;

        // ── Keyboard walk check ───────────────
        if (hasKeyboardWalk(password)) score -= 2;

        // ── Entropy penalty ───────────────────
        double entropy = calcEntropy(password);
        if (entropy < 28.0) score -= 1;

        return score;
    }

    // ─────────────────────────────────────────
    //  Map score → strength label
    // ─────────────────────────────────────────
    std::string getStrengthLabel(int score) const {
        if      (score <= 3)  return "Very Weak";
        else if (score <= 6)  return "Weak";
        else if (score <= 9)  return "Moderate";
        else if (score <= 12) return "Strong";
        else                  return "Very Strong";
    }

    // ─────────────────────────────────────────
    //  Build a list of improvement suggestions
    // ─────────────────────────────────────────
    std::vector<std::string> getSuggestions(const std::string& password) const {
        std::vector<std::string> suggestions;
        std::string lower = toLower(password);

        // Check for missing character types
        bool hasUpper = false, hasLower = false, hasDigit = false, hasSpecial = false;
        for (char c : password) {
            if      (std::isupper(static_cast<unsigned char>(c))) hasUpper   = true;
            else if (std::islower(static_cast<unsigned char>(c))) hasLower   = true;
            else if (std::isdigit(static_cast<unsigned char>(c))) hasDigit   = true;
            else                                                   hasSpecial = true;
        }

        if (!hasUpper)   suggestions.push_back("Add uppercase letters (A-Z)");
        if (!hasLower)   suggestions.push_back("Add lowercase letters (a-z)");
        if (!hasDigit)   suggestions.push_back("Add numbers (0-9)");
        if (!hasSpecial) suggestions.push_back("Add special characters (!@#$%^&*)");

        if (static_cast<int>(password.size()) < 12)
            suggestions.push_back("Increase length to at least 12 characters");

        if (isDictionaryPassword(password))
            suggestions.push_back("Avoid common / easily guessable passwords");

        if (hasSequentialPattern(password))
            suggestions.push_back("Avoid sequential patterns (123, abc, qwerty)");

        if (hasRepeatedChars(password))
            suggestions.push_back("Avoid repeated characters (aaa, 111)");

        if (hasKeyboardWalk(password))
            suggestions.push_back("Avoid keyboard patterns (asdf, zxcv)");

        if (calcEntropy(password) < 28.0)
            suggestions.push_back("Use a more random mix of characters to increase entropy");

        return suggestions;
    }
};

// ─────────────────────────────────────────────
//  Output helpers — pretty JSON for easy parsing
// ─────────────────────────────────────────────
std::string escapeJson(const std::string& s) {
    std::string out;
    for (char c : s) {
        if      (c == '"')  out += "\\\"";
        else if (c == '\\') out += "\\\\";
        else                out += c;
    }
    return out;
}

// ─────────────────────────────────────────────
//  Entry point
// ─────────────────────────────────────────────
int main() {
    PasswordChecker checker;

    // Load common passwords from file
    checker.loadDictionary("common_passwords.txt");

    // Read password from stdin
    std::string password;
    std::cout << "Enter password to evaluate: ";
    std::getline(std::cin, password);

    if (password.empty()) {
        std::cerr << "[ERROR] No password provided.\n";
        return 1;
    }

    // Run all checks
    int    score    = checker.calcScore(password);
    double entropy  = checker.calcEntropy(password);
    std::string strength = checker.getStrengthLabel(score);
    std::vector<std::string> suggestions = checker.getSuggestions(password);

    // ── Print results as JSON ─────────────────
    std::cout << "\n{\n";
    std::cout << "  \"score\"    : " << score << ",\n";
    std::cout << "  \"strength\" : \"" << escapeJson(strength) << "\",\n";
    std::cout << "  \"entropy\"  : " << std::fixed;
    std::cout.precision(2);
    std::cout << entropy << ",\n";
    std::cout << "  \"suggestions\": [\n";
    for (size_t i = 0; i < suggestions.size(); ++i) {
        std::cout << "    \"" << escapeJson(suggestions[i]) << "\"";
        if (i + 1 < suggestions.size()) std::cout << ",";
        std::cout << "\n";
    }
    std::cout << "  ]\n}\n";

    // ── Human-readable summary ─────────────────
    std::cout << "\n════════════════════════════════\n";
    std::cout << "  Password : " << std::string(password.size(), '*') << "\n";
    std::cout << "  Score    : " << score << "\n";
    std::cout << "  Strength : " << strength << "\n";
    std::cout << "  Entropy  : " << entropy << " bits\n";
    std::cout << "════════════════════════════════\n";

    if (!suggestions.empty()) {
        std::cout << "\n  Suggestions:\n";
        for (const auto& s : suggestions) {
            std::cout << "  • " << s << "\n";
        }
    } else {
        std::cout << "\n  ✓ Excellent password — no improvements suggested!\n";
    }
    std::cout << "\n";

    return 0;
}
