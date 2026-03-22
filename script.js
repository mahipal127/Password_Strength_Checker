/**
 * ============================================================
 *  Advanced Password Strength Checker — script.js
 *  Real-time password analysis engine (mirrors C++ main.cpp)
 *
 *  SCORING ALGORITHM
 *  -----------------
 *  +2  Uppercase letters
 *  +2  Lowercase letters
 *  +2  Digits
 *  +3  Special characters
 *  +4  Length ≥ 16  |  +2  length 12-15  |  +1  length 8-11  |  -2  length < 8
 *  -3  EXACT dictionary match only (no substring scan)
 *  -2  Sequential pattern  (12345, abcdef, qwerty …)
 *  -2  Repeated chars      (aaa, 111 …)
 *  -2  Keyboard walk       (asdf, zxcv …)
 *  -1  Entropy < 28 bits
 *
 *  Max possible score = 13  →  all 5 tiers reachable!
 *  STRENGTH LEVELS  ≤3 Very Weak | 4-6 Weak | 7-9 Moderate
 *                   10-12 Strong  | 13+ Very Strong
 * ============================================================
 */

/* ─────────────────────────────────────────────────────────────
   1. COMMON PASSWORDS  (HashSet / JS Set — O(1) lookup)
      Mirrors the data in common_passwords.txt
   ───────────────────────────────────────────────────────────── */
const COMMON_PASSWORDS = new Set([
  "123456","password","123456789","12345678","12345","1234567","1234567890",
  "qwerty","abc123","million2","000000","1234","iloveyou","aaron431",
  "password1","qqww1122","123","omgpop","123321","654321","qwerty123",
  "admin","qazwsx","123654","master","666666","111111","1q2w3e4r",
  "dragon","pass","monkey","shadow","sunshine","princess","letmein",
  "welcome","superman","michael","football","charlie","donald",
  "password123","ninja","mustang","access","flower","hello","master1",
  "passw0rd","secret","password2","batman","iloveyou1","starwars",
  "whatever","trustno1","jordan23","harley","ranger","dakota","magic",
  "zxcvbnm","asdfgh","qwertyuiop","asdfghjkl","zxcvbn","asdf","zxcv",
  "qwert","poiuy","lkjhg","mnbvc","abc","111222","321654","789456",
  "456789","159753","753951","147852","258369","369258","741852",
  "147258369","963852741","112233","223344","334455","445566","556677",
  "667788","778899","889900","998877","887766","776655","665544","554433",
  "443322","332211","12341234","11111111","00000000","99999999","55555555",
  "77777777","88888888","22222222","33333333","44444444","66666666",
  "aaaaaa","bbbbbb","cccccc","dddddd","ffffff","gggggg","hhhhhh","jjjjjj",
  "kkkkkk","llllll","mmmmmm","nnnnnn","pppppp","rrrrrr","ssssss","tttttt",
  "uuuuuu","wwwwww","zzzzzz","aaa111","bbb222","ccc333","ddd444","eee555",
  "fff666","ggg777","hhh888","iii999","jjj000","test","user","guest",
  "demo","sample","trial","login","root","admin123","administrator",
  "root123","toor","pass123","pass1234","pasword","p@ssword","p@ss123",
  "p@ssw0rd","pa$$word","pa$$w0rd","passw0rd1","changeme","secret123",
  "abc1234","abc12345","abcd1234","abcdefg","abcdef1","abcdef12",
  "abc123456","123abc","1234abc","12345abc","123456abc","qwerty1",
  "qwerty12","qwerty123","qwerty1234","qwertyuiop123","asdfghjkl123",
  "iloveyou2","iloveyou123","love1234","loveyou","sweetheart","chocolate",
  "pokemon","pikachu","goku","naruto","sasuke","bleach","luffy","zoro",
  "nami","onepiece","dragonball","vegeta","android","samsung","apple123",
  "iphone","google","facebook","twitter","instagram","youtube","microsoft",
  "windows10","linux123","ubuntu","debian","fedora","macbook","firefox",
  "chrome","safari","opera","outlook","hotmail1","yahoo123","gmail123",
  "email123","mypassword","mypass123","new123456","old123456","temp123",
  "temporary","test1234","testing123","qa12345","dev12345","staging",
  "production","company123","office123","work1234","home1234","family123",
  "kids1234","baby1234","mama1234","papa1234","daddy123","mommy123",
  "sister123","brother1","mother12","father12","grandma1","grandpa1",
  "uncle123","aunt1234","cousin12","friend12","boyfriend","girlfriend",
  "married1","wedding1","birthday","happyday","holiday1","vacation",
  "summer12","winter12","spring12","autumn12","january1","february",
  "march123","april123","june1234","july1234","august12","october1",
  "monday12","tuesday1","thursday","friday12","saturday","sunday12",
  "2020","2021","2022","2023","2024","2025","2026","2019","2018","2017",
  "2016","2015","2010","2000","1999","1990","1980","1970",
  "1234abcd","abcd4321","password!","password@","password#","password$",
  "welcome1","welcome123","hello123","hello1234","hi12345","hey12345",
  "goodday1","morning1","evening1","night123","sunshine1","moonlight",
  "starlight","rainbow1","ocean123","mountain","riverside","lakeview1",
  "deadbeef","cafebabe","c0ffee","c0decafe","badcode","goodcode",
  "monkey1","monkey12","monkey123","letmein1","letmein2","shadow1",
  "shadow12","shadow123","sunshine2","sunshine3","princess1","princess2",
  "football2","football3","master12","master123","superman2","batman123",
  "harley1","harley12","ranger1","ranger12","dakota1","dakota12",
  "soccer123","football1","baseball","basketball","tennis12","cricket1",
  "hockey12","rugby123","golf1234","swimming","running1","cycling1",
  "boxing12","wrestling","volleyball","badminton","minecraft","roblox12",
  "fortnite","pubg1234","valorant","csgo1234","dota1234","overwatch",
  "pokemon1","zelda123","mario123","sonic123","spiderman","batman12",
  "ironman1","avengers","deadpool","aquaman1","superman1","flash123",
  "jazz1234","blues123","rock1234","metal123","punk1234","hip1234",
  "rap12345","country1","classical","reggae12","soul1234","disco123",
  "techno12","house123","trance12","dubstep1","folkmusic","popmusic",
  "edm12345","beatles1","nirvana1","radiohead","coldplay","acdc1234",
  "metallica","aerosmith","greenday","linkinpark","slipknot","rammstein",
  "password01","password02","password03","password10","password99",
  "pass1word","pa55word","p4ssword","pa5sw0rd","!password","#password",
  "abc@123","abc#123","abc$123","abc!123","123@abc","Q1w2e3r4","q1w2e3r4",
  "Q1W2E3R4","zaq12wsx","xsw21qaz","qaz2wsx","wsx3edc","edc4rfv",
  "rfv5tgb","tgb6yhn","extreme1","maximum1","minimum1","perfect1",
  "excellent","amazing1","awesome1","wonderful","fantastic","incredible",
  "brilliant","superb123","supreme1","infinite1","eternal1","forever1"
]);

/* ─────────────────────────────────────────────────────────────
   2. PATTERN DATA
   ───────────────────────────────────────────────────────────── */

// Sequential substring patterns
const SEQUENTIAL_PATTERNS = [
  "abcde","bcdef","cdefg","defgh","efghi","fghij","ghijk","hijkl","ijklm",
  "jklmn","klmno","lmnop","mnopq","nopqr","opqrs","pqrst","qrstu","rstuv",
  "stuvw","tuvwx","uvwxy","vwxyz",
  "12345","23456","34567","45678","56789","67890",
  "qwerty","azerty","09876"
];

// Keyboard walk patterns (also checked in reverse)
const KEYBOARD_WALKS = [
  "qwerty","asdf","zxcv","qwert","asdfg","zxcvb",
  "poiuy","lkjh","mnbv","asdfghjkl","zxcvbnm","qwertyuiop"
];

/* ─────────────────────────────────────────────────────────────
   3. HELPER FUNCTIONS
   ───────────────────────────────────────────────────────────── */

/**
 * Check for 3+ consecutive identical characters (case-insensitive)
 * e.g. "aaa", "111", "zzz"
 */
function hasRepeatedChars(pwd) {
  const lower = pwd.toLowerCase();
  let count = 1;
  for (let i = 1; i < lower.length; i++) {
    if (lower[i] === lower[i - 1]) {
      count++;
      if (count >= 3) return true;
    } else {
      count = 1;
    }
  }
  return false;
}

/**
 * Detect keyboard walk patterns (and their reverses)
 */
function hasKeyboardWalk(pwd) {
  const lower = pwd.toLowerCase();
  for (const walk of KEYBOARD_WALKS) {
    if (lower.includes(walk)) return true;
    const rev = walk.split('').reverse().join('');
    if (lower.includes(rev)) return true;
  }
  return false;
}

/**
 * Detect sequential character patterns
 */
function hasSequentialPattern(pwd) {
  const lower = pwd.toLowerCase();
  for (const pattern of SEQUENTIAL_PATTERNS) {
    if (lower.includes(pattern)) return true;
  }
  return false;
}

/**
 * Dictionary check: EXACT match only.
 * Substring scanning was too aggressive — it penalised strong passwords
 * that merely contained a short common word (e.g. "hell", "pass", "super").
 */
function isDictionaryPassword(pwd) {
  return COMMON_PASSWORDS.has(pwd.toLowerCase());
}

/**
 * Compute character-set size based on types present
 */
function charsetSize(pwd) {
  const hasUpper   = /[A-Z]/.test(pwd);
  const hasLower   = /[a-z]/.test(pwd);
  const hasDigit   = /[0-9]/.test(pwd);
  const hasSpecial = /[^A-Za-z0-9]/.test(pwd);
  let size = 0;
  if (hasUpper)   size += 26;
  if (hasLower)   size += 26;
  if (hasDigit)   size += 10;
  if (hasSpecial) size += 32;
  return size || 1;
}

/**
 * Shannon-like entropy: length × log2(charsetSize)
 */
function calcEntropy(pwd) {
  return pwd.length * Math.log2(charsetSize(pwd));
}

/* ─────────────────────────────────────────────────────────────
   4. CORE SCORING ENGINE
      Mirrors the C++ calcScore() method exactly
   ───────────────────────────────────────────────────────────── */
function calcScore(pwd) {
  if (!pwd) return 0;

  let score = 0;

  // Character type bonuses
  if (/[A-Z]/.test(pwd))        score += 2;  // Uppercase
  if (/[a-z]/.test(pwd))        score += 2;  // Lowercase  (+2, was +1)
  if (/[0-9]/.test(pwd))        score += 2;  // Digits
  if (/[^A-Za-z0-9]/.test(pwd)) score += 3;  // Special chars (+3, was +2)

  // Length bonuses / penalties
  const len = pwd.length;
  if      (len >= 16) score += 4;  // +4 very long (pushes into Very Strong)
  else if (len >= 12) score += 2;
  else if (len >= 8)  score += 1;
  else                score -= 2;

  // Dictionary penalty
  if (isDictionaryPassword(pwd))  score -= 3;

  // Pattern penalties
  if (hasSequentialPattern(pwd))  score -= 2;
  if (hasRepeatedChars(pwd))      score -= 2;
  if (hasKeyboardWalk(pwd))       score -= 2;

  // Entropy penalty
  if (calcEntropy(pwd) < 28)      score -= 1;

  return score;
}

/**
 * Map score → strength label + CSS class + percentage width
 */
function getStrengthInfo(score) {
  if      (score <= 3)  return { label: "Very Weak",   cls: "s-very-weak",   pct: 12 };
  else if (score <= 6)  return { label: "Weak",         cls: "s-weak",        pct: 30 };
  else if (score <= 9)  return { label: "Moderate",     cls: "s-moderate",    pct: 55 };
  else if (score <= 12) return { label: "Strong",       cls: "s-strong",      pct: 78 };
  else                  return { label: "Very Strong",  cls: "s-very-strong", pct: 100 };
}

/**
 * Return a colour hex matching the strength level
 */
function getStrengthColour(cls) {
  const map = {
    "s-very-weak":   "#ff4757",
    "s-weak":        "#ff6b35",
    "s-moderate":    "#ffd32a",
    "s-strong":      "#7bed9f",
    "s-very-strong": "#2ed573"
  };
  return map[cls] || "#8e8eb4";
}

/**
 * Build suggestion strings (same logic as C++ getSuggestions())
 */
function getSuggestions(pwd) {
  if (!pwd) return [];
  const suggestions = [];

  if (!/[A-Z]/.test(pwd))        suggestions.push("Add uppercase letters (A–Z)");
  if (!/[a-z]/.test(pwd))        suggestions.push("Add lowercase letters (a–z)");
  if (!/[0-9]/.test(pwd))        suggestions.push("Add numbers (0–9)");
  if (!/[^A-Za-z0-9]/.test(pwd)) suggestions.push("Add special characters (!@#$%^&*)");
  if (pwd.length < 12)           suggestions.push("Increase length to at least 12 characters");
  if (isDictionaryPassword(pwd)) suggestions.push("Avoid common / easily guessable passwords");
  if (hasSequentialPattern(pwd)) suggestions.push("Avoid sequential patterns (123, abc, qwerty)");
  if (hasRepeatedChars(pwd))     suggestions.push("Avoid repeated characters (aaa, 111)");
  if (hasKeyboardWalk(pwd))      suggestions.push("Avoid keyboard walks (asdf, zxcv)");
  if (calcEntropy(pwd) < 28)     suggestions.push("Use a more random mix of characters to raise entropy");

  return suggestions;
}

/* ─────────────────────────────────────────────────────────────
   5. DOM REFERENCES
   ───────────────────────────────────────────────────────────── */
const input          = document.getElementById('password-input');
const toggleBtn      = document.getElementById('toggle-visibility');
const eyeOpen        = document.getElementById('icon-eye-open');
const eyeClosed      = document.getElementById('icon-eye-closed');
const charCountEl    = document.getElementById('char-count');

const meterFill      = document.getElementById('meter-fill');
const meterTrack     = document.querySelector('.meter-track');
const strengthLabel  = document.getElementById('strength-label');
const scoreBadge     = document.getElementById('score-badge');

const entropyValue   = document.getElementById('entropy-value');
const charsetValue   = document.getElementById('charset-value');
const lengthValue    = document.getElementById('length-value');
const finalScore     = document.getElementById('final-score');

const suggestionList = document.getElementById('suggestions-list');

// Security check elements
const checks = {
  upper:    document.getElementById('check-upper'),
  lower:    document.getElementById('check-lower'),
  digit:    document.getElementById('check-digit'),
  special:  document.getElementById('check-special'),
  length:   document.getElementById('check-length'),
  dict:     document.getElementById('check-dict'),
  seq:      document.getElementById('check-seq'),
  repeat:   document.getElementById('check-repeat'),
  keyboard: document.getElementById('check-keyboard'),
  entropy:  document.getElementById('check-entropy'),
};

/* ─────────────────────────────────────────────────────────────
   6. UI UPDATERS
   ───────────────────────────────────────────────────────────── */

/** Set a check item to pass / fail / neutral */
function setCheck(el, state) {
  el.classList.remove('pass', 'fail');
  if (state === true)  el.classList.add('pass');
  if (state === false) el.classList.add('fail');
}

/** Render the full UI based on the current password value */
function updateUI(pwd) {
  const score  = calcScore(pwd);
  const info   = pwd ? getStrengthInfo(score) : { label: "Enter a password", cls: "", pct: 0 };
  const colour = pwd ? getStrengthColour(info.cls) : "#8e8eb4";
  const entropy = pwd ? calcEntropy(pwd) : 0;
  const cs      = pwd ? charsetSize(pwd) : 0;

  // ── Character count ─────────────────────────────
  charCountEl.textContent = `${pwd.length} character${pwd.length !== 1 ? 's' : ''}`;
  charCountEl.style.color = pwd.length >= 12 ? "#7bed9f" : pwd.length >= 8 ? "#ffd32a" : pwd.length > 0 ? "#ff6b35" : "var(--text-muted)";

  // ── Strength meter bar ──────────────────────────
  meterFill.style.width           = info.pct + "%";
  meterFill.style.backgroundColor = colour;
  meterTrack.setAttribute('aria-valuenow', info.pct);

  // ── Labels & badge ──────────────────────────────
  strengthLabel.textContent  = info.label;
  strengthLabel.style.color  = colour;
  scoreBadge.textContent     = pwd ? `${score} pts` : "— pts";
  scoreBadge.style.color     = colour;
  scoreBadge.style.borderColor = colour + "55";

  // ── Body class (for CSS colour overrides) ───────
  document.body.className = info.cls || "";

  // ── Stats row ───────────────────────────────────
  entropyValue.textContent = pwd ? `${entropy.toFixed(1)} bits` : "0 bits";
  charsetValue.textContent = pwd ? cs : "0";
  lengthValue.textContent  = pwd.length;
  finalScore.textContent   = pwd ? score : "0";
  finalScore.style.color   = colour;

  // ── Security checks ─────────────────────────────
  if (!pwd) {
    Object.values(checks).forEach(el => setCheck(el, null));
  } else {
    setCheck(checks.upper,    /[A-Z]/.test(pwd));
    setCheck(checks.lower,    /[a-z]/.test(pwd));
    setCheck(checks.digit,    /[0-9]/.test(pwd));
    setCheck(checks.special,  /[^A-Za-z0-9]/.test(pwd));
    setCheck(checks.length,   pwd.length >= 12);
    setCheck(checks.dict,     !isDictionaryPassword(pwd));
    setCheck(checks.seq,      !hasSequentialPattern(pwd));
    setCheck(checks.repeat,   !hasRepeatedChars(pwd));
    setCheck(checks.keyboard, !hasKeyboardWalk(pwd));
    setCheck(checks.entropy,  entropy >= 28);
  }

  // ── Suggestions list ────────────────────────────
  suggestionList.innerHTML = '';

  if (!pwd) {
    const li = document.createElement('li');
    li.className = 'suggestion-placeholder';
    li.textContent = 'Start typing to see suggestions…';
    suggestionList.appendChild(li);
    return;
  }

  const hints = getSuggestions(pwd);
  if (hints.length === 0) {
    const li = document.createElement('li');
    li.className = 'all-clear';
    li.textContent = 'Excellent password — no improvements suggested!';
    suggestionList.appendChild(li);
  } else {
    hints.forEach((hint, i) => {
      const li = document.createElement('li');
      li.textContent = hint;
      li.style.animationDelay = `${i * 40}ms`;
      suggestionList.appendChild(li);
    });
  }
}

/* ─────────────────────────────────────────────────────────────
   7. EVENT LISTENERS
   ───────────────────────────────────────────────────────────── */

// Real-time password analysis
input.addEventListener('input', () => {
  updateUI(input.value);
});

// Show / Hide password toggle
let isVisible = false;
toggleBtn.addEventListener('click', () => {
  isVisible = !isVisible;
  input.type       = isVisible ? 'text' : 'password';
  eyeOpen.style.display   = isVisible ? 'none'  : 'block';
  eyeClosed.style.display = isVisible ? 'block' : 'none';
  toggleBtn.title  = isVisible ? 'Hide password' : 'Show password';
  input.focus();
});

// Initial render
updateUI('');
