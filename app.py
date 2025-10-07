from flask_session import Session 
import os
import re
import json
import requests
from flask import Flask, render_template, request, redirect, url_for, session, flash
from flask_bcrypt import Bcrypt
import mysql.connector



app = Flask(__name__)
app.secret_key = "a_very_secret_and_secure_key_for_production"
bcrypt = Bcrypt(app)

# Configure server-side sessions
app.config['SESSION_TYPE'] = 'filesystem'         
app.config['SESSION_FILE_DIR'] = './flask_session_dir'
app.config['SESSION_PERMANENT'] = False
app.config['SESSION_USE_SIGNER'] = True         

Session(app)  # Initialize Session


# --- Configuration ---
GEMINI_API_KEY = "your_GEMINI_API_KEY"  # Replace with your valid Gemini API key

# ---------- MySQL Connection ----------
def get_db_connection():
    """Establishes a connection to the MySQL database."""
    db = mysql.connector.connect(
        host="localhost",
        user="root",
        password="Rajesh@1",
        database="smart_quizzer"
    )
    return db, db.cursor(dictionary=True)

# ---------- Gemini API Helpers ----------
def _extract_text_from_gemini_body(body):
    """Safely extracts model-generated text from the Gemini API response."""
    try:
        candidates = body.get("candidates", [])
        if candidates:
            content = candidates[0].get("content", {})
            parts = content.get("parts", [])
            if parts:
                return parts[0].get("text")
    except Exception:
        pass
    return None


def _find_first_json_array(text):
    """Finds the first JSON array in text using regex and parses it."""
    if not isinstance(text, str):
        return None
    text = re.sub(r"```(?:json)?", "", text)  # Strip markdown fences
    match = re.search(r'\[.*\]', text, re.DOTALL)
    if not match:
        return None
    try:
        return json.loads(match.group(0))
    except json.JSONDecodeError:
        return None


def _normalize_questions(raw_items):
    """Converts model items into a standard format."""
    normalized = []
    if not isinstance(raw_items, list):
        return []

    for item in raw_items:
        if not isinstance(item, dict):
            continue
        q = item.get("question")
        opts = item.get("options")
        ans = item.get("answer")

        if not all([q, opts, ans is not None]) or len(opts) != 4:
            continue

        ans_index = -1
        if isinstance(ans, int) and 0 <= ans < 4:
            ans_index = ans
        elif isinstance(ans, str):
            ans = ans.strip().upper()
            if ans in ["A", "B", "C", "D"]:
                ans_index = ord(ans) - ord("A")

        if ans_index != -1:
            normalized.append({
                "question": str(q).strip(),
                "options": [str(o).strip() for o in opts],
                "answer": ans_index
            })
    return normalized


def _fallback_questions(topic, n):
    """Produces simple fallback questions if the API fails."""
    return [{
        "question": f"This is a sample question about {topic}.",
        "options": ["Option A", "Option B (Correct)", "Option C", "Option D"],
        "answer": 1
    } for _ in range(n)]


# ---------- Gemini API Integration ----------
def generate_quiz_questions(topic, num_questions, difficulty):
    """Calls Gemini to generate quiz questions and normalizes the response."""
    if not GEMINI_API_KEY:
        flash("API Key not configured; using fallback questions.", "danger")
        return _fallback_questions(topic, num_questions)

    url = f"https://generativelanguage.googleapis.com/v1beta/models/gemini-2.0-flash:generateContent?key={GEMINI_API_KEY}"


    prompt = (
        f"Generate exactly {num_questions} multiple-choice questions on '{topic}' for a '{difficulty}' level student. "
        "Return ONLY a valid JSON array of objects. Each object must have keys: "
        "'question', 'options' (4 strings), and 'answer' (the 0-based index of correct option)."
    )

    payload = {
        "contents": [
            {"parts": [{"text": prompt}]}
        ]
    }

    headers = {"Content-Type": "application/json"}

    try:
        resp = requests.post(url, headers=headers, json=payload, timeout=40)
        print("Status Code:", resp.status_code)
        print("Response:", resp.text)
        resp.raise_for_status()
        body = resp.json()
    except Exception as e:
        print("[Gemini Error]", e)
        return _fallback_questions(topic, num_questions)



# ---------- Routes ----------
@app.route('/')
def home():
    return render_template("home.html")


@app.route('/register', methods=["GET", "POST"])
def register():
    if request.method == "POST":
        username = request.form["username"]
        password = request.form["password"]
        confirm_password = request.form["confirm_password"]

        if password != confirm_password:
            flash("Passwords do not match!", "danger")
            return redirect(url_for("register"))

        hashed_password = bcrypt.generate_password_hash(password).decode('utf-8')
        db, cursor = get_db_connection()
        try:
            cursor.execute("INSERT INTO users (username, password) VALUES (%s, %s)", (username, hashed_password))
            db.commit()
            flash("Registration successful! Please login.", "success")
            return redirect(url_for("login"))
        except mysql.connector.IntegrityError:
            flash("Username already exists!", "danger")
        finally:
            cursor.close()
            db.close()
    return render_template("register.html")


@app.route('/login', methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form["username"]
        password = request.form["password"]
        db, cursor = get_db_connection()
        cursor.execute("SELECT * FROM users WHERE username=%s", (username,))
        user = cursor.fetchone()
        cursor.close()
        db.close()

        if user and bcrypt.check_password_hash(user['password'], password):
            session["user"] = user["username"]
            return redirect(url_for("topic_selection"))
        flash("Invalid username or password!", "danger")
    return render_template("login.html")


@app.route('/topic', methods=["GET", "POST"])
def topic_selection():
    if "user" not in session:
        return redirect(url_for("login"))

    subjects = {
        "Computer Science": ["Java", "Python", "DSA", "Operating System", "DBMS", "AI & ML"],
        "Science": ["Physics", "Chemistry", "Biology"],
        "Mathematics": ["Algebra", "Geometry", "Calculus", "Probability"],
        "History": ["World History", "Indian History", "Modern History"],
        "Literature": ["Poetry", "Novels", "Drama"],
        "Geography": ["Physical Geography", "World Geography", "Indian Geography"]
    }

    if request.method == "POST":
        session["name"] = request.form["name"].strip()
        session["skill"] = request.form["skill"]
        session["subject"] = request.form["subject"]
        session["topic"] = request.form["topic"]
        session["num_questions"] = int(request.form["num_questions"])
        return redirect(url_for("confirm_selection"))

    return render_template("topic.html", subjects=subjects)


@app.route('/confirm', methods=["GET", "POST"])
def confirm_selection():
    if "user" not in session:
        return redirect(url_for("login"))

    # Ensure session has required info
    required_keys = ["name", "skill", "topic", "num_questions"]
    if not all(session.get(k) for k in required_keys):
        flash("Please select a topic first.", "warning")
        return redirect(url_for("topic_selection"))

    if request.method == "POST":
        if request.form.get("start_quiz") == "yes":
            # Debug: print session before generation
            print("Session before quiz generation:", dict(session))

            questions = generate_quiz_questions(
                session["topic"],
                session["num_questions"],
                session["skill"]
            )

            # Debug: print generated questions
            print("Generated questions:", questions)

            # Store in session
            session["questions"] = questions
            flash(f"Quiz ready! {len(questions)} questions loaded.", "success")
            return redirect(url_for("quiz"))
        else:
            flash("Quiz cancelled. Please select topic again.", "info")
            return redirect(url_for("topic_selection"))

    return render_template(
        "confirm.html",
        name=session.get("name"),
        skill=session.get("skill"),
        subject=session.get("subject"),
        topic=session.get("topic"),
        num_questions=session.get("num_questions")
    )



@app.route('/quiz')
def quiz():
    if "user" not in session:
        return redirect(url_for("login"))

    questions = session.get("questions")
    if not questions:
        flash("No active quiz found. Please select a topic again.", "warning")
        return redirect(url_for("topic_selection"))

    return render_template(
        "quiz.html",
        questions=questions,
        name=session.get("name")
    )



@app.route('/submit_quiz', methods=["POST"])
def submit_quiz():
    if "user" not in session:
        return redirect(url_for("login"))

    questions = session.get("questions", [])
    if not questions:
        return redirect(url_for("topic_selection"))

    score = 0
    user_answers = []
    for idx, q in enumerate(questions):
        selected = request.form.get(f"answer_{idx}")
        if selected is not None and int(selected) == q["answer"]:
            score += 1
        user_answers.append(int(selected) if selected else -1)

    return render_template(
        "quiz_result.html",
        score=score,
        total=len(questions),
        questions=questions,
        user_answers=user_answers
    )


@app.route('/logout')
def logout():
    session.clear()
    flash("You have been logged out.", "info")
    return redirect(url_for("home"))

def generate_quiz_questions(topic, num_questions, difficulty):
    """Calls Gemini to generate quiz questions and normalizes the response."""
    if not GEMINI_API_KEY:
        flash("API Key not configured; using fallback questions.", "danger")
        return _fallback_questions(topic, num_questions)

    url = f"https://generativelanguage.googleapis.com/v1beta/models/gemini-2.0-flash:generateContent?key={GEMINI_API_KEY}"

    prompt = (
        f"Generate exactly {num_questions} multiple-choice questions on '{topic}' "
        f"for a '{difficulty}' level student. "
        "Return ONLY a valid JSON array of objects. "
        "Do NOT include explanations, markdown, or extra text. "
        "Each object must have keys: 'question', 'options' (4 strings), and 'answer' (0-based index)."
    )

    payload = {"contents": [{"parts": [{"text": prompt}]}]}
    headers = {"Content-Type": "application/json"}

    try:
        resp = requests.post(url, headers=headers, json=payload, timeout=40)
        resp.raise_for_status()
        body = resp.json()

        # Extract Gemini text
        candidates = body.get("candidates", [])
        if not candidates:
            flash("Gemini returned empty candidates; using fallback.", "warning")
            return _fallback_questions(topic, num_questions)

        text = candidates[0].get("content", {}).get("parts", [{}])[0].get("text", "")
        if not text:
            flash("Gemini returned empty text; using fallback.", "warning")
            return _fallback_questions(topic, num_questions)

        # Attempt to extract first JSON array using regex
        text = re.sub(r"```(?:json)?", "", text)  # remove markdown
        match = re.search(r"\[.*\]", text, re.DOTALL)
        if match:
            try:
                parsed_json = json.loads(match.group(0))
                normalized = _normalize_questions(parsed_json)
                if normalized:
                    return normalized
                else:
                    flash("Gemini returned invalid question format; using fallback.", "warning")
            except json.JSONDecodeError:
                flash("Failed to parse JSON from Gemini response; using fallback.", "warning")
        else:
            flash("No JSON array found in Gemini response; using fallback.", "warning")

    except Exception as e:
        print("[Gemini Error]", e)
        flash("Network/API error; using fallback questions.", "warning")

    # Fallback if anything fails
    return _fallback_questions(topic, num_questions)



if __name__ == "__main__":
    app.run(debug=True)
