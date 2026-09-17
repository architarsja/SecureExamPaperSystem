import os
import io
import bcrypt
from flask import Flask, request, jsonify, send_file, session
from flask_cors import CORS
from dotenv import load_dotenv
import psycopg2
from supabase import create_client
from security.encryption import encrypt_data, decrypt_data
from security.hashing import generate_hash
from security.otp import generate_otp, hash_otp, verify_otp, get_expiry
from security.signature import sign_data

load_dotenv()

app = Flask(__name__)

app.secret_key = os.getenv("SECRET_KEY")

app.config["SESSION_COOKIE_HTTPONLY"] = True
app.config["SESSION_COOKIE_SECURE"] = False
app.config["SESSION_COOKIE_SAMESITE"] = "Lax"
app.config["PERMANENT_SESSION_LIFETIME"] = 7200

CORS(
    app,
    origins=[
        "http://127.0.0.1:5500",
        "http://localhost:5500"
    ],
    supports_credentials=True
)

SUPABASE_URL = os.getenv("SUPABASE_URL")
SUPABASE_KEY = os.getenv("SUPABASE_KEY")
BUCKET = os.getenv("SUPABASE_BUCKET", "exam-papers")

supabase = create_client(
    SUPABASE_URL,
    SUPABASE_KEY
)

def get_db():
    return psycopg2.connect(
        os.getenv("DATABASE_URL"),
        sslmode="require"
    )

def role_required(*roles):
    if "user_id" not in session:
        return False
    return session.get("role") in roles

def audit_log(con, user_id, action, details):
    cur = con.cursor()
    cur.execute(
        """
        INSERT INTO audit_logs
        (
            user_id,
            action,
            details,
            ip_address
        )
        VALUES(%s,%s,%s,%s)
        """,
        (
            user_id,
            action,
            details,
            request.remote_addr
        )
    )
    cur.close()

@app.route("/")
def home():
    return jsonify({
        "success": True,
        "message": "Secure Exam Paper Backend Running"
    })

# =========================================================
# LOGIN
# =========================================================

@app.route("/api/login", methods=["POST"])
def login():
    data = request.json or {}

    email = data.get("email")
    password = data.get("password")

    if not email or not password:
        return jsonify({
            "success": False,
            "message": "Email and password are required"
        }), 400

    con = get_db()
    cur = con.cursor()

    cur.execute(
        """
        SELECT
            id,
            full_name,
            password_hash,
            role
        FROM users
        WHERE email=%s
        AND active=true
        """,
        (email,)
    )

    user = cur.fetchone()

    if not user:
        cur.close()
        con.close()

        return jsonify({
            "success": False,
            "message": "Invalid email or password"
        }), 401

    try:
        password_valid = bcrypt.checkpw(
            password.encode(),
            user[2].encode()
        )
    except Exception:
        password_valid = False

    if not password_valid:
        cur.close()
        con.close()

        return jsonify({
            "success": False,
            "message": "Invalid email or password"
        }), 401

    otp = generate_otp()

    cur.execute(
        """
        UPDATE otp_codes
        SET used=true
        WHERE user_id=%s
        AND used=false
        """,
        (user[0],)
    )

    cur.execute(
        """
        INSERT INTO otp_codes
        (
            user_id,
            code_hash,
            expires_at,
            used
        )
        VALUES(%s,%s,%s,false)
        """,
        (
            user[0],
            hash_otp(otp),
            get_expiry()
        )
    )

    con.commit()

    cur.close()
    con.close()

    session.clear()
    session.permanent = True

    session["pending_user_id"] = user[0]
    session["pending_name"] = user[1]
    session["pending_role"] = user[3]

    session.modified = True

    print("================================")
    print("DEMO OTP:", otp)
    print("================================")

    return jsonify({
        "success": True,
        "message": "OTP generated. Check backend terminal."
    })

# =========================================================
# OTP VERIFICATION
# =========================================================

@app.route("/api/verify-otp", methods=["POST"])
def verify():
    data = request.json or {}

    otp = data.get("otp")

    if not otp:
        return jsonify({
            "success": False,
            "message": "OTP is required"
        }), 400

    pending_user_id = session.get("pending_user_id")

    print("OTP SESSION USER ID:", pending_user_id)

    if not pending_user_id:
        return jsonify({
            "success": False,
            "message": "Login session expired. Please login again."
        }), 401

    con = get_db()
    cur = con.cursor()

    cur.execute(
        """
        SELECT
            id,
            code_hash,
            expires_at,
            used
        FROM otp_codes
        WHERE user_id=%s
        ORDER BY id DESC
        LIMIT 1
        """,
        (pending_user_id,)
    )

    otp_row = cur.fetchone()

    if not otp_row:
        cur.close()
        con.close()

        return jsonify({
            "success": False,
            "message": "OTP not found"
        }), 400

    if otp_row[3]:
        cur.close()
        con.close()

        return jsonify({
            "success": False,
            "message": "OTP has already been used"
        }), 400

    if not verify_otp(
        otp,
        otp_row[1]
    ):
        cur.close()
        con.close()

        return jsonify({
            "success": False,
            "message": "Invalid OTP"
        }), 400

    cur.execute(
        """
        SELECT NOW() > %s
        """,
        (otp_row[2],)
    )

    expired = cur.fetchone()[0]

    if expired:
        cur.close()
        con.close()

        return jsonify({
            "success": False,
            "message": "OTP has expired. Please login again."
        }), 400

    cur.execute(
        """
        UPDATE otp_codes
        SET used=true
        WHERE id=%s
        """,
        (otp_row[0],)
    )

    user_name = session.get("pending_name")
    user_role = session.get("pending_role")

    session["user_id"] = pending_user_id
    session["name"] = user_name
    session["role"] = user_role

    session.pop("pending_user_id", None)
    session.pop("pending_name", None)
    session.pop("pending_role", None)

    session.permanent = True
    session.modified = True

    audit_log(
        con,
        session["user_id"],
        "LOGIN",
        "User logged in successfully"
    )

    con.commit()

    cur.close()
    con.close()

    return jsonify({
        "success": True,
        "message": "OTP verified successfully",
        "name": session["name"],
        "role": session["role"]
    })

# =========================================================
# LOGOUT
# =========================================================

@app.route("/api/logout", methods=["GET", "POST"])
def logout():
    user_id = session.get("user_id")

    if user_id:
        con = get_db()

        audit_log(
            con,
            user_id,
            "LOGOUT",
            "User logged out"
        )

        con.commit()
        con.close()

    session.clear()

    return jsonify({
        "success": True,
        "message": "Logged out successfully"
    })

# =========================================================
# DASHBOARD
# =========================================================

@app.route("/api/dashboard")
def dashboard():
    if "user_id" not in session:
        return jsonify({
            "success": False,
            "message": "Login required"
        }), 401

    con = get_db()
    cur = con.cursor()

    cur.execute(
        """
        SELECT COUNT(*)
        FROM exam_papers
        """
    )

    total = cur.fetchone()[0]

    cur.execute(
        """
        SELECT COUNT(*)
        FROM exam_papers
        WHERE status='SCHEDULED'
        """
    )

    scheduled = cur.fetchone()[0]

    cur.execute(
        """
        SELECT COUNT(*)
        FROM exam_papers
        WHERE status='RELEASED'
        """
    )

    released = cur.fetchone()[0]

    cur.execute(
        """
        SELECT COUNT(*)
        FROM exam_papers
        WHERE review_status='PENDING'
        """
    )

    pending_review = cur.fetchone()[0]

    cur.execute(
        """
        SELECT COUNT(*)
        FROM exam_papers
        WHERE review_status='APPROVED'
        """
    )

    approved = cur.fetchone()[0]

    cur.execute(
        """
        SELECT COUNT(*)
        FROM exam_papers
        WHERE review_status='REJECTED'
        """
    )

    rejected = cur.fetchone()[0]

    cur.close()
    con.close()

    return jsonify({
        "success": True,
        "name": session.get("name"),
        "role": session.get("role"),
        "total": total,
        "scheduled": scheduled,
        "released": released,
        "pending_review": pending_review,
        "approved": approved,
        "rejected": rejected
    })

# =========================================================
# UPLOAD PAPER - QUESTION SETTER
# =========================================================

@app.route("/api/upload", methods=["POST"])
def upload():
    if not role_required("QUESTION_SETTER"):
        return jsonify({
            "success": False,
            "message": "Only Question Setter can upload papers"
        }), 403

    title = request.form.get("title")
    subject = request.form.get("subject")
    exam_date = request.form.get("exam_date")
    release_at = request.form.get("release_at")

    file = request.files.get("paper")

    if not title or not subject or not exam_date:
        return jsonify({
            "success": False,
            "message": "Title, subject and exam date are required"
        }), 400

    if not file:
        return jsonify({
            "success": False,
            "message": "PDF is required"
        }), 400

    if not file.filename.lower().endswith(".pdf"):
        return jsonify({
            "success": False,
            "message": "Only PDF files are allowed"
        }), 400

    original_data = file.read()

    if not original_data.startswith(b"%PDF"):
        return jsonify({
            "success": False,
            "message": "Invalid PDF"
        }), 400

    encrypted_data = encrypt_data(original_data)

    file_hash = generate_hash(original_data)

    signature = sign_data(original_data)

    path = "papers/" + file.filename

    try:
        supabase.storage.from_(BUCKET).upload(
            path,
            encrypted_data,
            {
                "content-type": "application/octet-stream"
            }
        )
    except Exception as e:
        return jsonify({
            "success": False,
            "message": "File upload failed",
            "error": str(e)
        }), 500

    con = get_db()
    cur = con.cursor()

    release_value = release_at if release_at else None

    cur.execute(
        """
        INSERT INTO exam_papers
        (
            title,
            subject,
            exam_date,
            release_at,
            storage_path,
            sha256,
            signature,
            status,
            review_status,
            uploaded_by
        )
        VALUES(
            %s,
            %s,
            %s,
            %s,
            %s,
            %s,
            %s,
            'SCHEDULED',
            'PENDING',
            %s
        )
        """,
        (
            title,
            subject,
            exam_date,
            release_value,
            path,
            file_hash,
            signature,
            session["user_id"]
        )
    )

    audit_log(
        con,
        session["user_id"],
        "PAPER_UPLOADED",
        f"Question paper uploaded: {title}"
    )

    con.commit()

    cur.close()
    con.close()

    return jsonify({
        "success": True,
        "message": "Question paper encrypted and submitted for review"
    })

# =========================================================
# REVIEW PAPER - REVIEWER
# =========================================================

@app.route("/api/review/<int:paper_id>", methods=["POST"])
def review_paper(paper_id):
    if not role_required("REVIEWER"):
        return jsonify({
            "success": False,
            "message": "Only Reviewer can review papers"
        }), 403

    data = request.json or {}

    decision = data.get("decision")
    reason = data.get("reason", "")

    if decision not in ["APPROVED", "REJECTED"]:
        return jsonify({
            "success": False,
            "message": "Decision must be APPROVED or REJECTED"
        }), 400

    if decision == "REJECTED" and not reason:
        return jsonify({
            "success": False,
            "message": "Rejection reason is required"
        }), 400

    con = get_db()
    cur = con.cursor()

    cur.execute(
        """
        SELECT
            id,
            title,
            review_status
        FROM exam_papers
        WHERE id=%s
        """,
        (paper_id,)
    )

    paper = cur.fetchone()

    if not paper:
        cur.close()
        con.close()

        return jsonify({
            "success": False,
            "message": "Paper not found"
        }), 404

    if paper[2] != "PENDING":
        cur.close()
        con.close()

        return jsonify({
            "success": False,
            "message": "This paper has already been reviewed"
        }), 400

    cur.execute(
        """
        UPDATE exam_papers
        SET
            review_status=%s,
            reviewed_by=%s,
            reviewed_at=NOW(),
            rejection_reason=%s
        WHERE id=%s
        """,
        (
            decision,
            session["user_id"],
            reason if decision == "REJECTED" else None,
            paper_id
        )
    )

    audit_log(
        con,
        session["user_id"],
        "PAPER_REVIEW",
        f"Paper {paper_id} - {decision}"
    )

    con.commit()

    cur.close()
    con.close()

    return jsonify({
        "success": True,
        "message": f"Paper {decision.lower()} successfully"
    })

# =========================================================
# SCHEDULE PAPER - EXAM OFFICER
# =========================================================

@app.route("/api/schedule/<int:paper_id>", methods=["POST"])
def schedule_paper(paper_id):
    if not role_required("EXAM_OFFICER"):
        return jsonify({
            "success": False,
            "message": "Only Exam Officer can schedule papers"
        }), 403

    data = request.json or {}

    release_at = data.get("release_at")

    if not release_at:
        return jsonify({
            "success": False,
            "message": "Release date and time are required"
        }), 400

    con = get_db()
    cur = con.cursor()

    cur.execute(
        """
        SELECT
            id,
            title,
            review_status
        FROM exam_papers
        WHERE id=%s
        """,
        (paper_id,)
    )

    paper = cur.fetchone()

    if not paper:
        cur.close()
        con.close()

        return jsonify({
            "success": False,
            "message": "Paper not found"
        }), 404

    if paper[2] != "APPROVED":
        cur.close()
        con.close()

        return jsonify({
            "success": False,
            "message": "Paper must be approved by Reviewer before scheduling"
        }), 400

    cur.execute(
        """
        UPDATE exam_papers
        SET
            release_at=%s,
            status='SCHEDULED'
        WHERE id=%s
        """,
        (
            release_at,
            paper_id
        )
    )

    audit_log(
        con,
        session["user_id"],
        "PAPER_SCHEDULED",
        f"Paper {paper_id} scheduled for release at {release_at}"
    )

    con.commit()

    cur.close()
    con.close()

    return jsonify({
        "success": True,
        "message": "Paper scheduled successfully"
    })

# =========================================================
# AUTOMATIC CONTROLLED RELEASE
# =========================================================

def release_scheduled_papers():
    con = get_db()
    cur = con.cursor()

    cur.execute(
        """
        UPDATE exam_papers
        SET status='RELEASED'
        WHERE status='SCHEDULED'
        AND review_status='APPROVED'
        AND release_at IS NOT NULL
        AND release_at <= NOW()
        """
    )

    released_count = cur.rowcount

    con.commit()

    cur.close()
    con.close()

    if released_count > 0:
        print(
            released_count,
            "paper(s) released automatically."
        )

# =========================================================
# VIEW PAPERS
# =========================================================

@app.route("/api/papers")
def papers():
    if "user_id" not in session:
        return jsonify({
            "success": False,
            "message": "Login required"
        }), 401

    con = get_db()
    cur = con.cursor()

    cur.execute(
        """
        SELECT
            id,
            title,
            subject,
            exam_date,
            release_at,
            status,
            review_status,
            reviewed_by,
            reviewed_at,
            rejection_reason,
            uploaded_by
        FROM exam_papers
        ORDER BY id DESC
        """
    )

    rows = cur.fetchall()

    cur.close()
    con.close()

    result = []

    for row in rows:
        result.append({
            "id": row[0],
            "title": row[1],
            "subject": row[2],
            "exam_date": str(row[3]),
            "release_at": str(row[4]) if row[4] else None,
            "status": row[5],
            "review_status": row[6],
            "reviewed_by": row[7],
            "reviewed_at": str(row[8]) if row[8] else None,
            "rejection_reason": row[9],
            "uploaded_by": row[10]
        })

    return jsonify({
        "success": True,
        "papers": result
    })

# =========================================================
# DOWNLOAD RELEASED PAPER
# =========================================================

@app.route("/api/download/<int:paper_id>")
def download(paper_id):
    if "user_id" not in session:
        return jsonify({
            "success": False,
            "message": "Login required"
        }), 401

    con = get_db()
    cur = con.cursor()

    cur.execute(
        """
        SELECT
            title,
            storage_path,
            status,
            sha256
        FROM exam_papers
        WHERE id=%s
        """,
        (paper_id,)
    )

    paper = cur.fetchone()

    if not paper:
        cur.close()
        con.close()

        return jsonify({
            "success": False,
            "message": "Paper not found"
        }), 404

    if paper[2] != "RELEASED":
        cur.close()
        con.close()

        return jsonify({
            "success": False,
            "message": "Paper is not released yet"
        }), 403

    try:
        encrypted_data = (
            supabase.storage
            .from_(BUCKET)
            .download(paper[1])
        )

        original_data = decrypt_data(
            encrypted_data
        )

    except Exception as e:
        cur.close()
        con.close()

        return jsonify({
            "success": False,
            "message": "Unable to retrieve paper",
            "error": str(e)
        }), 500

    if generate_hash(original_data) != paper[3]:
        audit_log(
            con,
            session["user_id"],
            "INTEGRITY_FAILURE",
            f"Integrity verification failed for paper {paper_id}"
        )

        con.commit()

        cur.close()
        con.close()

        return jsonify({
            "success": False,
            "message": "Integrity verification failed"
        }), 500

    audit_log(
        con,
        session["user_id"],
        "PAPER_DOWNLOADED",
        f"Paper {paper_id} downloaded"
    )

    con.commit()

    cur.close()
    con.close()

    return send_file(
        io.BytesIO(original_data),
        mimetype="application/pdf",
        as_attachment=True,
        download_name=paper[0] + ".pdf"
    )

# =========================================================
# HEALTH CHECK
# =========================================================

@app.route("/health")
def health():
    return jsonify({
        "success": True,
        "status": "healthy"
    })

# =========================================================
# START SERVER
# =========================================================

if __name__ == "__main__":
    from apscheduler.schedulers.background import BackgroundScheduler

    scheduler = BackgroundScheduler()

    scheduler.add_job(
        release_scheduled_papers,
        "interval",
        seconds=30
    )

    scheduler.start()

    app.run(
        host="0.0.0.0",
        port=5000,
        debug=True
    )