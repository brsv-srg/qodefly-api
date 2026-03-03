import os
import secrets
import hashlib
import hmac
import base64
import json
from datetime import datetime, timedelta
from contextlib import contextmanager

import sqlite3
from fastapi import FastAPI, HTTPException, Request, Depends, Security
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import APIKeyHeader, HTTPBearer, HTTPAuthorizationCredentials
from pydantic import BaseModel, EmailStr, field_validator
from slowapi import Limiter, _rate_limit_exceeded_handler
from slowapi.util import get_remote_address
from slowapi.errors import RateLimitExceeded

# --- Configuration ---
DATABASE = "waitlist.db"
ADMIN_API_KEY = os.environ.get("ADMIN_API_KEY", "change-me-in-production")
JWT_SECRET = os.environ.get("JWT_SECRET", "change-me-jwt-secret-in-production")
JWT_ALGORITHM = "HS256"
JWT_EXPIRATION_HOURS = 72

# --- Rate Limiter ---
limiter = Limiter(key_func=get_remote_address)

# --- App ---
app = FastAPI(title="Qodefly API", version="3.0.0")
app.state.limiter = limiter
app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)

# CORS
app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        "https://qodefly.io",
        "http://qodefly.io",
        "https://api.qodefly.io",
        "https://app.qodefly.io",
        "http://localhost:3000",
    ],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


# ==================== DATABASE ====================

@contextmanager
def get_db():
    conn = sqlite3.connect(DATABASE)
    conn.row_factory = sqlite3.Row
    try:
        yield conn
    finally:
        conn.close()


def init_db():
    with get_db() as conn:
        conn.execute("""
            CREATE TABLE IF NOT EXISTS waitlist (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                email TEXT UNIQUE NOT NULL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                ip_address TEXT,
                user_agent TEXT
            )
        """)
        conn.execute("""
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                email TEXT UNIQUE NOT NULL,
                password_hash TEXT NOT NULL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                last_login TIMESTAMP,
                is_active INTEGER DEFAULT 1,
                is_beta INTEGER DEFAULT 1
            )
        """)
        conn.execute("""
            CREATE TABLE IF NOT EXISTS projects (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER NOT NULL,
                name TEXT NOT NULL,
                slug TEXT NOT NULL,
                description TEXT,
                html_code TEXT,
                status TEXT DEFAULT 'draft',
                version INTEGER DEFAULT 1,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (user_id) REFERENCES users(id)
            )
        """)
        conn.commit()


@app.on_event("startup")
async def startup_event():
    init_db()


# ==================== PASSWORD HASHING (PBKDF2) ====================

def hash_password(password: str) -> str:
    salt = secrets.token_hex(16)
    key = hashlib.pbkdf2_hmac("sha256", password.encode(), salt.encode(), 100000)
    return f"{salt}:{key.hex()}"


def verify_password(password: str, stored_hash: str) -> bool:
    try:
        salt, key_hex = stored_hash.split(":")
        key = hashlib.pbkdf2_hmac("sha256", password.encode(), salt.encode(), 100000)
        return hmac.compare_digest(key.hex(), key_hex)
    except (ValueError, AttributeError):
        return False


# ==================== JWT ====================

def _b64url_encode(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def _b64url_decode(s: str) -> bytes:
    padding = 4 - len(s) % 4
    if padding != 4:
        s += "=" * padding
    return base64.urlsafe_b64decode(s)


def create_jwt(user_id: int, email: str) -> str:
    header = _b64url_encode(json.dumps({"alg": JWT_ALGORITHM, "typ": "JWT"}).encode())
    payload_data = {
        "sub": str(user_id),
        "email": email,
        "exp": int((datetime.utcnow() + timedelta(hours=JWT_EXPIRATION_HOURS)).timestamp()),
        "iat": int(datetime.utcnow().timestamp()),
    }
    payload = _b64url_encode(json.dumps(payload_data).encode())
    signature = _b64url_encode(
        hmac.new(JWT_SECRET.encode(), f"{header}.{payload}".encode(), hashlib.sha256).digest()
    )
    return f"{header}.{payload}.{signature}"


def decode_jwt(token: str) -> dict:
    try:
        parts = token.split(".")
        if len(parts) != 3:
            raise ValueError("Invalid token")
        header, payload, signature = parts
        expected_sig = _b64url_encode(
            hmac.new(JWT_SECRET.encode(), f"{header}.{payload}".encode(), hashlib.sha256).digest()
        )
        if not hmac.compare_digest(signature, expected_sig):
            raise ValueError("Invalid signature")
        payload_data = json.loads(_b64url_decode(payload))
        if payload_data.get("exp", 0) < datetime.utcnow().timestamp():
            raise ValueError("Token expired")
        return payload_data
    except Exception:
        raise HTTPException(status_code=401, detail="Invalid or expired token")


# ==================== AUTH DEPENDENCIES ====================

api_key_header = APIKeyHeader(name="X-Admin-Key", auto_error=False)
bearer_scheme = HTTPBearer(auto_error=False)


async def verify_admin_key(api_key: str = Security(api_key_header)):
    if not api_key or api_key != ADMIN_API_KEY:
        raise HTTPException(status_code=403, detail="Invalid or missing admin API key")
    return api_key


async def get_current_user(creds: HTTPAuthorizationCredentials = Security(bearer_scheme)):
    if not creds:
        raise HTTPException(status_code=401, detail="Not authenticated")
    payload = decode_jwt(creds.credentials)
    return {"user_id": int(payload["sub"]), "email": payload["email"]}


# ==================== MODELS ====================

class EmailSubmission(BaseModel):
    email: EmailStr

class EmailResponse(BaseModel):
    message: str
    email: str

class RegisterRequest(BaseModel):
    email: EmailStr
    password: str

    @field_validator("password")
    @classmethod
    def password_min_length(cls, v):
        if len(v) < 8:
            raise ValueError("Password must be at least 8 characters")
        return v

class LoginRequest(BaseModel):
    email: EmailStr
    password: str

class AuthResponse(BaseModel):
    access_token: str
    token_type: str = "bearer"
    user: dict


class GenerateRequest(BaseModel):
    prompt: str
    project_id: int | None = None  # if iterating on existing project
    design_preferences: str | None = None

    @field_validator("prompt")
    @classmethod
    def prompt_not_empty(cls, v):
        if len(v.strip()) < 5:
            raise ValueError("Prompt must be at least 5 characters")
        return v.strip()


class SaveProjectRequest(BaseModel):
    name: str
    description: str
    html_code: str


class UpdateProjectRequest(BaseModel):
    prompt: str


# ==================== PUBLIC ROUTES ====================

@app.get("/")
async def root():
    return {
        "message": "Qodefly API",
        "version": "3.0.0",
        "endpoints": {
            "POST /auth/register": "Create account (beta)",
            "POST /auth/login": "Log in",
            "GET /auth/me": "Get current user",
            "POST /projects/generate": "Generate HTML from prompt (AI)",
            "POST /projects": "Save a project",
            "GET /projects": "List user projects",
            "GET /projects/{id}": "Get project details",
            "PUT /projects/{id}": "Iterate on project with new prompt",
            "DELETE /projects/{id}": "Delete project",
            "POST /waitlist": "Submit email to waitlist",
            "GET /health": "Health check",
        },
    }

@app.get("/health")
async def health_check():
    return {"status": "healthy", "timestamp": datetime.now().isoformat()}


# ==================== AUTH ROUTES ====================

@app.post("/auth/register", response_model=AuthResponse)
@limiter.limit("5/minute")
async def register(request: Request, body: RegisterRequest):
    """Register a new beta user"""
    try:
        password_hash = hash_password(body.password)
        with get_db() as conn:
            cursor = conn.cursor()
            cursor.execute(
                "INSERT INTO users (email, password_hash) VALUES (?, ?)",
                (body.email, password_hash),
            )
            conn.commit()
            user_id = cursor.lastrowid

        token = create_jwt(user_id, body.email)
        return AuthResponse(
            access_token=token,
            user={"id": user_id, "email": body.email, "is_beta": True},
        )
    except sqlite3.IntegrityError:
        raise HTTPException(status_code=400, detail="An account with this email already exists")
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Registration failed: {str(e)}")


@app.post("/auth/login", response_model=AuthResponse)
@limiter.limit("10/minute")
async def login(request: Request, body: LoginRequest):
    """Log in and receive a JWT token"""
    with get_db() as conn:
        row = conn.execute(
            "SELECT id, email, password_hash, is_active, is_beta FROM users WHERE email = ?",
            (body.email,),
        ).fetchone()

    if not row:
        raise HTTPException(status_code=401, detail="Invalid email or password")
    if not row["is_active"]:
        raise HTTPException(status_code=403, detail="Account is deactivated")
    if not verify_password(body.password, row["password_hash"]):
        raise HTTPException(status_code=401, detail="Invalid email or password")

    with get_db() as conn:
        conn.execute(
            "UPDATE users SET last_login = ? WHERE id = ?",
            (datetime.now().isoformat(), row["id"]),
        )
        conn.commit()

    token = create_jwt(row["id"], row["email"])
    return AuthResponse(
        access_token=token,
        user={"id": row["id"], "email": row["email"], "is_beta": bool(row["is_beta"])},
    )


@app.get("/auth/me")
async def get_me(user=Depends(get_current_user)):
    """Get current authenticated user"""
    with get_db() as conn:
        row = conn.execute(
            "SELECT id, email, created_at, is_beta FROM users WHERE id = ?",
            (user["user_id"],),
        ).fetchone()
    if not row:
        raise HTTPException(status_code=404, detail="User not found")
    return {
        "id": row["id"],
        "email": row["email"],
        "created_at": row["created_at"],
        "is_beta": bool(row["is_beta"]),
    }


# ==================== AI GENERATION (STUB) ====================

ANTHROPIC_API_KEY = os.environ.get("ANTHROPIC_API_KEY", "")


def generate_with_ai(prompt: str, existing_code: str | None = None, design_prefs: str | None = None) -> dict:
    """
    Generate HTML from prompt using Claude API.
    Currently returns a stub. Replace with real Claude API call later.
    """
    from prompts import build_system_prompt, build_user_message

    system_prompt = build_system_prompt(design_prefs)
    user_message = build_user_message(prompt, existing_code)

    if ANTHROPIC_API_KEY:
        try:
            import httpx
            response = httpx.post(
                "https://api.anthropic.com/v1/messages",
                headers={
                    "x-api-key": ANTHROPIC_API_KEY,
                    "anthropic-version": "2023-06-01",
                    "content-type": "application/json",
                },
                json={
                    "model": "claude-sonnet-4-20250514",
                    "max_tokens": 16000,
                    "system": system_prompt,
                    "messages": [{"role": "user", "content": user_message}],
                },
                timeout=120.0,
            )
            response.raise_for_status()
            data = response.json()
            html = data["content"][0]["text"]

            # Clean up if Claude wrapped in code fences
            if html.startswith("```"):
                html = html.split("\n", 1)[1]
            if html.endswith("```"):
                html = html.rsplit("```", 1)[0]
            html = html.strip()

            return {
                "html": html,
                "name": prompt[:50].strip(),
                "description": prompt,
            }
        except Exception as e:
            # Fall through to stub if API fails
            print(f"Claude API error: {e}")

    # STUB: generate a placeholder when no API key
    stub_html = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Generated by Qodefly</title>
    <script src="https://cdn.tailwindcss.com"></script>
    <link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;600;800&display=swap" rel="stylesheet">
    <style>body {{ font-family: 'Inter', sans-serif; }}</style>
</head>
<body class="min-h-screen bg-gradient-to-br from-slate-900 to-slate-800 text-white flex items-center justify-center p-8">
    <div class="max-w-2xl text-center">
        <div class="inline-block px-4 py-2 bg-indigo-500/10 border border-indigo-500/30 rounded-full text-sm text-indigo-400 mb-8">
            Generated with Qodefly AI
        </div>
        <h1 class="text-5xl font-extrabold mb-6 bg-gradient-to-r from-indigo-400 to-purple-400 bg-clip-text text-transparent">
            Your Project
        </h1>
        <p class="text-lg text-slate-400 mb-10 leading-relaxed">
            This is a preview placeholder. Connect your Anthropic API key to generate real websites from your description.
        </p>
        <div class="bg-white/5 border border-white/10 rounded-2xl p-6 text-left">
            <h3 class="text-xs uppercase text-slate-500 tracking-wider mb-2">Your prompt</h3>
            <p class="text-slate-300">{prompt}</p>
        </div>
        {('<div class="mt-4 bg-white/5 border border-white/10 rounded-2xl p-6 text-left"><h3 class="text-xs uppercase text-slate-500 tracking-wider mb-2">Design preferences</h3><p class="text-slate-300">' + (design_prefs or '') + '</p></div>') if design_prefs else ''}
    </div>
</body>
</html>"""

    return {
        "html": stub_html,
        "name": prompt[:50].strip(),
        "description": prompt,
    }


def slugify(text: str) -> str:
    """Create a URL-safe slug from text"""
    import re
    slug = text.lower().strip()
    slug = re.sub(r'[^\w\s-]', '', slug)
    slug = re.sub(r'[\s_]+', '-', slug)
    slug = re.sub(r'-+', '-', slug)
    return slug[:60].strip('-')


# ==================== PROJECT ROUTES ====================

@app.post("/projects/generate")
@limiter.limit("10/minute")
async def generate_project(request: Request, body: GenerateRequest, user=Depends(get_current_user)):
    """Generate HTML from a prompt using AI"""
    existing_code = None

    # If iterating on existing project, load current code
    if body.project_id:
        with get_db() as conn:
            row = conn.execute(
                "SELECT html_code FROM projects WHERE id = ? AND user_id = ?",
                (body.project_id, user["user_id"]),
            ).fetchone()
            if not row:
                raise HTTPException(status_code=404, detail="Project not found")
            existing_code = row["html_code"]

    result = generate_with_ai(body.prompt, existing_code, body.design_preferences)
    return result


@app.post("/projects")
@limiter.limit("10/minute")
async def create_project(request: Request, body: SaveProjectRequest, user=Depends(get_current_user)):
    """Save a generated project"""
    slug = slugify(body.name)

    with get_db() as conn:
        cursor = conn.cursor()
        cursor.execute(
            "INSERT INTO projects (user_id, name, slug, description, html_code) VALUES (?, ?, ?, ?, ?)",
            (user["user_id"], body.name, slug, body.description, body.html_code),
        )
        conn.commit()
        project_id = cursor.lastrowid

    return {
        "id": project_id,
        "name": body.name,
        "slug": slug,
        "status": "draft",
        "version": 1,
    }


@app.get("/projects")
async def list_projects(user=Depends(get_current_user)):
    """List all projects for the current user"""
    with get_db() as conn:
        rows = conn.execute(
            "SELECT id, name, slug, description, status, version, created_at, updated_at "
            "FROM projects WHERE user_id = ? ORDER BY updated_at DESC",
            (user["user_id"],),
        ).fetchall()

    return {
        "total": len(rows),
        "projects": [dict(row) for row in rows],
    }


@app.get("/projects/{project_id}")
async def get_project(project_id: int, user=Depends(get_current_user)):
    """Get a single project with its code"""
    with get_db() as conn:
        row = conn.execute(
            "SELECT id, name, slug, description, html_code, status, version, created_at, updated_at "
            "FROM projects WHERE id = ? AND user_id = ?",
            (project_id, user["user_id"]),
        ).fetchone()

    if not row:
        raise HTTPException(status_code=404, detail="Project not found")
    return dict(row)


@app.put("/projects/{project_id}")
@limiter.limit("10/minute")
async def update_project(request: Request, project_id: int, body: UpdateProjectRequest, user=Depends(get_current_user)):
    """Iterate on an existing project with a new prompt"""
    with get_db() as conn:
        row = conn.execute(
            "SELECT html_code, version FROM projects WHERE id = ? AND user_id = ?",
            (project_id, user["user_id"]),
        ).fetchone()

    if not row:
        raise HTTPException(status_code=404, detail="Project not found")

    result = generate_with_ai(body.prompt, row["html_code"], None)

    with get_db() as conn:
        conn.execute(
            "UPDATE projects SET html_code = ?, version = ?, updated_at = ? WHERE id = ? AND user_id = ?",
            (result["html"], row["version"] + 1, datetime.now().isoformat(), project_id, user["user_id"]),
        )
        conn.commit()

    return {
        "id": project_id,
        "version": row["version"] + 1,
        "html": result["html"],
    }


@app.delete("/projects/{project_id}")
async def delete_project(project_id: int, user=Depends(get_current_user)):
    """Delete a project"""
    with get_db() as conn:
        row = conn.execute(
            "SELECT id FROM projects WHERE id = ? AND user_id = ?",
            (project_id, user["user_id"]),
        ).fetchone()
        if not row:
            raise HTTPException(status_code=404, detail="Project not found")
        conn.execute("DELETE FROM projects WHERE id = ?", (project_id,))
        conn.commit()

    return {"message": "Project deleted"}


# ==================== WAITLIST ROUTES ====================

@app.post("/waitlist", response_model=EmailResponse)
@limiter.limit("5/minute")
async def add_to_waitlist(request: Request, submission: EmailSubmission):
    """Add email to waitlist"""
    try:
        client_ip = request.client.host if request.client else None
        user_agent = request.headers.get("user-agent")
        with get_db() as conn:
            conn.execute(
                "INSERT INTO waitlist (email, ip_address, user_agent) VALUES (?, ?, ?)",
                (submission.email, client_ip, user_agent),
            )
            conn.commit()
        return EmailResponse(message="Successfully added to waitlist!", email=submission.email)
    except sqlite3.IntegrityError:
        raise HTTPException(status_code=400, detail="This email is already on the waitlist")
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to add email: {str(e)}")


@app.get("/waitlist/count")
@limiter.limit("30/minute")
async def get_waitlist_count(request: Request):
    with get_db() as conn:
        result = conn.execute("SELECT COUNT(*) as count FROM waitlist").fetchone()
        return {"count": result["count"]}


# ==================== ADMIN ROUTES ====================

@app.get("/admin/waitlist")
async def get_all_emails(api_key: str = Depends(verify_admin_key)):
    with get_db() as conn:
        rows = conn.execute(
            "SELECT id, email, created_at, ip_address, user_agent FROM waitlist ORDER BY created_at DESC"
        ).fetchall()
        return {
            "total": len(rows),
            "emails": [dict(row) for row in rows],
        }


@app.get("/admin/users")
async def get_all_users(api_key: str = Depends(verify_admin_key)):
    """Get all registered users"""
    with get_db() as conn:
        rows = conn.execute(
            "SELECT id, email, created_at, last_login, is_active, is_beta FROM users ORDER BY created_at DESC"
        ).fetchall()
        return {
            "total": len(rows),
            "users": [
                {**dict(row), "is_active": bool(row["is_active"]), "is_beta": bool(row["is_beta"])}
                for row in rows
            ],
        }


@app.get("/admin/stats")
async def get_stats(api_key: str = Depends(verify_admin_key)):
    with get_db() as conn:
        today = datetime.now().strftime("%Y-%m-%d")

        wl_total = conn.execute("SELECT COUNT(*) as c FROM waitlist").fetchone()["c"]
        wl_today = conn.execute("SELECT COUNT(*) as c FROM waitlist WHERE DATE(created_at) = ?", (today,)).fetchone()["c"]
        u_total = conn.execute("SELECT COUNT(*) as c FROM users").fetchone()["c"]
        u_today = conn.execute("SELECT COUNT(*) as c FROM users WHERE DATE(created_at) = ?", (today,)).fetchone()["c"]

        wl_7d = conn.execute(
            "SELECT DATE(created_at) as day, COUNT(*) as count FROM waitlist "
            "WHERE created_at >= datetime('now', '-7 days') GROUP BY DATE(created_at) ORDER BY day DESC"
        ).fetchall()
        u_7d = conn.execute(
            "SELECT DATE(created_at) as day, COUNT(*) as count FROM users "
            "WHERE created_at >= datetime('now', '-7 days') GROUP BY DATE(created_at) ORDER BY day DESC"
        ).fetchall()

        return {
            "waitlist": {"total": wl_total, "today": wl_today, "last_7_days": [dict(r) for r in wl_7d]},
            "users": {"total": u_total, "today": u_today, "last_7_days": [dict(r) for r in u_7d]},
        }


@app.get("/admin/waitlist/export")
async def export_waitlist_csv(api_key: str = Depends(verify_admin_key)):
    from fastapi.responses import StreamingResponse
    import io, csv

    with get_db() as conn:
        rows = conn.execute("SELECT id, email, created_at, ip_address, user_agent FROM waitlist ORDER BY created_at DESC").fetchall()

    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow(["id", "email", "created_at", "ip_address", "user_agent"])
    for row in rows:
        writer.writerow([row["id"], row["email"], row["created_at"], row["ip_address"], row["user_agent"]])
    output.seek(0)

    return StreamingResponse(
        iter([output.getvalue()]),
        media_type="text/csv",
        headers={"Content-Disposition": "attachment; filename=waitlist_export.csv"},
    )


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8080)
