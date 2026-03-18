import os
import secrets
import hashlib
import hmac
import base64
import json
from datetime import datetime, timedelta
from contextlib import contextmanager

import psycopg2
import psycopg2.extras
from fastapi import FastAPI, HTTPException, Request, Depends, Security
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import APIKeyHeader, HTTPBearer, HTTPAuthorizationCredentials
from pydantic import BaseModel, EmailStr, field_validator
from slowapi import Limiter, _rate_limit_exceeded_handler
from slowapi.util import get_remote_address
from slowapi.errors import RateLimitExceeded

# --- Configuration ---
DATABASE_URL = os.environ.get("DATABASE_URL", "postgresql://qodefly:qodefly@localhost:5432/qodefly")
UPLOADS_DIR = os.environ.get("UPLOADS_DIR", os.path.join(os.path.dirname(os.path.abspath(__file__)), "uploads"))
os.makedirs(UPLOADS_DIR, exist_ok=True)
ADMIN_API_KEY = os.environ.get("ADMIN_API_KEY", "change-me-in-production")
JWT_SECRET = os.environ.get("JWT_SECRET", "change-me-jwt-secret-in-production")
JWT_ALGORITHM = "HS256"
JWT_EXPIRATION_HOURS = 72
MAX_UPLOAD_SIZE = 10 * 1024 * 1024  # 10 MB

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
    conn = psycopg2.connect(DATABASE_URL, cursor_factory=psycopg2.extras.RealDictCursor)
    try:
        yield conn
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()


def _column_exists(cur, table: str, column: str) -> bool:
    cur.execute(
        "SELECT 1 FROM information_schema.columns WHERE table_name = %s AND column_name = %s",
        (table, column),
    )
    return cur.fetchone() is not None


def _add_column_if_missing(cur, table: str, column: str, definition: str):
    if not _column_exists(cur, table, column):
        cur.execute(f'ALTER TABLE {table} ADD COLUMN {column} {definition}')
        print(f"  migration: added {table}.{column}")


def init_db():
    with get_db() as conn:
        cur = conn.cursor()

        # --- Create tables ---
        cur.execute("""
            CREATE TABLE IF NOT EXISTS waitlist (
                id SERIAL PRIMARY KEY,
                email TEXT UNIQUE NOT NULL,
                created_at TIMESTAMP DEFAULT NOW(),
                ip_address TEXT,
                user_agent TEXT
            )
        """)
        cur.execute("""
            CREATE TABLE IF NOT EXISTS users (
                id SERIAL PRIMARY KEY,
                email TEXT UNIQUE NOT NULL,
                password_hash TEXT NOT NULL,
                created_at TIMESTAMP DEFAULT NOW(),
                last_login TIMESTAMP,
                is_active BOOLEAN DEFAULT TRUE,
                is_beta BOOLEAN DEFAULT TRUE
            )
        """)
        cur.execute("""
            CREATE TABLE IF NOT EXISTS projects (
                id SERIAL PRIMARY KEY,
                user_id INTEGER NOT NULL REFERENCES users(id),
                name TEXT NOT NULL,
                slug TEXT NOT NULL,
                description TEXT,
                html_code TEXT,
                status TEXT DEFAULT 'draft',
                version INTEGER DEFAULT 1,
                created_at TIMESTAMP DEFAULT NOW(),
                updated_at TIMESTAMP DEFAULT NOW()
            )
        """)
        cur.execute("""
            CREATE TABLE IF NOT EXISTS schema_version (
                id INTEGER PRIMARY KEY CHECK (id = 1),
                version INTEGER NOT NULL DEFAULT 0,
                updated_at TIMESTAMP DEFAULT NOW()
            )
        """)

        cur.execute("SELECT version FROM schema_version WHERE id = 1")
        row = cur.fetchone()
        if not row:
            cur.execute("INSERT INTO schema_version (id, version) VALUES (1, 0)")
            current_version = 0
        else:
            current_version = row["version"]

        # --- Migrations ---
        migrations_applied = 0

        # Migration 1: baseline — ensure all columns exist
        if current_version < 1:
            for table, columns in {
                "users": [
                    ("last_login", "TIMESTAMP"),
                    ("is_active", "BOOLEAN DEFAULT TRUE"),
                    ("is_beta", "BOOLEAN DEFAULT TRUE"),
                ],
                "projects": [
                    ("description", "TEXT"),
                    ("html_code", "TEXT"),
                    ("status", "TEXT DEFAULT 'draft'"),
                    ("version", "INTEGER DEFAULT 1"),
                    ("updated_at", "TIMESTAMP DEFAULT NOW()"),
                ],
            }.items():
                for col_name, col_def in columns:
                    _add_column_if_missing(cur, table, col_name, col_def)
            current_version = 1
            migrations_applied += 1

        # Migration 2: project context, design preferences, resources
        if current_version < 2:
            _add_column_if_missing(cur, "projects", "design_preferences", "JSONB DEFAULT '{}'")
            _add_column_if_missing(cur, "projects", "context_md", "TEXT DEFAULT ''")
            cur.execute("""
                CREATE TABLE IF NOT EXISTS project_resources (
                    id SERIAL PRIMARY KEY,
                    project_id INTEGER NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
                    user_id INTEGER NOT NULL REFERENCES users(id),
                    resource_type TEXT NOT NULL,
                    name TEXT NOT NULL,
                    description TEXT,
                    content TEXT,
                    mime_type TEXT,
                    file_size INTEGER,
                    created_at TIMESTAMP DEFAULT NOW()
                )
            """)
            current_version = 2
            migrations_applied += 1

        # --- Future migrations go here ---

        cur.execute(
            "UPDATE schema_version SET version = %s, updated_at = %s WHERE id = 1",
            (current_version, datetime.now().isoformat()),
        )
        conn.commit()
        print(f"DB ready: version={current_version}, migrations_applied={migrations_applied}")


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
    existing_code: str | None = None  # current HTML for iteration without saved project

    @field_validator("prompt")
    @classmethod
    def prompt_not_empty(cls, v):
        if len(v.strip()) < 5:
            raise ValueError("Prompt must be at least 5 characters")
        return v.strip()


class CreateProjectRequest(BaseModel):
    name: str = "Untitled Project"
    design_preferences: dict | None = None


class UpdateProjectRequest(BaseModel):
    prompt: str | None = None
    name: str | None = None
    description: str | None = None
    design_preferences: dict | None = None
    context_md: str | None = None
    html_code: str | None = None


class ResourceRequest(BaseModel):
    resource_type: str
    name: str
    description: str = ""
    content: str | None = None


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
            cur = conn.cursor()
            cur.execute(
                "INSERT INTO users (email, password_hash) VALUES (%s, %s) RETURNING id",
                (body.email, password_hash),
            )
            user_id = cur.fetchone()["id"]
            conn.commit()

        token = create_jwt(user_id, body.email)
        return AuthResponse(
            access_token=token,
            user={"id": user_id, "email": body.email, "is_beta": True},
        )
    except psycopg2.IntegrityError:
        raise HTTPException(status_code=400, detail="An account with this email already exists")
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Registration failed: {str(e)}")


@app.post("/auth/login", response_model=AuthResponse)
@limiter.limit("10/minute")
async def login(request: Request, body: LoginRequest):
    """Log in and receive a JWT token"""
    with get_db() as conn:
        cur = conn.cursor()
        cur.execute(
            "SELECT id, email, password_hash, is_active, is_beta FROM users WHERE email = %s",
            (body.email,),
        )
        row = cur.fetchone()

    if not row:
        raise HTTPException(status_code=401, detail="Invalid email or password")
    if not row["is_active"]:
        raise HTTPException(status_code=403, detail="Account is deactivated")
    if not verify_password(body.password, row["password_hash"]):
        raise HTTPException(status_code=401, detail="Invalid email or password")

    with get_db() as conn:
        cur = conn.cursor()
        cur.execute(
            "UPDATE users SET last_login = %s WHERE id = %s",
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
        cur = conn.cursor()
        cur.execute(
            "SELECT id, email, created_at, is_beta FROM users WHERE id = %s",
            (user["user_id"],),
        )
        row = cur.fetchone()
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


def _call_claude(system_prompt: str, user_message: str) -> str | None:
    """Call Claude API and return raw text response, or None on failure."""
    if not ANTHROPIC_API_KEY:
        return None
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
        if html.startswith("```"):
            html = html.split("\n", 1)[1]
        if html.endswith("```"):
            html = html.rsplit("```", 1)[0]
        return html.strip()
    except Exception as e:
        print(f"Claude API error: {e}")
        return None


def generate_with_ai_full(system_prompt: str, user_message: str) -> dict:
    """Generate HTML using pre-built system prompt and user message."""
    html = _call_claude(system_prompt, user_message)
    if html:
        return {"html": html}
    return {"html": "<p>AI generation failed. Please try again.</p>"}


def generate_with_ai(prompt: str, existing_code: str | None = None, design_prefs: str | None = None) -> dict:
    """Generate HTML from prompt using Claude API (legacy — used by POST /projects/generate)."""
    from prompts import build_system_prompt, build_user_message

    system_prompt = build_system_prompt(design_prefs)
    user_message = build_user_message(prompt, existing_code)

    html = _call_claude(system_prompt, user_message)
    if html:
        return {"html": html, "name": prompt[:50].strip(), "description": prompt}

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
    existing_code = body.existing_code or None

    # If iterating on existing project, load current code from DB
    if not existing_code and body.project_id:
        with get_db() as conn:
            cur = conn.cursor()
            cur.execute(
                "SELECT html_code FROM projects WHERE id = %s AND user_id = %s",
                (body.project_id, user["user_id"]),
            )
            row = cur.fetchone()
            if not row:
                raise HTTPException(status_code=404, detail="Project not found")
            existing_code = row["html_code"]

    result = generate_with_ai(body.prompt, existing_code, body.design_preferences)
    return result


@app.post("/projects")
@limiter.limit("10/minute")
async def create_project(request: Request, body: CreateProjectRequest, user=Depends(get_current_user)):
    """Create a new project (minimal — no HTML required)"""
    import json as _json
    slug = slugify(body.name)
    design_prefs = _json.dumps(body.design_preferences or {})

    with get_db() as conn:
        cur = conn.cursor()
        cur.execute(
            "INSERT INTO projects (user_id, name, slug, design_preferences) VALUES (%s, %s, %s, %s::jsonb) RETURNING id, name, slug, status, version, created_at",
            (user["user_id"], body.name, slug, design_prefs),
        )
        row = cur.fetchone()
        conn.commit()

    return row


@app.get("/projects")
async def list_projects(user=Depends(get_current_user)):
    """List all projects for the current user"""
    with get_db() as conn:
        cur = conn.cursor()
        cur.execute(
            "SELECT id, name, slug, description, status, version, created_at, updated_at "
            "FROM projects WHERE user_id = %s ORDER BY updated_at DESC",
            (user["user_id"],),
        )
        rows = cur.fetchall()

    return {
        "total": len(rows),
        "projects": rows,
    }


@app.get("/projects/{project_id}")
async def get_project(project_id: int, user=Depends(get_current_user)):
    """Get a single project with its code"""
    with get_db() as conn:
        cur = conn.cursor()
        cur.execute(
            "SELECT id, name, slug, description, html_code, status, version, "
            "design_preferences, context_md, created_at, updated_at "
            "FROM projects WHERE id = %s AND user_id = %s",
            (project_id, user["user_id"]),
        )
        row = cur.fetchone()

    if not row:
        raise HTTPException(status_code=404, detail="Project not found")
    return row


@app.put("/projects/{project_id}")
@limiter.limit("10/minute")
async def update_project(request: Request, project_id: int, body: UpdateProjectRequest, user=Depends(get_current_user)):
    """Update project — metadata, design, context, or AI generation (if prompt given)"""
    import json as _json
    with get_db() as conn:
        cur = conn.cursor()
        cur.execute(
            "SELECT html_code, version, design_preferences, context_md "
            "FROM projects WHERE id = %s AND user_id = %s",
            (project_id, user["user_id"]),
        )
        row = cur.fetchone()

    if not row:
        raise HTTPException(status_code=404, detail="Project not found")

    updates = {"updated_at": datetime.now().isoformat()}
    new_version = row["version"]
    new_html = row["html_code"]

    # Metadata updates
    if body.name is not None:
        updates["name"] = body.name
        updates["slug"] = slugify(body.name)
    if body.description is not None:
        updates["description"] = body.description
    if body.design_preferences is not None:
        updates["design_preferences"] = _json.dumps(body.design_preferences)
    if body.context_md is not None:
        updates["context_md"] = body.context_md
    if body.html_code is not None:
        updates["html_code"] = body.html_code

    # AI generation if prompt provided
    if body.prompt:
        from prompts import build_full_context
        # Load resources for context
        with get_db() as conn:
            cur = conn.cursor()
            cur.execute(
                "SELECT name, description, resource_type, content FROM project_resources WHERE project_id = %s",
                (project_id,),
            )
            resources = cur.fetchall()

        design_prefs = body.design_preferences or (row["design_preferences"] if isinstance(row["design_preferences"], dict) else {})
        context_md = body.context_md if body.context_md is not None else (row["context_md"] or "")

        system_prompt, user_message = build_full_context(
            prompt=body.prompt,
            existing_code=row["html_code"],
            design_prefs=design_prefs,
            context_md=context_md,
            resources=resources,
        )
        result = generate_with_ai_full(system_prompt, user_message)
        new_html = result["html"]
        new_version = row["version"] + 1
        updates["html_code"] = new_html
        updates["version"] = new_version

        # Auto-append to context_md
        summary = body.prompt[:100].strip()
        ctx = context_md or ""
        ctx += f"\nv{new_version}: {summary}"
        updates["context_md"] = ctx.strip()

    # Build SET clause
    set_parts = []
    values = []
    for k, v in updates.items():
        if k == "design_preferences":
            set_parts.append(f"{k} = %s::jsonb")
        else:
            set_parts.append(f"{k} = %s")
        values.append(v)
    values.extend([project_id, user["user_id"]])

    with get_db() as conn:
        cur = conn.cursor()
        cur.execute(
            f"UPDATE projects SET {', '.join(set_parts)} WHERE id = %s AND user_id = %s",
            values,
        )
        conn.commit()

    return {
        "id": project_id,
        "version": new_version,
        "html": new_html,
    }


@app.delete("/projects/{project_id}")
async def delete_project(project_id: int, user=Depends(get_current_user)):
    """Delete a project"""
    with get_db() as conn:
        cur = conn.cursor()
        cur.execute(
            "SELECT id FROM projects WHERE id = %s AND user_id = %s",
            (project_id, user["user_id"]),
        )
        row = cur.fetchone()
        if not row:
            raise HTTPException(status_code=404, detail="Project not found")
        cur.execute("DELETE FROM projects WHERE id = %s", (project_id,))
        conn.commit()

    return {"message": "Project deleted"}


# ==================== RESOURCE ROUTES ====================

def _verify_project_owner(project_id: int, user_id: int):
    """Check project exists and belongs to user. Returns project row or raises 404."""
    with get_db() as conn:
        cur = conn.cursor()
        cur.execute("SELECT id FROM projects WHERE id = %s AND user_id = %s", (project_id, user_id))
        row = cur.fetchone()
    if not row:
        raise HTTPException(status_code=404, detail="Project not found")
    return row


@app.get("/projects/{project_id}/resources")
async def list_resources(project_id: int, user=Depends(get_current_user)):
    """List all resources for a project"""
    _verify_project_owner(project_id, user["user_id"])
    with get_db() as conn:
        cur = conn.cursor()
        cur.execute(
            "SELECT id, resource_type, name, description, content, mime_type, file_size, created_at "
            "FROM project_resources WHERE project_id = %s ORDER BY created_at DESC",
            (project_id,),
        )
        rows = cur.fetchall()
    return {"resources": rows}


@app.post("/projects/{project_id}/resources")
@limiter.limit("20/minute")
async def add_resource(request: Request, project_id: int, user=Depends(get_current_user)):
    """Add a resource — supports JSON body or multipart file upload"""
    _verify_project_owner(project_id, user["user_id"])

    content_type = request.headers.get("content-type", "")

    if "multipart/form-data" in content_type:
        from fastapi import UploadFile
        form = await request.form()
        file = form.get("file")
        name = form.get("name", getattr(file, "filename", "upload"))
        description = form.get("description", "")
        resource_type = form.get("resource_type", "image")

        if not file or not hasattr(file, "read"):
            raise HTTPException(status_code=400, detail="No file uploaded")

        file_data = await file.read()
        if len(file_data) > MAX_UPLOAD_SIZE:
            raise HTTPException(status_code=400, detail="File too large (max 10 MB)")

        # Save to DB first to get ID
        with get_db() as conn:
            cur = conn.cursor()
            cur.execute(
                "INSERT INTO project_resources (project_id, user_id, resource_type, name, description, mime_type, file_size) "
                "VALUES (%s, %s, %s, %s, %s, %s, %s) RETURNING id",
                (project_id, user["user_id"], resource_type, name, description,
                 getattr(file, "content_type", "application/octet-stream"), len(file_data)),
            )
            resource_id = cur.fetchone()["id"]

            # Save file to disk
            project_dir = os.path.join(UPLOADS_DIR, str(project_id))
            os.makedirs(project_dir, exist_ok=True)
            safe_name = f"{resource_id}_{name}"
            filepath = os.path.join(project_dir, safe_name)
            with open(filepath, "wb") as f:
                f.write(file_data)

            # Store filename in content column
            cur.execute(
                "UPDATE project_resources SET content = %s WHERE id = %s",
                (safe_name, resource_id),
            )
            conn.commit()

        return {
            "id": resource_id,
            "resource_type": resource_type,
            "name": name,
            "description": description,
            "url": f"/uploads/{project_id}/{safe_name}",
        }
    else:
        # JSON body for text resources
        body = await request.json()
        resource_type = body.get("resource_type", "text")
        name = body.get("name", "")
        description = body.get("description", "")
        content = body.get("content", "")

        if not name:
            raise HTTPException(status_code=400, detail="Name is required")

        with get_db() as conn:
            cur = conn.cursor()
            cur.execute(
                "INSERT INTO project_resources (project_id, user_id, resource_type, name, description, content) "
                "VALUES (%s, %s, %s, %s, %s, %s) RETURNING id",
                (project_id, user["user_id"], resource_type, name, description, content),
            )
            resource_id = cur.fetchone()["id"]
            conn.commit()

        return {"id": resource_id, "resource_type": resource_type, "name": name, "description": description}


@app.delete("/projects/{project_id}/resources/{resource_id}")
async def delete_resource(project_id: int, resource_id: int, user=Depends(get_current_user)):
    """Delete a resource"""
    _verify_project_owner(project_id, user["user_id"])
    with get_db() as conn:
        cur = conn.cursor()
        cur.execute(
            "SELECT content, resource_type FROM project_resources WHERE id = %s AND project_id = %s",
            (resource_id, project_id),
        )
        row = cur.fetchone()
        if not row:
            raise HTTPException(status_code=404, detail="Resource not found")

        # Delete file from disk if it's a file resource
        if row["resource_type"] in ("image", "logo") and row["content"]:
            filepath = os.path.join(UPLOADS_DIR, str(project_id), row["content"])
            if os.path.exists(filepath):
                os.remove(filepath)

        cur.execute("DELETE FROM project_resources WHERE id = %s", (resource_id,))
        conn.commit()
    return {"message": "Resource deleted"}


# Serve uploaded files
from fastapi.responses import FileResponse

@app.get("/uploads/{project_id}/{filename}")
async def serve_upload(project_id: int, filename: str):
    """Serve uploaded resource files"""
    filepath = os.path.join(UPLOADS_DIR, str(project_id), filename)
    if not os.path.exists(filepath):
        raise HTTPException(status_code=404, detail="File not found")
    return FileResponse(filepath)


# ==================== WAITLIST ROUTES ====================

@app.post("/waitlist", response_model=EmailResponse)
@limiter.limit("5/minute")
async def add_to_waitlist(request: Request, submission: EmailSubmission):
    """Add email to waitlist"""
    try:
        client_ip = request.client.host if request.client else None
        user_agent = request.headers.get("user-agent")
        with get_db() as conn:
            cur = conn.cursor()
            cur.execute(
                "INSERT INTO waitlist (email, ip_address, user_agent) VALUES (%s, %s, %s)",
                (submission.email, client_ip, user_agent),
            )
            conn.commit()
        return EmailResponse(message="Successfully added to waitlist!", email=submission.email)
    except psycopg2.IntegrityError:
        raise HTTPException(status_code=400, detail="This email is already on the waitlist")
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to add email: {str(e)}")


@app.get("/waitlist/count")
@limiter.limit("30/minute")
async def get_waitlist_count(request: Request):
    with get_db() as conn:
        cur = conn.cursor()
        cur.execute("SELECT COUNT(*) as count FROM waitlist")
        result = cur.fetchone()
        return {"count": result["count"]}


# ==================== ADMIN ROUTES ====================

@app.get("/admin/waitlist")
async def get_all_emails(api_key: str = Depends(verify_admin_key)):
    with get_db() as conn:
        cur = conn.cursor()
        cur.execute("SELECT id, email, created_at, ip_address, user_agent FROM waitlist ORDER BY created_at DESC")
        rows = cur.fetchall()
        return {
            "total": len(rows),
            "emails": rows,
        }


@app.get("/admin/users")
async def get_all_users(api_key: str = Depends(verify_admin_key)):
    """Get all registered users"""
    with get_db() as conn:
        cur = conn.cursor()
        cur.execute("SELECT id, email, created_at, last_login, is_active, is_beta FROM users ORDER BY created_at DESC")
        rows = cur.fetchall()
        return {
            "total": len(rows),
            "users": rows,
        }


@app.get("/admin/stats")
async def get_stats(api_key: str = Depends(verify_admin_key)):
    with get_db() as conn:
        cur = conn.cursor()
        today = datetime.now().strftime("%Y-%m-%d")

        cur.execute("SELECT COUNT(*) as c FROM waitlist")
        wl_total = cur.fetchone()["c"]
        cur.execute("SELECT COUNT(*) as c FROM waitlist WHERE DATE(created_at) = %s", (today,))
        wl_today = cur.fetchone()["c"]
        cur.execute("SELECT COUNT(*) as c FROM users")
        u_total = cur.fetchone()["c"]
        cur.execute("SELECT COUNT(*) as c FROM users WHERE DATE(created_at) = %s", (today,))
        u_today = cur.fetchone()["c"]

        cur.execute(
            "SELECT DATE(created_at) as day, COUNT(*) as count FROM waitlist "
            "WHERE created_at >= NOW() - INTERVAL '7 days' GROUP BY DATE(created_at) ORDER BY day DESC"
        )
        wl_7d = cur.fetchall()
        cur.execute(
            "SELECT DATE(created_at) as day, COUNT(*) as count FROM users "
            "WHERE created_at >= NOW() - INTERVAL '7 days' GROUP BY DATE(created_at) ORDER BY day DESC"
        )
        u_7d = cur.fetchall()

        return {
            "waitlist": {"total": wl_total, "today": wl_today, "last_7_days": wl_7d},
            "users": {"total": u_total, "today": u_today, "last_7_days": u_7d},
        }


@app.get("/admin/waitlist/export")
async def export_waitlist_csv(api_key: str = Depends(verify_admin_key)):
    from fastapi.responses import StreamingResponse
    import io, csv

    with get_db() as conn:
        cur = conn.cursor()
        cur.execute("SELECT id, email, created_at, ip_address, user_agent FROM waitlist ORDER BY created_at DESC")
        rows = cur.fetchall()

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
