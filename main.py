from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, EmailStr
import sqlite3
from datetime import datetime
from contextlib import contextmanager

app = FastAPI(title="Qodefly Waitlist API", version="1.0.0")

# CORS для frontend
app.add_middleware(
    CORSMiddleware,
    allow_origins=["https://qodefly.io", "http://qodefly.io", "http://localhost:3000"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Database setup
DATABASE = "waitlist.db"

@contextmanager
def get_db():
    conn = sqlite3.connect(DATABASE)
    conn.row_factory = sqlite3.Row
    try:
        yield conn
    finally:
        conn.close()

def init_db():
    """Initialize database with waitlist table"""
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
        conn.commit()

# Initialize DB on startup
@app.on_event("startup")
async def startup_event():
    init_db()

# Models
class EmailSubmission(BaseModel):
    email: EmailStr

class EmailResponse(BaseModel):
    message: str
    email: str

# Routes
@app.get("/")
async def root():
    return {
        "message": "Qodefly Waitlist API",
        "version": "1.0.0",
        "endpoints": {
            "POST /waitlist": "Submit email to waitlist",
            "GET /waitlist/count": "Get total waitlist count",
            "GET /health": "Health check"
        }
    }

@app.post("/waitlist", response_model=EmailResponse)
async def add_to_waitlist(submission: EmailSubmission):
    """Add email to waitlist"""
    try:
        with get_db() as conn:
            cursor = conn.cursor()
            cursor.execute(
                "INSERT INTO waitlist (email) VALUES (?)",
                (submission.email,)
            )
            conn.commit()
        
        return EmailResponse(
            message="Successfully added to waitlist!",
            email=submission.email
        )
    
    except sqlite3.IntegrityError:
        raise HTTPException(
            status_code=400,
            detail="This email is already on the waitlist"
        )
    except Exception as e:
        raise HTTPException(
            status_code=500,
            detail=f"Failed to add email: {str(e)}"
        )

@app.get("/waitlist/count")
async def get_waitlist_count():
    """Get total number of emails in waitlist"""
    with get_db() as conn:
        cursor = conn.cursor()
        result = cursor.execute("SELECT COUNT(*) as count FROM waitlist").fetchone()
        return {"count": result["count"]}

@app.get("/health")
async def health_check():
    """Health check endpoint"""
    return {
        "status": "healthy",
        "timestamp": datetime.now().isoformat()
    }

# Admin endpoints (basic, no auth yet)
@app.get("/admin/waitlist")
async def get_all_emails():
    """Get all emails (for admin - should add auth later)"""
    with get_db() as conn:
        cursor = conn.cursor()
        rows = cursor.execute(
            "SELECT id, email, created_at FROM waitlist ORDER BY created_at DESC"
        ).fetchall()
        
        emails = [
            {
                "id": row["id"],
                "email": row["email"],
                "created_at": row["created_at"]
            }
            for row in rows
        ]
        
        return {
            "total": len(emails),
            "emails": emails
        }

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8080)
