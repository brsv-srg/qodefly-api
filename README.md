# Qodefly Waitlist API

Simple FastAPI backend for collecting email addresses for the qodefly.io waitlist.

## Features

- ✅ Email validation
- ✅ SQLite database storage
- ✅ CORS enabled for frontend
- ✅ Duplicate email prevention
- ✅ Admin endpoint for viewing emails
- ✅ Docker ready

## API Endpoints

### POST /waitlist
Submit email to waitlist

**Request:**
```json
{
  "email": "user@example.com"
}
```

**Response:**
```json
{
  "message": "Successfully added to waitlist!",
  "email": "user@example.com"
}
```

### GET /waitlist/count
Get total count of emails

**Response:**
```json
{
  "count": 42
}
```

### GET /admin/waitlist
Get all emails (admin only - auth to be added)

**Response:**
```json
{
  "total": 2,
  "emails": [
    {
      "id": 1,
      "email": "user@example.com",
      "created_at": "2026-02-21 20:00:00"
    }
  ]
}
```

### GET /health
Health check endpoint

## Local Development

```bash
# Install dependencies
pip install -r requirements.txt

# Run server
uvicorn main:app --reload --port 8080

# API docs available at:
# http://localhost:8080/docs
```

## Docker Deployment

```bash
# Build
docker build -t qodefly-api .

# Run
docker run -p 8080:8080 qodefly-api
```

## Coolify Deployment

1. Create new application in Coolify
2. Point to this GitHub repository
3. Build Pack: Docker
4. Port: 8080
5. Domain: api.qodefly.io
6. Deploy!

## Environment Variables

None required for basic setup. SQLite database is created automatically.

## Database

SQLite database file: `waitlist.db`

Table schema:
```sql
CREATE TABLE waitlist (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    email TEXT UNIQUE NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    ip_address TEXT,
    user_agent TEXT
);
```

## TODO

- [ ] Add authentication to admin endpoints
- [ ] Add rate limiting
- [ ] Email notifications on signup
- [ ] Export to CSV functionality
- [ ] Analytics dashboard
