# Web-Recon (projectfinal)

Integrated reconnaissance platform with:
- FastAPI backend + static UI served from one process
- JWT auth + Register + OTP login
- Domain scan and Extended scan modes
- History, details, report download (TXT/DOCX/PDF/XML), email send
- Optional Docker deployment

---

## 1. What is included

### Scan modes

| Mode | Output |
| --- | --- |
| `domain` | Subdomains only (`subfinder`) |
| `extended` | Subdomains + Open Ports + Live Hosts (`subfinder -> naabu -> httpx`) |

### UI pages

- `login.html` - Sign in / Register / OTP
- `index.html` - Scan dashboard
- `history.html` - History + Download + Email
- `details.html` - Detailed result view

### Important input rule

Enter domains as plain hostnames:
- ✅ `offsec.com`
- ✅ `www.offsec.com`
- ❌ `https://www.offsec.com/`

---

## 2. Local run (Linux/macOS, non-Docker)

### One-time setup

```bash
cd /path/to/projectfinal
python3 -m venv .venv
source .venv/bin/activate
python -m pip install --upgrade pip
python -m pip install -r requirements.txt
go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
go install -v github.com/projectdiscovery/naabu/v2/cmd/naabu@latest
go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest
chmod +x run_project.sh
```

### Start in one command

```bash
cd /path/to/projectfinal && source .venv/bin/activate && PATH="$HOME/go/bin:/usr/local/bin:/usr/bin:/bin:/usr/local/go/bin:$PATH" ./run_project.sh
```

Open: `http://localhost:8000/login.html`

---

## 3. Local run (Windows, non-Docker)

Use **PowerShell**.

### One-time setup

```powershell
cd C:\path\to\projectfinal
py -3 -m venv .venv
.\.venv\Scripts\python.exe -m pip install --upgrade pip
.\.venv\Scripts\python.exe -m pip install -r requirements.txt

go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
go install -v github.com/projectdiscovery/naabu/v2/cmd/naabu@latest
go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest
```

### Start in one command

```powershell
cd C:\path\to\projectfinal; $env:Path="$env:USERPROFILE\go\bin;C:\Program Files\Go\bin;$env:Path"; .\.venv\Scripts\python.exe .\app.py
```

Open: `http://localhost:8000/login.html`

---

## 4. Docker run (Windows/Linux/macOS)

### Prerequisites

- Docker Engine / Docker Desktop
- Docker Compose plugin
- Linux containers mode enabled (Docker Desktop)

### Step-by-step

1. Move to project folder:
```bash
cd /path/to/projectfinal
```

2. Stop old containers:
```bash
docker compose down --remove-orphans
```

3. Build image:
```bash
docker compose build
```

If you need a full clean rebuild, use:
```bash
docker compose build --no-cache --pull
```

4. Start container:
```bash
docker compose up -d
```

5. Check status and logs:
```bash
docker compose ps
docker compose logs --tail=100 web-recon
```

6. Verify tools inside container:
```bash
docker compose exec web-recon sh -lc "which subfinder && which naabu && which httpx"
```

7. Open UI:
`http://localhost:8000/login.html`

8. Quick health checks:
```bash
curl -fsS http://localhost:8000/login.html >/dev/null && echo "UI OK"
curl -fsS http://localhost:8000/docs >/dev/null && echo "API OK"
```

### Stop / start

```bash
docker compose down
docker compose up -d
```

### If port 8000 is busy

Edit `docker-compose.yml`:

```yaml
ports:
  - "8080:8000"
```

Then run:

```bash
docker compose down
docker compose up -d --build
```

Open: `http://localhost:8080/login.html`

---

## 5. SMTP setup (OTP + report email)

Configure `config.yaml`:

```yaml
Notifications:
  smtp:
    host: "smtp.example.com"
    port: 587
    username: "your-email@example.com"
    password: "your-password-or-app-password"
    sender: "your-email@example.com"
    use_tls: true
    use_ssl: false
```

Notes:
- Use TLS (`587`) or SSL (`465`) correctly (not both).
- Restart app after config update.

---

## 6. Essential API endpoints

- `POST /login`
- `POST /register`
- `POST /login-otp/request`
- `POST /login-otp/verify`
- `POST /newrecon`
- `GET /allrecon` (user-scoped; admin sees all)
- `GET /recon/{orgname}`
- `GET /subdomain?orgname=...` (returns subdomain + resolved IPs)
- `GET /openports?orgname=...`
- `GET /live?orgname=...` (returns live host + resolved hostname + IPs)
- `GET /recon/{orgname}/download?format=txt|docx|pdf|xml`
- `POST /recon/{orgname}/send-email`
- `DELETE /recon/{orgname}`

---

## 7. Troubleshooting (quick)

### `Required tools not found for ... scan`

Install tools and ensure `Engine.path` in `config.yaml` includes their directories.

Example:
```yaml
Engine:
  path: "/home/<user>/go/bin:/usr/local/bin:/usr/bin:/bin:/usr/local/go/bin"
```

### Scan `failed` when input was like `https://domain.com/`

Use plain domains only (no protocol/path).

### Extended scan expected ports/live, but none shown

Check selected mode:
- `domain` mode intentionally gives subdomains only.
- Use `extended` mode for ports/live.

### Docker build error `pcap.h: No such file or directory`

Use the latest files in this folder and rebuild with:
```bash
docker compose down --remove-orphans
docker builder prune -af
docker compose build --no-cache --pull
```

### Docker build error `httpx ... requires go >= 1.25.7`

This project already uses Go 1.25 in Dockerfile. Rebuild with `--no-cache --pull` to avoid stale base image layers.

### OTP or report email not sending

SMTP is not configured correctly. Verify `Notifications.smtp` values and restart.

### OTP login first attempt fails

Use this sequence:
1. Click **Request OTP** and wait for the **OTP Sent** success toast.
2. Enter the code from that email.
3. Click **Login with OTP**.

The backend now requires an active OTP session for that email before verification.

### Subdomain IPs in UI/download

`/subdomain` now returns each subdomain with all resolved IPv4/IPv6 addresses.  
The same IP mapping is included in TXT/DOCX/PDF/XML exports.

### Live host IPs in UI/download

`/live` now returns each live host with resolved hostname and all resolvable IPv4/IPv6 addresses.  
The same host-to-IP mapping is included in TXT/DOCX/PDF/XML exports.

---

## 8. Minimal project layout

```text
projectfinal/
├── app.py
├── auth.py
├── db.py
├── recon_engine.py
├── export_utils.py
├── notifications.py
├── schemas.py
├── config.yaml
├── requirements.txt
├── run_project.sh
├── Dockerfile
├── docker-compose.yml
├── Team1ui/
└── data/
```
