from fastapi import FastAPI, Depends, HTTPException, BackgroundTasks, Query
from fastapi.security import OAuth2PasswordRequestForm
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from starlette.responses import JSONResponse
import uvicorn
from auth import (
    authenticate_user,
    create_access_token,
    create_login_otp,
    get_current_user,
    has_active_login_otp,
    rate_limit,
    register_user,
    user_exists,
    verify_login_otp,
)
from recon_engine import ReconEngine
from db import Storage
from export_utils import build_export_file, build_recon_report
from notifications import send_email
from schemas import ExportEmailIn, NewReconIn, OTPRequestIn, OTPVerifyIn, RegisterIn
from datetime import datetime
from pathlib import Path
from starlette.responses import Response

app = FastAPI(title="Unified Recon API")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

storage = Storage()
engine = ReconEngine(storage)


def _normalized_email(value: str) -> str:
    return str(value or "").strip().lower()


def _is_admin(user: dict) -> bool:
    return str(user.get("role", "")).strip().lower() == "admin"


def _visible_records_for_user(user: dict):
    records = storage.load_all()
    if _is_admin(user):
        return records
    user_email = _normalized_email(user.get("email", ""))
    return [
        record
        for record in records
        if _normalized_email(record.get("initiated_by", "")) == user_email
    ]


def _ensure_org_access(user: dict, orgname: str):
    if _is_admin(user):
        return
    org_key = storage.normalize_orgname(orgname)
    allowed = any(
        record.get("orgname") == orgname or record.get("org_key") == org_key
        for record in _visible_records_for_user(user)
    )
    if not allowed:
        raise HTTPException(status_code=403, detail="Access denied for this organization")


@app.post("/login")
async def login(form_data: OAuth2PasswordRequestForm = Depends()):
    user = authenticate_user(form_data.username, form_data.password)
    if not user:
        raise HTTPException(status_code=401, detail="Invalid credentials")
    token = create_access_token({"sub": user["email"]})
    return {"access_token": token, "token_type": "bearer"}


@app.post("/register")
async def register(payload: RegisterIn):
    try:
        user = register_user(payload.email, payload.password, payload.name)
    except ValueError as exc:
        raise HTTPException(status_code=409, detail=str(exc))
    return {"email": user["email"], "name": user["name"], "role": user["role"]}


@app.post("/login-otp/request")
async def login_otp_request(payload: OTPRequestIn):
    if not user_exists(payload.email):
        raise HTTPException(status_code=404, detail="User not found")

    otp = create_login_otp(payload.email)
    subject = "Web-Recon OTP Login Code"
    body = (
        "Your OTP code is: "
        f"{otp}\n\n"
        "This code expires in 5 minutes.\n"
        "If you did not request this code, ignore this email."
    )
    try:
        send_email(payload.email, subject, body, config_path="config.yaml")
    except ValueError as exc:
        raise HTTPException(status_code=503, detail=str(exc))
    except Exception as exc:
        raise HTTPException(status_code=500, detail=f"Failed to send OTP email: {exc}")
    return {"message": "OTP sent successfully", "expires_in_seconds": 300}


@app.post("/login-otp/verify")
async def login_otp_verify(payload: OTPVerifyIn):
    if not user_exists(payload.email):
        raise HTTPException(status_code=404, detail="User not found")
    if not has_active_login_otp(payload.email):
        raise HTTPException(status_code=400, detail="Request OTP before verification")
    if not verify_login_otp(payload.email, payload.otp):
        raise HTTPException(status_code=401, detail="Invalid or expired OTP")

    token = create_access_token({"sub": _normalized_email(payload.email)})
    return {"access_token": token, "token_type": "bearer"}


@app.post("/newrecon")
async def newrecon(payload: NewReconIn, background_tasks: BackgroundTasks, user=Depends(get_current_user)):
    rate_limit(user["email"])  # may raise HTTPException if rate-limited
    missing = engine.missing_tools(payload.scan_type)
    if missing:
        raise HTTPException(
            status_code=503,
            detail=(
                f"Required tools not found for {payload.scan_type} scan: {', '.join(missing)}. "
                "Install the tools or update Engine.path in config.yaml."
            ),
        )

    now = datetime.utcnow().isoformat() + "Z"
    org_key = storage.normalize_orgname(payload.orgname)
    record = {
        "orgname": payload.orgname,
        "org_key": org_key,
        "domains": payload.domains,
        "started_at": now,
        "status": "queued",
        "scan_type": payload.scan_type,
        "initiated_by": user["email"],
    }
    job_id = storage.append_global(record)
    # also persist initial record to per-org history
    storage.append_org(payload.orgname, dict(record, job_id=job_id))

    # write domains immediately to data/recon/{orgname}/all.txt so tools can read it
    org_path = engine.path_for_org(payload.orgname)
    (org_path / "all.txt").write_text("\n".join(payload.domains), encoding="utf-8")

    # schedule background recon
    background_tasks.add_task(
        engine.run_recon, payload.orgname, payload.domains, job_id, payload.scan_type
    )
    mode_message = (
        "Domain scan collects subdomains only."
        if payload.scan_type == "domain"
        else "Extended scan collects subdomains, open ports, and live hosts."
    )
    return {
        "job_id": job_id,
        "status": "queued",
        "scan_type": payload.scan_type,
        "mode_message": mode_message,
    }


@app.get("/allrecon")
async def allrecon(user=Depends(get_current_user)):
    return _visible_records_for_user(user)
 
 
@app.get("/subdomain")
async def get_subdomain(orgname: str, user=Depends(get_current_user)):
    _ensure_org_access(user, orgname)
    return engine.read_subdomains_with_ip(orgname)
 
 
@app.get("/openports")
async def get_openports(orgname: str, user=Depends(get_current_user)):
    _ensure_org_access(user, orgname)
    return engine.read_output_list(orgname, "naabu.txt")
 
 
@app.get("/live")
async def get_live(orgname: str, user=Depends(get_current_user)):
    _ensure_org_access(user, orgname)
    return engine.read_live_hosts_with_ip(orgname)



@app.get("/recon/{orgname}")
async def get_recon(orgname: str, user=Depends(get_current_user)):
    _ensure_org_access(user, orgname)
    return storage.load_org(orgname)


@app.get("/recon/{orgname}/download")
async def download_recon(
    orgname: str,
    format: str = Query("txt", pattern="^(txt|docx|pdf|xml)$"),
    user=Depends(get_current_user),
):
    _ensure_org_access(user, orgname)
    report = build_recon_report(orgname, storage, engine)
    try:
        content, filename, mime = build_export_file(orgname, report, format)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))
    headers = {"Content-Disposition": f'attachment; filename="{filename}"'}
    return Response(content=content, media_type=mime, headers=headers)


@app.post("/recon/{orgname}/send-email")
async def send_recon_email(orgname: str, payload: ExportEmailIn, user=Depends(get_current_user)):
    _ensure_org_access(user, orgname)
    report = build_recon_report(orgname, storage, engine)
    try:
        content, filename, mime = build_export_file(orgname, report, payload.format)
        send_email(
            payload.recipient_email,
            subject=f"Recon Report - {orgname}",
            body=(
                f"Attached is the reconnaissance report for organization: {orgname}\n"
                f"Generated by: {user['email']}\n"
                f"Format: {payload.format.upper()}"
            ),
            attachments=[(filename, content, mime)],
            config_path="config.yaml",
        )
    except ValueError as exc:
        raise HTTPException(status_code=503, detail=str(exc))
    except Exception as exc:
        raise HTTPException(status_code=500, detail=f"Email send failed: {exc}")

    return {
        "message": "Email sent successfully",
        "recipient_email": payload.recipient_email,
        "filename": filename,
    }


@app.delete("/recon/{orgname}")
async def delete_recon(orgname: str, user=Depends(get_current_user)):
    _ensure_org_access(user, orgname)
    storage.delete_org(orgname)
    storage.delete_org_from_global(orgname)
    engine.delete_org_files(orgname)
    return JSONResponse({"deleted": orgname})


ui_dir = Path(__file__).parent / "Team1ui"
if ui_dir.exists():
    app.mount("/", StaticFiles(directory=str(ui_dir), html=True), name="ui")


if __name__ == "__main__":
    uvicorn.run("app:app", host="0.0.0.0", port=8000, reload=True)
