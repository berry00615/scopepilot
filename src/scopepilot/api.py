import os
from pathlib import Path

from fastapi import FastAPI, File, HTTPException, Request, UploadFile
from fastapi.responses import HTMLResponse, PlainTextResponse
from fastapi.templating import Jinja2Templates
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.middleware.trustedhost import TrustedHostMiddleware

from .db import Database
from .schemas import PolicyCreate, ProjectCreate, ReviewCreate
from .service import ConflictError, NotFoundError, ScopePilotService, ValidationError


PACKAGE_DIR = Path(__file__).parent
DB_PATH = Path(os.environ.get("SCOPEPILOT_DB", "runtime/scopepilot.db"))
MAX_UPLOAD = int(os.environ.get("SCOPEPILOT_MAX_UPLOAD_BYTES", "5242880"))

app = FastAPI(title="ScopePilot", version="0.1.0", description="Offline authorization-aware research workbench")
app.add_middleware(TrustedHostMiddleware, allowed_hosts=["127.0.0.1", "localhost", "::1", "testserver"])


class LocalOriginMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next):
        if request.method not in {"GET", "HEAD", "OPTIONS"}:
            origin = request.headers.get("origin")
            expected_origin = f"{request.url.scheme}://{request.headers.get('host', '')}"
            if origin and origin.rstrip("/") != expected_origin.rstrip("/"):
                return PlainTextResponse("cross-origin state change rejected", status_code=403)
        return await call_next(request)


app.add_middleware(LocalOriginMiddleware)
service = ScopePilotService(Database(DB_PATH))
templates = Jinja2Templates(directory=str(PACKAGE_DIR / "templates"))


@app.exception_handler(NotFoundError)
async def not_found(_: Request, exc: NotFoundError):
    return PlainTextResponse(str(exc), status_code=404)


@app.exception_handler(ConflictError)
async def conflict(_: Request, exc: ConflictError):
    return PlainTextResponse(str(exc), status_code=409)


@app.exception_handler(ValidationError)
async def invalid(_: Request, exc: ValidationError):
    return PlainTextResponse(str(exc), status_code=422)


@app.get("/health")
def health() -> dict:
    return {"status": "ok", "mode": "offline", "target_execution": False}


@app.get("/", response_class=HTMLResponse)
def home(request: Request):
    return templates.TemplateResponse(request=request, name="index.html", context={"projects": service.list_projects()})


@app.post("/projects", status_code=201)
def create_project(data: ProjectCreate) -> dict:
    return service.create_project(data)


@app.get("/projects")
def list_projects() -> list[dict]:
    return service.list_projects()


@app.get("/projects/{project_id}")
def get_project(project_id: str) -> dict:
    return service.get_project(project_id)


@app.post("/projects/{project_id}/policies", status_code=201)
def add_policy(project_id: str, policy: PolicyCreate) -> dict:
    return service.add_policy(project_id, policy)


@app.post("/projects/{project_id}/imports/har", status_code=201)
async def import_har(project_id: str, file: UploadFile = File(...)) -> dict:
    content = await file.read(MAX_UPLOAD + 1)
    await file.close()
    if len(content) > MAX_UPLOAD:
        raise HTTPException(413, f"upload exceeds {MAX_UPLOAD} bytes")
    return service.import_har(project_id, file.filename or "upload.har", content)


@app.get("/projects/{project_id}/endpoints")
def list_endpoints(project_id: str) -> list[dict]:
    service.get_project(project_id)
    return service.list_endpoints(project_id)


@app.post("/projects/{project_id}/analysis-runs", status_code=201)
def analyze(project_id: str) -> dict:
    return service.analyze(project_id)


@app.get("/projects/{project_id}/findings")
def list_findings(project_id: str) -> list[dict]:
    service.get_project(project_id)
    return service.list_findings(project_id)


@app.post("/projects/{project_id}/findings/{finding_id}/reviews", status_code=201)
def review(project_id: str, finding_id: str, data: ReviewCreate) -> dict:
    return service.review_finding(project_id, finding_id, data)


@app.post("/projects/{project_id}/reports", response_class=PlainTextResponse)
def report(project_id: str) -> str:
    return service.report_markdown(project_id)
