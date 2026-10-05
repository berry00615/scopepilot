import os
from pathlib import Path

from fastapi import FastAPI, File, HTTPException, Request, UploadFile
from fastapi.responses import HTMLResponse, PlainTextResponse
from fastapi.templating import Jinja2Templates
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.middleware.trustedhost import TrustedHostMiddleware

from .db import Database
from .llm import LocalLlmGateway, LocalLlmSettings
from .schemas import IdentityCreate, PolicyCreate, ProjectCreate, ReviewCreate
from .service import ConflictError, NotFoundError, ScopePilotService, ValidationError


PACKAGE_DIR = Path(__file__).parent
DB_PATH = Path(os.environ.get("SCOPEPILOT_DB", "runtime/scopepilot.db"))
MAX_UPLOAD = int(os.environ.get("SCOPEPILOT_MAX_UPLOAD_BYTES", "5242880"))

app = FastAPI(title="ScopePilot", version="0.2.0", description="Offline authorization-aware research workbench")
app.add_middleware(TrustedHostMiddleware, allowed_hosts=["127.0.0.1", "localhost", "::1", "testserver"])


class LocalOriginMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next):
        if request.method not in {"GET", "HEAD", "OPTIONS"}:
            origin = request.headers.get("origin")
            expected_origin = f"{request.url.scheme}://{request.headers.get('host', '')}"
            if origin and origin.rstrip("/") != expected_origin.rstrip("/"):
                return PlainTextResponse("cross-origin state change rejected", status_code=403)
        response = await call_next(request)
        response.headers["Content-Security-Policy"] = "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'; connect-src 'self'; img-src 'self' data:; object-src 'none'; base-uri 'none'; frame-ancestors 'none'; form-action 'self'"
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["Referrer-Policy"] = "no-referrer"
        response.headers["Cache-Control"] = "no-store"
        return response


app.add_middleware(LocalOriginMiddleware)
service = ScopePilotService(Database(DB_PATH))
templates = Jinja2Templates(directory=str(PACKAGE_DIR / "templates"))


def local_llm_gateway() -> LocalLlmGateway:
    settings = LocalLlmSettings.from_env()
    if settings is None:
        raise ValidationError("set both SCOPEPILOT_LOCAL_LLM_URL and SCOPEPILOT_LOCAL_LLM_MODEL")
    try:
        return LocalLlmGateway(settings)
    except ValueError as exc:
        raise ValidationError(str(exc)) from exc


def local_llm_available() -> bool:
    try:
        local_llm_gateway()
        return True
    except ValidationError:
        return False


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


@app.get("/workspace/{project_id}", response_class=HTMLResponse)
def workspace(request: Request, project_id: str):
    project = service.get_project(project_id)
    return templates.TemplateResponse(
        request=request,
        name="workspace.html",
        context={
            "project": project,
            "artifacts": service.list_artifacts(project_id),
            "identities": service.list_identities(project_id),
            "endpoints": service.list_endpoints(project_id),
            "findings": service.list_findings(project_id),
            "local_llm_configured": local_llm_available(),
        },
    )


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
    try:
        content = await file.read(MAX_UPLOAD + 1)
    finally:
        await file.close()
    if len(content) > MAX_UPLOAD:
        raise HTTPException(413, f"upload exceeds {MAX_UPLOAD} bytes")
    return service.import_har(project_id, file.filename or "upload.har", content)


@app.get("/projects/{project_id}/artifacts")
def list_artifacts(project_id: str) -> list[dict]:
    service.get_project(project_id)
    return service.list_artifacts(project_id)


@app.delete("/projects/{project_id}/artifacts/{artifact_id}")
def delete_artifact(project_id: str, artifact_id: str) -> dict:
    return service.delete_artifact(project_id, artifact_id)


@app.post("/projects/{project_id}/identities", status_code=201)
def create_identity(project_id: str, data: IdentityCreate) -> dict:
    return service.create_identity(project_id, data)


@app.get("/projects/{project_id}/identities")
def list_identities(project_id: str) -> list[dict]:
    service.get_project(project_id)
    return service.list_identities(project_id)


@app.delete("/projects/{project_id}/identities/{identity_id}")
def delete_identity(project_id: str, identity_id: str) -> dict:
    return service.delete_identity(project_id, identity_id)


@app.get("/projects/{project_id}/endpoints")
def list_endpoints(project_id: str) -> list[dict]:
    service.get_project(project_id)
    return service.list_endpoints(project_id)


@app.post("/projects/{project_id}/analysis-runs", status_code=201)
def analyze(project_id: str) -> dict:
    return service.analyze(project_id)


@app.post("/projects/{project_id}/analysis-runs/local-llm", status_code=201)
def analyze_local_llm(project_id: str) -> dict:
    return service.analyze_with_local_llm(project_id, local_llm_gateway())


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
