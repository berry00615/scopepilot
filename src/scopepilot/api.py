import os
import threading
from contextlib import asynccontextmanager
from pathlib import Path
from typing import Literal

from fastapi import FastAPI, File, Form, HTTPException, Request, UploadFile
from fastapi.exceptions import RequestValidationError
from pydantic import BaseModel, ConfigDict
from fastapi.responses import HTMLResponse, PlainTextResponse
from fastapi.templating import Jinja2Templates
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.middleware.trustedhost import TrustedHostMiddleware

from .db import Database
from .llm import LocalLlmGateway, LocalLlmSettings
from .schemas import IdentityCreate, PolicyCreate, ProjectCreate, ReviewCreate
from .service import ConflictError, NotFoundError, ScopePilotService, ValidationError
from .tasks import TaskManager


PACKAGE_DIR = Path(__file__).parent
DB_PATH = Path(os.environ.get("SCOPEPILOT_DB", "runtime/scopepilot.db"))
MAX_UPLOAD = int(os.environ.get("SCOPEPILOT_MAX_UPLOAD_BYTES", "5242880"))

_task_manager = None
_task_manager_lock = threading.Lock()


def tasks() -> TaskManager:
    global _task_manager
    with _task_manager_lock:
        if _task_manager is None or _task_manager.service is not service:
            if _task_manager is not None:
                _task_manager.close()
            _task_manager = TaskManager(service, Path.cwd(), os.environ.get('SCOPEPILOT_ENABLE_LOCAL_TOOLS') == '1')
        return _task_manager


@asynccontextmanager
async def lifespan(app):
    global _task_manager
    yield
    with _task_manager_lock:
        manager, _task_manager = _task_manager, None
    if manager is not None:
        manager.close()


app = FastAPI(title="ScopePilot", version="1.0.0", description="Offline authorization-aware research workbench", lifespan=lifespan,
              docs_url=None, redoc_url=None)
app.add_middleware(TrustedHostMiddleware, allowed_hosts=["127.0.0.1", "localhost", "::1", "testserver"])


class BoundedRequestBodyMiddleware:
    """Bound the complete body before multipart parsing can spool to disk."""
    def __init__(self, app, max_body: int):
        self.app, self.max_body = app, max_body

    async def __call__(self, scope, receive, send):
        if scope['type'] != 'http' or scope['method'] in {'GET', 'HEAD', 'OPTIONS'}:
            return await self.app(scope, receive, send)
        headers = dict(scope.get('headers', []))
        if b'content-length' in headers:
            try:
                length = int(headers[b'content-length'])
                if length < 0:
                    raise ValueError
            except ValueError:
                return await PlainTextResponse('无效的请求长度', status_code=400)(scope, receive, send)
            if length > self.max_body:
                return await PlainTextResponse('请求体超过允许大小', status_code=413)(scope, receive, send)
        body = bytearray()
        while True:
            message = await receive()
            if message['type'] == 'http.disconnect':
                return
            chunk = message.get('body', b'')
            if len(body) + len(chunk) > self.max_body:
                return await PlainTextResponse('请求体超过允许大小', status_code=413)(scope, receive, send)
            body.extend(chunk)
            if not message.get('more_body', False):
                break
        delivered = False

        async def replay():
            nonlocal delivered
            if not delivered:
                delivered = True
                return {'type': 'http.request', 'body': bytes(body), 'more_body': False}
            return await receive()

        await self.app(scope, replay, send)


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


app.add_middleware(BoundedRequestBodyMiddleware, max_body=MAX_UPLOAD + 65536)
app.add_middleware(LocalOriginMiddleware)
service = ScopePilotService(Database(DB_PATH))
templates = Jinja2Templates(directory=str(PACKAGE_DIR / "templates"))


@app.get('/docs', response_class=HTMLResponse, include_in_schema=False)
def offline_api_docs(request: Request):
    return templates.TemplateResponse(request, 'api_docs.html', {'schema': app.openapi()})


def local_llm_gateway() -> LocalLlmGateway:
    settings = LocalLlmSettings.from_env()
    if settings is None:
        raise ValidationError("set both SCOPEPILOT_LOCAL_LLM_URL and SCOPEPILOT_LOCAL_LLM_MODEL")
    try:
        gateway = LocalLlmGateway(settings)
        if os.environ.get('SCOPEPILOT_ENABLE_LOCAL_LLM') != '1':
            raise ValidationError('本地模型调用默认关闭，需显式启用')
        return gateway
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


@app.exception_handler(RequestValidationError)
async def invalid_input(_: Request, exc: RequestValidationError):
    # Pydantic's default payload includes the submitted value, which may be a secret.
    return PlainTextResponse('输入结构不正确，请检查必填字段、类型与长度。', status_code=422)


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
def workspace(request: Request, project_id: str, severity: str | None = None, status: str | None = None,
              source: str | None = None, category: str | None = None):
    project = service.get_project(project_id)
    all_findings = service.list_findings(project_id)
    return templates.TemplateResponse(
        request=request,
        name="workspace.html",
        context={
            "project": project,
            "artifacts": service.list_artifacts(project_id),
            "identities": service.list_identities(project_id),
            "endpoints": service.list_endpoints(project_id),
            "findings": service.list_findings(project_id, severity=severity or None, status=status or None, source=source or None, category=category or None),
            "counts": {
                "confirmed": sum(f['status'] == 'confirmed' and f['category'] == 'vulnerability' for f in all_findings),
                "pending": sum(f['status'] in {'pending_review', 'needs_evidence'} and f['category'] == 'vulnerability' for f in all_findings),
                "hardening": sum(f['category'] == 'hardening' for f in all_findings),
                "total": len(all_findings),
            },
            "filters": {"severity": severity or '', "status": status or '', "source": source or '', "category": category or ''},
            "capabilities": tasks().capabilities(),
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
def list_findings(project_id: str, severity: str | None = None, status: str | None = None,
                  source: str | None = None, category: str | None = None) -> list[dict]:
    service.get_project(project_id)
    return service.list_findings(project_id, severity=severity, status=status, source=source, category=category)


@app.get('/projects/{project_id}/findings/{finding_id}')
def finding_detail(project_id: str, finding_id: str) -> dict:
    return service.get_finding(project_id, finding_id)


@app.get('/projects/{project_id}/evidence')
def evidence(project_id: str) -> list[dict]:
    return service.list_evidence(project_id)


@app.get('/capabilities')
def capabilities() -> dict:
    return {**tasks().capabilities(), 'codex_mcp': True, 'local_model': local_llm_available()}


@app.post('/projects/{project_id}/imports/{tool}', status_code=201)
async def import_tool(project_id: str, tool: Literal['nuclei', 'gitleaks'],
                      file: UploadFile = File(...), tool_version: str = Form(...), source_root: str = Form('source')):
    try:
        content = await file.read(MAX_UPLOAD + 1)
    finally:
        await file.close()
    if len(content) > MAX_UPLOAD:
        raise HTTPException(413, '文件超过 5MiB')
    return service.import_tool_results(project_id, tool, file.filename or 'results.json', content, tool_version, source_root)


class TaskCreate(BaseModel):
    model_config = ConfigDict(extra='forbid')
    tool: Literal['nuclei', 'gitleaks', 'simulation']
    scenario: Literal['positive', 'negative', 'slow'] = 'positive'


@app.post('/projects/{project_id}/tasks', status_code=201)
def create_task(project_id: str, data: TaskCreate) -> dict:
    return tasks().start(project_id, data.tool, data.scenario)


@app.get('/projects/{project_id}/tasks')
def list_tasks(project_id: str) -> list[dict]:
    return tasks().list(project_id)


@app.get('/projects/{project_id}/tasks/{task_id}')
def get_task(project_id: str, task_id: str) -> dict:
    return tasks().get(project_id, task_id)


@app.post('/projects/{project_id}/tasks/{task_id}/cancel')
def cancel_task(project_id: str, task_id: str) -> dict:
    return tasks().cancel(project_id, task_id)


@app.post("/projects/{project_id}/findings/{finding_id}/reviews", status_code=201)
def review(project_id: str, finding_id: str, data: ReviewCreate) -> dict:
    return service.review_finding(project_id, finding_id, data)


@app.post("/projects/{project_id}/reports", response_class=PlainTextResponse)
def report(project_id: str) -> str:
    return service.report_markdown(project_id)
