"""Verify the installed Codex MCP client without a model turn or saved chat.

Only allowlisted read-only calls are sent. CLI overrides are process-local;
global configuration and credentials are never opened or printed by this script.
"""

from datetime import datetime, timezone
import json
import os
from pathlib import Path
import queue
import re
import shutil
import signal
import subprocess
import sys
import threading
import time


ROOT = Path(__file__).resolve().parents[1]
OUTPUT = ROOT / "docs" / "codex-verification.json"
DISABLED_FEATURES = ("plugins", "remote_plugin", "apps", "hooks", "memories", "shell_snapshot", "code_mode_host")
ALLOWED_METHODS = {"initialize", "thread/start", "mcpServerStatus/list", "mcpServer/tool/call"}
QUERY_TOOLS = {"capabilities", "list_projects"}
HIDDEN = {"creationflags": subprocess.CREATE_NO_WINDOW} if os.name == "nt" else {"start_new_session": True}


class VerificationStopped(Exception):
    pass


def toml(value):
    if isinstance(value, dict):
        return "{" + ",".join(json.dumps(key) + "=" + toml(item) for key, item in value.items()) + "}"
    if isinstance(value, list):
        return "[" + ",".join(toml(item) for item in value) + "]"
    return json.dumps(value)


def main():
    started = time.monotonic()
    deadline = started + 40  # Reserve five seconds for finally cleanup; total <= 45s.
    process = None
    result = {
        "checked_at_utc": datetime.now(timezone.utc).isoformat(), "status": "not_verified",
        "client": "installed Codex CLI app-server", "model_turns_requested": 0,
        "configuration_scope": "process-local CLI overrides; no global configuration edits",
        "project_config_present": (ROOT / ".codex" / "config.toml").is_file(),
        "existing_chat_modified": False, "protocol_session_ephemeral": False,
        "persisted_session_path": False, "other_plugins_disabled": False,
        "requested_methods": [], "calls": {}, "cleanup_completed": False,
    }

    def remaining():
        seconds = deadline - time.monotonic()
        if seconds <= 0:
            raise VerificationStopped("deadline_exceeded")
        return seconds

    def run_checked(args):
        completed = subprocess.run(args, cwd=ROOT, capture_output=True, text=True,
                                   encoding="utf-8", errors="replace", timeout=remaining(), **HIDDEN)
        if completed.returncode:
            result["preflight_error_keywords"] = [word for word in ("parse", "unknown", "invalid", "duplicate", "required", "disabled", "string", "boolean", "table", "key", "overlap") if word in completed.stderr.lower()]
            raise VerificationStopped("client_preflight_failed")
        return completed.stdout

    try:
        codex = shutil.which("codex")
        if not codex:
            raise VerificationStopped("codex_not_found")
        version = run_checked([codex, "--version"]).strip()
        # Only a known version shape is retained; no arbitrary command output.
        if not version.startswith("codex-cli ") or len(version) > 80:
            raise VerificationStopped("unrecognized_client_version")
        result["client_version"] = version
        python = ROOT / ".venv" / ("Scripts/python.exe" if os.name == "nt" else "bin/python")
        if not python.is_file():
            raise VerificationStopped("project_python_not_found")
        # Use a dedicated empty project-local database, so even query responses
        # do not fetch the user's workbench project names or owner information.
        probe_root = ROOT / "runtime" / "codex-probe"
        probe_root.mkdir(parents=True, exist_ok=True)
        database = probe_root / ("probe-" + str(os.getpid()) + ".db")
        server_config = {
            "scopepilot": {
                "command": str(python), "args": ["-m", "scopepilot.mcp_server", "--db", str(database)],
                "cwd": str(ROOT), "env": {"PYTHONIOENCODING": "utf-8"},
                "enabled": True, "required": True, "startup_timeout_sec": 12, "tool_timeout_sec": 10,
            },
        }
        overrides = ["-c", "mcp_servers=" + toml(server_config), "-c", "analytics.enabled=false"]
        for name in DISABLED_FEATURES:
            overrides += ["-c", f"features.{name}=false"]
        # Confirm isolation BEFORE starting app-server or a protocol session.
        features = run_checked([codex, *overrides, "features", "list"])
        flags = {line.split()[0]: line.split()[-1] for line in features.splitlines() if line.split()}
        if any(flags.get(name) != "false" for name in DISABLED_FEATURES):
            raise VerificationStopped("feature_isolation_not_verified")
        result["other_plugins_disabled"] = True
        configured = json.loads(run_checked([codex, *overrides, "mcp", "list", "--json"]))
        result["preflight_inventory_type"] = type(configured).__name__
        if isinstance(configured, list):
            result["preflight_entry_count"] = len(configured)
            result["scopepilot_registered_in_probe"] = any(item.get("name") == "scopepilot" for item in configured)
            result["other_enabled_mcp_count"] = sum(item.get("name") != "scopepilot" and item.get("enabled", True) for item in configured)
            # Config tables merge across layers in this client. Disable every
            # unrelated named server in this process only, then verify again.
            # Their names/configuration are neither printed nor saved.
            for item in configured:
                if item.get("name") != "scopepilot":
                    if not re.fullmatch(r"[A-Za-z0-9_-]+", item["name"]):
                        raise VerificationStopped("unsupported_server_name_for_safe_override")
                    overrides += ["-c", "mcp_servers." + item["name"] + ".enabled=false"]
            configured = json.loads(run_checked([codex, *overrides, "mcp", "list", "--json"]))
            result["other_enabled_mcp_count"] = sum(item.get("name") != "scopepilot" and item.get("enabled", True) for item in configured)
        if not isinstance(configured, list) or not result.get("scopepilot_registered_in_probe") or result.get("other_enabled_mcp_count"):
            raise VerificationStopped("mcp_isolation_not_verified")
        result["configured_server_names"] = ["scopepilot"]
        messages = queue.Queue(maxsize=1000)
        process = subprocess.Popen(
            [codex, *overrides, "app-server", "--stdio"], cwd=ROOT,
            stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
            text=True, encoding="utf-8", errors="strict", bufsize=1, **HIDDEN,
        )

        def read_stdout():
            try:
                for line in process.stdout:
                    try:
                        message = json.loads(line)
                    except (ValueError, UnicodeError):
                        continue
                    # Discard notifications, including account-related payloads.
                    if "id" in message:
                        messages.put(message, timeout=1)
            except (ValueError, OSError, queue.Full):
                pass

        reader = threading.Thread(target=read_stdout, daemon=True)
        reader.start()
        request_id = 0

        def request(method, params):
            nonlocal request_id
            if method not in ALLOWED_METHODS:
                raise VerificationStopped("non_allowlisted_method")
            if method == "thread/start" and params.get("ephemeral") is not True:
                raise VerificationStopped("persistent_session_forbidden")
            if method == "mcpServer/tool/call" and (params.get("server") != "scopepilot" or params.get("tool") not in QUERY_TOOLS):
                raise VerificationStopped("non_query_tool_forbidden")
            request_id += 1
            result["requested_methods"].append(method)
            process.stdin.write(json.dumps({"id": request_id, "method": method, "params": params}) + "\n")
            process.stdin.flush()
            while True:
                try:
                    message = messages.get(timeout=remaining())
                except queue.Empty as exc:
                    raise VerificationStopped("protocol_deadline_exceeded") from exc
                if message.get("method"):
                    # Never approve unexpected account refresh, elicitation or
                    # command requests. Stop without printing their arguments.
                    raise VerificationStopped("unexpected_server_request")
                if message.get("id") == request_id:
                    if "error" in message:
                        result["protocol_error_code"] = message["error"].get("code")
                        raise VerificationStopped("protocol_request_rejected")
                    return message["result"]

        request("initialize", {"clientInfo": {"name": "scopepilot_mcp_verifier", "version": "1.0.0"},
                               "capabilities": {"experimentalApi": True}})
        process.stdin.write('{"method":"initialized"}\n')
        process.stdin.flush()
        started_session = request("thread/start", {"cwd": str(ROOT), "ephemeral": True,
                                                    "serviceName": "scopepilot_mcp_verifier"})
        protocol_session = started_session["thread"]
        if protocol_session.get("ephemeral") is not True or protocol_session.get("path") is not None:
            raise VerificationStopped("session_not_proven_ephemeral")
        result["protocol_session_ephemeral"] = True
        session_id = protocol_session["id"]  # Used only in memory; never saved or printed.
        inventory = request("mcpServerStatus/list", {"threadId": session_id, "serverName": "scopepilot", "detail": "toolsAndAuthOnly"})
        servers = inventory.get("data", [])
        if len(servers) != 1 or servers[0].get("name") != "scopepilot":
            raise VerificationStopped("server_discovery_failed")
        server = servers[0]
        result["runtime_status"] = server.get("runtimeStatus")
        result["tool_names"] = sorted(server.get("tools", {}).keys())
        result["server_info"] = {key: server.get("serverInfo", {}).get(key) for key in ("name", "version")}
        for tool in ("capabilities", "list_projects"):
            response = request("mcpServer/tool/call", {"threadId": session_id, "server": "scopepilot", "tool": tool, "arguments": {}})
            structured = response.get("structuredContent")
            if response.get("isError") or not isinstance(structured, dict) or structured.get("ok") is not True:
                raise VerificationStopped("query_call_failed")
            payload = structured["data"]
            if tool == "capabilities":
                result["calls"][tool] = {"ok": True, "offline": payload.get("offline"), "task_execution": payload.get("task_execution")}
            else:
                result["calls"][tool] = {"ok": True, "project_count": len(payload["projects"])}
        result["status"] = "passed"
    except (VerificationStopped, subprocess.TimeoutExpired, ValueError, KeyError, TypeError, AttributeError, OSError) as exc:
        result["stop_reason"] = str(exc) if isinstance(exc, VerificationStopped) else type(exc).__name__
    finally:
        if process is not None:
            # Terminate this exact process tree. Do not affect the desktop's
            # app-server or other Codex instances owned by the user.
            try:
                if os.name == "nt" and process.poll() is None:
                    subprocess.run([os.path.join(os.environ.get("SystemRoot", r"C:\Windows"), "System32", "taskkill.exe"),
                                    "/PID", str(process.pid), "/T", "/F"], stdout=subprocess.DEVNULL,
                                   stderr=subprocess.DEVNULL, timeout=3, **HIDDEN)
                elif process.poll() is None:
                    os.killpg(process.pid, signal.SIGTERM)
                process.wait(timeout=2)
            except (subprocess.TimeoutExpired, OSError):
                process.kill()
            result["cleanup_completed"] = process.poll() is not None
        else:
            result["cleanup_completed"] = True
        # Only delete the dedicated known database created by this invocation.
        if "database" in locals() and database.resolve().is_relative_to((ROOT / "runtime" / "codex-probe").resolve()):
            for suffix in ("", "-wal", "-shm", "-journal"):
                try:
                    Path(str(database) + suffix).unlink(missing_ok=True)
                except OSError:
                    result["cleanup_completed"] = False
        if not result["cleanup_completed"]:
            result["status"] = "not_verified"
            result["stop_reason"] = "cleanup_failed"
        result["elapsed_seconds"] = round(time.monotonic() - started, 3)
        OUTPUT.write_text(json.dumps(result, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
        print(json.dumps(result, ensure_ascii=False))
    return 0 if result["status"] == "passed" and result["cleanup_completed"] else 1


if __name__ == "__main__":
    sys.exit(main())
