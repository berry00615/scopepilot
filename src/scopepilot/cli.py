import argparse

import uvicorn


def main() -> None:
    parser = argparse.ArgumentParser(description="Run the ScopePilot offline workbench")
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=8000)
    args = parser.parse_args()
    if args.host not in {"127.0.0.1", "::1", "localhost"}:
        parser.error("MVP may only bind to a loopback host")
    uvicorn.run("scopepilot.api:app", host=args.host, port=args.port, reload=False, workers=1)
