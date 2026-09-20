import os
import secrets
import subprocess
from typing import Iterable

from mcp.server import MCPServer
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import JSONResponse

TOKEN = os.environ.get("MCP_TOKEN")
if not TOKEN:
    raise RuntimeError("MCP_TOKEN is required")

ALLOWED_HOSTS = [x.strip() for x in os.environ.get("MCP_ALLOWED_HOSTS", "127.0.0.1:*").split(",") if x.strip()]
ALLOWED_ORIGINS = [x.strip() for x in os.environ.get("MCP_ALLOWED_ORIGINS", "http://127.0.0.1:*").split(",") if x.strip()]

mcp = MCPServer("VPS Management")

def run_command(args: Iterable[str], timeout: int = 30) -> str:
    result = subprocess.run(list(args), capture_output=True, text=True, timeout=timeout, check=False)
    output = (result.stdout + result.stderr).strip()
    if result.returncode:
        raise RuntimeError(f"command failed ({result.returncode}): {output[-4000:]}")
    return output[-12000:] or "(no output)"

class BearerAuthMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next):
        if request.url.path == "/mcp":
            header = request.headers.get("authorization", "")
            scheme, _, value = header.partition(" ")
            if scheme.lower() != "bearer" or not value or not secrets.compare_digest(value, TOKEN):
                return JSONResponse({"error": "unauthorized"}, status_code=401)
        return await call_next(request)

@mcp.tool()
def server_status() -> str:
    """Return service failure state and uptime."""
    return run_command(["bash", "-lc", "uptime; systemctl --failed --no-pager --plain"])

@mcp.tool()
def system_info() -> str:
    """Return OS, kernel, hostname and architecture."""
    return run_command(["bash", "-lc", "cat /etc/os-release; echo; uname -a; echo; hostname"])

@mcp.tool()
def disk_usage() -> str:
    """Return filesystem disk usage."""
    return run_command(["df", "-hT"])

@mcp.tool()
def memory_usage() -> str:
    """Return RAM and swap usage."""
    return run_command(["free", "-h"])

@mcp.tool()
def cpu_usage() -> str:
    """Return CPU and load information."""
    return run_command(["bash", "-lc", "nproc; echo; cat /proc/loadavg"])

@mcp.tool()
def network_info() -> str:
    """Return network interfaces and listening sockets."""
    return run_command(["bash", "-lc", "ip -brief address; echo; ss -lntup"])

@mcp.tool()
def process_list(limit: int = 30) -> str:
    """Return the busiest processes by CPU usage."""
    limit = max(1, min(limit, 100))
    return run_command(["bash", "-lc", f"ps -eo pid,user,stat,%cpu,%mem,etime,cmd --sort=-%cpu | head -n {limit + 1}"])

def validate_service(service: str) -> str:
    if not service or not service.replace("-", "").replace("_", "").replace(".", "").replace("@", "").replace(":", "").isalnum():
        raise ValueError("invalid service name")
    return service

@mcp.tool()
def service_status(service: str) -> str:
    """Return status for an exact systemd service name."""
    return run_command(["systemctl", "status", validate_service(service), "--no-pager", "--full"], timeout=20)

@mcp.tool()
def service_restart(service: str) -> str:
    """Restart an exact systemd service name."""
    return run_command(["systemctl", "restart", validate_service(service)], timeout=30)

@mcp.tool()
def recent_logs(service: str, lines: int = 100) -> str:
    """Return recent journal entries for an exact systemd service."""
    lines = max(1, min(lines, 500))
    return run_command(["journalctl", "-u", validate_service(service), "-n", str(lines), "--no-pager", "--output=short-iso"])

app = BearerAuthMiddleware(
    mcp.streamable_http_app(
        json_response=True,
        stateless_http=True,
        transport_security={
            "allowed_hosts": ALLOWED_HOSTS,
            "allowed_origins": ALLOWED_ORIGINS,
        },
    )
)
