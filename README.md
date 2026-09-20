# VPS MCP

Linux VPS management server built with the official MCP Python SDK v2 and Streamable HTTP.

## Architecture

MCP client -> HTTPS :443 -> Nginx -> 127.0.0.1:8000 -> MCP /mcp

## Tools

- server_status
- system_info
- disk_usage
- memory_usage
- cpu_usage
- network_info
- process_list
- service_status
- service_restart
- recent_logs

There is intentionally no arbitrary shell-command tool.

## Requirements

- Linux VPS with systemd
- Python 3.10+
- Nginx
- DNS hostname pointing to the VPS
- TLS certificate

## Install

    sudo apt update
    sudo apt install -y python3 python3-venv python3-pip nginx openssl curl ca-certificates certbot python3-certbot-nginx iproute2 procps
    sudo mkdir -p /opt/vps-mcp
    cd /opt/vps-mcp
    sudo python3 -m venv .venv
    sudo .venv/bin/pip install --upgrade pip
    sudo .venv/bin/pip install -r requirements.txt
    sudo .venv/bin/python -m py_compile server.py

## Token

Generate the real token on the VPS. Never commit it.

    sudo sh -c 'printf "MCP_TOKEN=%s\n" "$(openssl rand -hex 32)" > /etc/vps-mcp.env'
    sudo chmod 600 /etc/vps-mcp.env

Then set the hostname allowlists, for example:

    MCP_ALLOWED_HOSTS=mcp.example.com,mcp.example.com:443
    MCP_ALLOWED_ORIGINS=https://mcp.example.com

## systemd

    sudo cp vps-mcp.service /etc/systemd/system/vps-mcp.service
    sudo systemctl daemon-reload
    sudo systemctl enable --now vps-mcp
    sudo systemctl status vps-mcp --no-pager

Port 8000 is bound to 127.0.0.1 and should not be opened publicly.

## Nginx

Replace mcp.example.com in nginx-vps-mcp.conf with the real hostname.

    sudo cp nginx-vps-mcp.conf /etc/nginx/sites-available/vps-mcp
    sudo ln -s /etc/nginx/sites-available/vps-mcp /etc/nginx/sites-enabled/vps-mcp
    sudo nginx -t
    sudo systemctl reload nginx
    sudo certbot --nginx -d mcp.example.com
    sudo certbot renew --dry-run

The MCP endpoint is:

    https://mcp.example.com/mcp

Clients authenticate with:

    Authorization: Bearer YOUR_MCP_TOKEN

## Security

- No VPS password or real MCP token belongs in this repository.
- Port 8000 stays localhost-only.
- Service names are validated before systemd operations.
- There is no arbitrary command execution tool.
- The service currently uses root because service restart and system inspection may require privileges. Production hardening should move read-only operations to an unprivileged account and narrowly scope restart permissions.

## Verification

    sudo systemctl is-active vps-mcp
    sudo nginx -t
    sudo journalctl -u vps-mcp -n 100 --no-pager

The server code uses the current MCP Python SDK v2 API, including MCPServer and streamable_http_app().


## Cat Hero 960 서버 게시판

루트(`/`)에 게스트 기반 커뮤니티 게시판이 포함되어 있습니다.

- 로그인 없이 임시 게스트 ID + 임시 닉네임 사용
- 닉네임 1~24자
- 게시글/댓글
- JPG/PNG/WEBP 이미지 업로드, 10MB 제한
- 업로드 이미지는 서버에서 Pillow로 실제 이미지 검증 후 JPEG로 재인코딩
- 원본 파일명은 저장하지 않고 랜덤 UUID 파일명 사용
- 프론트엔드 출력은 HTML escape 처리
- 상태 변경 요청에는 Same-Origin 검사 + CSRF 토큰 적용
- 데이터 접근은 SQLAlchemy ORM의 바인드 파라미터를 사용하므로 사용자 입력을 SQL 문자열에 직접 연결하지 않음

### 데이터베이스

개발/단일 VPS 테스트는 SQLite(sqlite+aiosqlite)로 바로 시작할 수 있습니다. 실제 공개 게시판 운영은 PostgreSQL 17을 권장합니다. 동시 접속, 백업, 인덱스 관리, 장애 대응을 고려하면 SQLite보다 운영 DB로 적합합니다.

환경변수 예: DATABASE_URL=postgresql+asyncpg://USER:PASSWORD@HOST:5432/DBNAME

docker-compose.yml에는 PostgreSQL 17 + 앱 구성을 함께 넣어 두었습니다. 실제 배포 전에는 예시 비밀번호를 반드시 강한 비밀값으로 교체하고 저장소에 실제 비밀번호를 커밋하지 마세요.

### 보안 범위

SQL Injection만 막는 것으로 공개 게시판 보안이 끝나는 것은 아닙니다. 현재 기본 방어는 SQLAlchemy 파라미터 바인딩, XSS 출력 이스케이프, CSRF, Same-Origin 검사, 이미지 MIME/실제 포맷 검증, 이미지 크기 제한, 랜덤 저장명입니다.

운영 전에는 관리자 인증/삭제 기능, IP/게스트 기반 rate limit, 신고/차단, DB migration(Alembic), 이미지 저장소 분리 및 자동 백업을 추가하는 것을 권장합니다.
