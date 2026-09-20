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
