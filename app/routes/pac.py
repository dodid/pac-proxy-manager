import base64
import re
from datetime import datetime

import httpx
from fastapi import APIRouter, Form, HTTPException, Request
from fastapi.responses import HTMLResponse, RedirectResponse, Response
from fastapi.templating import Jinja2Templates
from loguru import logger

from app.storage import (delete_access_log, get_access_log, get_pac_file,
                         log_access, save_pac_file)

router = APIRouter()

# Add templates configuration
templates = Jinja2Templates(directory="app/templates")

@router.get("/", response_class=HTMLResponse)
async def index(request: Request):
    from app.storage import load_pac_files
    pac_files = load_pac_files()

    # Transform the data to only include what's needed for rendering
    simplified_pac_files = []
    for pac in pac_files.values():
        proxied_count = len([line for line in pac['editor_content']['proxied_domains'].split('\n') if line.strip() and not line.strip().startswith(('#', '//'))])
        blocked_count = len([line for line in pac['editor_content']['blocked_domains'].split('\n') if line.strip() and not line.strip().startswith(('#', '//'))])
        bypassed_count = len([line for line in pac['editor_content']['bypassed_ips'].split('\n') if line.strip() and not line.strip().startswith(('#', '//'))])

        simplified_pac_files.append({
            'id': pac['id'],
            'name': pac['name'],
            'proxy_url': pac['proxy_url'],
            'proxied_count': proxied_count,
            'blocked_count': blocked_count,
            'bypassed_count': bypassed_count
        })

    return templates.TemplateResponse("index.html", {
        "request": request,
        "pac_files": simplified_pac_files
    })

@router.get("/create", response_class=HTMLResponse)
async def create_pac_file_form(request: Request):
    return templates.TemplateResponse("create.html", {"request": request})

@router.post("/create", response_class=HTMLResponse)
async def create_pac_file(
    request: Request,
    name: str = Form(...),
    proxy_url: str = Form(...),
    proxied_domains: str = Form(default=""),
    blocked_domains: str = Form(default=""),
    bypassed_ips: str = Form(default="")
):
    # Validate name format
    if not re.match(r'^[a-zA-Z0-9_\-]+$', name):
        return templates.TemplateResponse("create.html", {
            "request": request,
            "error": "Name can only contain letters, numbers, underscores (_), and hyphens (-)"
        })

    file_id = name.lower().replace(' ', '-').replace('/', '-')

    if get_pac_file(file_id):
        return templates.TemplateResponse("create.html", {
            "request": request,
            "error": "PAC file with this ID already exists"
        })

    # Generate PAC content
    pac_content = generate_pac_content(proxy_url, proxied_domains, blocked_domains, bypassed_ips)

    # Create new PAC file
    pac_data = {
        "id": file_id,
        "name": name,
        "content": pac_content,
        "proxy_url": proxy_url,
        "editor_content": {
            "proxied_domains": proxied_domains,
            "blocked_domains": blocked_domains,
            "bypassed_ips": bypassed_ips
        },
        "created_at": datetime.now().isoformat(),
        "updated_at": None,
        "is_active": True
    }

    save_pac_file(file_id, pac_data)
    logger.info(f"Created new PAC file: {file_id}")
    return templates.TemplateResponse("preview.html", {
        "request": request,
        "pac_file": pac_data
    })

@router.get("/{pac_id}/proxy.pac")
async def serve_pac_file(pac_id: str, request: Request):
    if not get_pac_file(pac_id):
        raise HTTPException(status_code=404, detail="PAC file not found")

    # Log the access
    client_ip = request.client.host
    log_access(pac_id, client_ip)

    return Response(content=get_pac_file(pac_id)["content"], media_type="application/x-ns-proxy-autoconfig")

@router.get("/edit/{pac_id}", response_class=HTMLResponse)
async def edit_pac_file_form(request: Request, pac_id: str):
    pac_file = get_pac_file(pac_id)
    if not pac_file:
        return templates.TemplateResponse("index.html", {
            "request": request,
            "error": "PAC file not found"
        })

    return templates.TemplateResponse("edit.html", {
        "request": request,
        "pac_file": pac_file
    })

@router.post("/edit/{pac_id}", response_class=HTMLResponse)
async def update_pac_file(
    request: Request,
    pac_id: str,
    name: str = Form(...),
    proxy_url: str = Form(...),
    proxied_domains: str = Form(default=""),
    blocked_domains: str = Form(default=""),
    bypassed_ips: str = Form(default="")
):
    # Validate name format
    if not re.match(r'^[a-zA-Z0-9_\-]+$', name):
        return templates.TemplateResponse("edit.html", {
            "request": request,
            "pac_file": get_pac_file(pac_id),
            "error": "Name can only contain letters, numbers, underscores (_), and hyphens (-)"
        })

    pac_file = get_pac_file(pac_id)
    if not pac_file:
        raise HTTPException(status_code=404, detail="PAC file not found")

    # Generate new PAC content
    pac_content = generate_pac_content(proxy_url, proxied_domains, blocked_domains, bypassed_ips)

    # Update PAC file
    updated_data = {
        **pac_file,
        "name": name,
        "content": pac_content,
        "proxy_url": proxy_url,
        "editor_content": {
            "proxied_domains": proxied_domains,
            "blocked_domains": blocked_domains,
            "bypassed_ips": bypassed_ips
        },
        "updated_at": datetime.now().isoformat()
    }

    save_pac_file(pac_id, updated_data)
    logger.info(f"Updated PAC file: {pac_id}")
    return templates.TemplateResponse("preview.html", {
        "request": request,
        "pac_file": updated_data
    })

def generate_pac_content(proxy_url, proxied_domains, blocked_domains, bypassed_ips):
    # Helper function to filter out comments, empty lines, and domains with quotes
    def filter_rules(lines):
        return [line.strip() for line in lines if line.strip() and
                not line.strip().startswith(('#', '//')) and
                '"' not in line and "'" not in line]

    # Filter and process rules
    proxied_domains = filter_rules(proxied_domains.split('\n')) if proxied_domains else []
    blocked_domains = filter_rules(blocked_domains.split('\n')) if blocked_domains else []
    bypassed_ips = filter_rules(bypassed_ips.split('\n')) if bypassed_ips else []

    # Generate optimized PAC content
    pac_content = """function FindProxyForURL(url, host) {
    // Bypass proxy for local addresses
    if (isPlainHostName(host)"""

    # Add bypass IPs if any
    if bypassed_ips:
        bypass_conditions = " ||\n        " + " ||\n        ".join(
            [f'isInNet(host, "{ip.split("/")[0]}", netmaskFromPrefix({ip.split("/")[1]}))'
             for ip in bypassed_ips]
        )
        pac_content += bypass_conditions

    pac_content += ") {\n        return \"DIRECT\";\n    }\n"

    # Add proxied domains if any
    if proxied_domains:
        # Convert shell patterns to optimized regex
        domain_patterns = [
            pattern
                .replace('.', '\\.')
                .replace('*', '[^.]*')
                .replace('?', '.')
            for pattern in proxied_domains
        ]
        domain_regex = '^(' + '|'.join(domain_patterns) + ')$'
        pac_content += f"""
    // Use proxy for specific domains
    if (/{domain_regex}/.test(host)) {{
        return "{proxy_url}";
    }}
"""

    # Add blocked domains if any
    if blocked_domains:
        # Concatenate blocked domains into a single string for faster matching
        blocked_domains_str = '|' + '|'.join(blocked_domains) + '|'
        pac_content += f"""
    // Block specific domains using substring matching
    if ("{blocked_domains_str}".indexOf('|' + host + '|') !== -1) {{
        return "PROXY 0.0.0.0; DROP";
    }}
"""

    # Add default direct connection
    pac_content += """
    // Default: direct connection
    return "DIRECT";
}

// Precomputed netmask values
const NETMASKS = [0, 128, 192, 224, 240, 248, 252, 254, 255];

function netmaskFromPrefix(prefix) {
    return [
        NETMASKS[Math.min(prefix, 8)],
        NETMASKS[Math.min(Math.max(prefix - 8, 0), 8)],
        NETMASKS[Math.min(Math.max(prefix - 16, 0), 8)],
        NETMASKS[Math.min(Math.max(prefix - 24, 0), 8)]
    ].join('.');
}"""

    return pac_content

@router.get("/log/{pac_id}", response_class=HTMLResponse)
async def view_access_log(request: Request, pac_id: str):
    pac_file = get_pac_file(pac_id)
    if not pac_file:
        raise HTTPException(status_code=404, detail="PAC file not found")

    access_log = get_access_log(pac_id)
    return templates.TemplateResponse("log.html", {
        "request": request,
        "pac_file": pac_file,
        "access_log": access_log
    })

@router.delete("/delete/{pac_id}")
async def delete_pac_file(pac_id: str):
    from app.storage import delete_pac_file
    try:
        delete_pac_file(pac_id)
        logger.info(f"Deleted PAC file: {pac_id}")
        return Response(status_code=204)
    except Exception as e:
        logger.error(f"Error deleting PAC file {pac_id}: {str(e)}")
        raise HTTPException(status_code=500, detail="Error deleting PAC file")

# Add the moved endpoints from main.py
async def fetch_gfwlist():
    mirror_urls = [
        "https://pagure.io/gfwlist/raw/master/f/gfwlist.txt",
        "http://repo.or.cz/gfwlist.git/blob_plain/HEAD:/gfwlist.txt",
        "https://bitbucket.org/gfwlist/gfwlist/raw/HEAD/gfwlist.txt",
        "https://gitlab.com/gfwlist/gfwlist/raw/master/gfwlist.txt",
        "https://git.tuxfamily.org/gfwlist/gfwlist.git/plain/gfwlist.txt",
        "https://raw.githubusercontent.com/gfwlist/gfwlist/master/gfwlist.txt"
    ]

    async with httpx.AsyncClient() as client:
        for url in mirror_urls:
            try:
                response = await client.get(url, timeout=30.0)
                response.raise_for_status()
                return response.text
            except Exception as e:
                logger.warning(f"Failed to fetch GFWList from {url}: {str(e)}")
                continue

        raise Exception("All GFWList mirrors failed")

def parse_gfwlist(content):
    """Parse GFWList content and extract domains"""
    try:
        # Decode the base64 content
        decoded = base64.b64decode(content).decode('utf-8')
        domains = set()

        for line in decoded.splitlines():
            line = line.strip()
            if line and not line.startswith(('!', '[', '@', '/')):
                # Handle ||domain.com pattern (blocks domain and all subdomains)
                if line.startswith('||'):
                    domain = line[2:].split('/')[0]  # Remove || and any path
                    domain = domain.split(':')[0]    # Remove port
                    if domain and '.' in domain:
                        domains.add(f'*.{domain}')
                        domains.add(domain)  # Include the base domain

                # Handle .domain.com pattern (blocks all subdomains)
                elif line.startswith('.'):
                    domain = line[1:].split('/')[0]  # Remove . and any path
                    domain = domain.split(':')[0]    # Remove port
                    if domain and '.' in domain:
                        domains.add(f'*.{domain}')

                # Handle |http://domain.com pattern (blocks specific URL)
                elif line.startswith('|http://') or line.startswith('|https://'):
                    domain = line.split('//')[1].split('/')[0]  # Get domain part
                    domain = domain.split(':')[0]  # Remove port
                    if domain and '.' in domain:
                        domains.add(domain)

                # Handle regular domains
                else:
                    # Remove protocol and path
                    domain = line.split('/')[0]
                    # Remove wildcard and port
                    domain = domain.lstrip('.*').split(':')[0]
                    if domain and '.' in domain:
                        domains.add(domain)

        return sorted(domains)
    except Exception as e:
        raise Exception(f"Error parsing GFWList: {str(e)}")

@router.get("/gfwlist")
async def get_gfwlist():
    try:
        # Fetch and parse GFWList
        content = await fetch_gfwlist()
        domains = parse_gfwlist(content)
        return {"domains": domains}
    except Exception as e:
        raise HTTPException(
            status_code=500,
            detail=f"Error fetching GFWList: {str(e)}"
        )

@router.get("/test/{pac_id}")
async def test_pac_url(pac_id: str, url: str):
    pac = get_pac_file(pac_id)
    if not pac:
        raise HTTPException(status_code=404, detail="PAC file not found")

    try:
        # Extract host from URL
        import ipaddress
        from urllib.parse import urlparse

        # Add http:// if no protocol is present
        if not url.startswith(('http://', 'https://')):
            url = f'http://{url}'

        parsed = urlparse(url)
        if not parsed.hostname:
            raise ValueError("Invalid URL - no hostname found")
        host = parsed.hostname

        # Check bypass rules first
        bypassed_ips = pac.get('editor_content', {}).get('bypassed_ips', '').split('\n')
        for ip_range in bypassed_ips:
            ip_range = ip_range.strip()
            if not ip_range or ip_range.startswith(('!', '#', '//')):
                continue
            try:
                # Check if host is an IP address and in bypass range
                ip = ipaddress.ip_address(host)
                if ip in ipaddress.ip_network(ip_range, strict=False):
                    return {
                        "result": "DIRECT",
                        "matched_rule": f"Bypass IP Range: {ip_range}"
                    }
            except ValueError:
                continue  # Host is not an IP address

        # Check domains
        domains = pac.get('editor_content', {}).get('proxied_domains', '').split('\n')
        for domain in domains:
            domain = domain.strip()
            if not domain or domain.startswith(('!', '#', '//')):
                continue
            domain = domain.lstrip('*.')
            if host == domain or host.endswith(f".{domain}"):
                return {
                    "result": "PROXY",
                    "proxy": pac.get('proxy_url', ''),
                    "matched_rule": f"Domain: {domain}"
                }

        # Check IP ranges
        ip_ranges = pac.get('editor_content', {}).get('proxied_ips', '').split('\n')
        for ip_range in ip_ranges:
            ip_range = ip_range.strip()
            if not ip_range or ip_range.startswith(('!', '#', '//')):
                continue
            try:
                ip = ipaddress.ip_address(host)
                if ip in ipaddress.ip_network(ip_range, strict=False):
                    return {
                        "result": "PROXY",
                        "proxy": pac.get('proxy_url', ''),
                        "matched_rule": f"IP Range: {ip_range}"
                    }
            except ValueError:
                continue  # Host is not an IP address

        return {"result": "DIRECT", "matched_rule": "No matching rules found"}

    except Exception as e:
        raise HTTPException(
            status_code=400,
            detail=f"Error testing URL: {str(e)}"
        )

@router.delete("/log/{pac_id}", response_class=HTMLResponse)
async def delete_log(pac_id: str, request: Request):
    if delete_access_log(pac_id):
        return RedirectResponse(url=f"{request.scope.get('root_path', '')}/log/{pac_id}", status_code=303)
    raise HTTPException(status_code=404, detail="Log not found")

async def fetch_easylist():
    url = "https://easylist.to/easylist/easylist.txt"
    async with httpx.AsyncClient() as client:
        try:
            response = await client.get(url, timeout=30.0)
            response.raise_for_status()
            return response.text
        except Exception as e:
            logger.error(f"Failed to fetch EasyList: {str(e)}")
            raise Exception("Failed to fetch EasyList")

def parse_easylist(content):
    """Parse EasyList content and extract domains"""
    try:
        domains = set()
        for line in content.splitlines():
            line = line.strip()
            # Only process lines that match the pattern ||domain.com^
            if line.startswith('||') and line.endswith('^'):
                domain = line[2:-1]  # Remove || and ^
                if domain and '.' in domain:
                    domains.add(domain)
        return sorted(domains)
    except Exception as e:
        raise Exception(f"Error parsing EasyList: {str(e)}")

@router.get("/easylist")
async def get_easylist():
    try:
        content = await fetch_easylist()
        domains = parse_easylist(content)
        return {"domains": domains}
    except Exception as e:
        raise HTTPException(
            status_code=500,
            detail=f"Error fetching EasyList: {str(e)}"
        )