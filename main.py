"""
AURA Gateway — VLESS Proxy with Admin Panel
Complete single-file FastAPI application for Railway/Render deployment.
"""

import os
import time
import hashlib
import logging
import asyncio
import secrets
import uuid as uuid_mod
from datetime import datetime
from collections import deque
from contextlib import asynccontextmanager

import httpx
import psutil
from fastapi import FastAPI, WebSocket, WebSocketDisconnect, Request, Response, HTTPException
from fastapi.responses import HTMLResponse, StreamingResponse, JSONResponse
from starlette.requests import ClientDisconnect

# ─── Logging ──────────────────────────────────────────────────────────────────
logging.basicConfig(level=logging.WARNING, format="%(asctime)s %(levelname)s %(message)s")
logger = logging.getLogger("aura")

# ─── Constants ────────────────────────────────────────────────────────────────
RELAY_BUF = 65536
SESSION_TTL = 86400
SESSION_COOKIE = "aura_session"
ADMIN_PATH = os.environ.get("ADMIN_PATH", "panel").strip("/")
PORT = int(os.environ.get("PORT", "8000"))

# ─── Global State ─────────────────────────────────────────────────────────────
stats = {"total_bytes": 0, "total_requests": 0, "total_errors": 0, "start_time": time.time()}
error_logs: deque = deque(maxlen=50)
hourly_traffic: dict = {}
connections: dict = {}
LINKS: dict = {}
LINKS_LOCK = asyncio.Lock()
XHTTP_SESSIONS: dict = {}
XHTTP_SESSIONS_LOCK = asyncio.Lock()

# ─── Auth State ───────────────────────────────────────────────────────────────
raw_pass = os.environ.get("ADMIN_PASSWORD", "admin1234")
ADMIN_PASSWORD_HASH: str = hashlib.sha256(raw_pass.encode()).hexdigest()
SESSIONS: dict = {}
SESSIONS_LOCK = asyncio.Lock()


# ═══════════════════════════════════════════════════════════════════════════════
# بخش ۱: تشخیص دامنه
# ═══════════════════════════════════════════════════════════════════════════════
def get_domain() -> str:
    host = (
        os.environ.get("PUBLIC_HOST")
        or os.environ.get("RENDER_EXTERNAL_URL")
        or os.environ.get("RAILWAY_PUBLIC_DOMAIN")
        or "localhost"
    )
    return host.replace("https://", "").replace("http://", "").strip("/")


# ═══════════════════════════════════════════════════════════════════════════════
# بخش ۲: UUID Generation
# ═══════════════════════════════════════════════════════════════════════════════
def generate_uuid(label: str) -> str:
    h = hashlib.sha256(f"aura-{label}".encode()).digest()
    return str(uuid_mod.UUID(bytes=h[:16], version=4))


# ═══════════════════════════════════════════════════════════════════════════════
# بخش ۳: لینک‌سازی VLESS — سه Transport
# ═══════════════════════════════════════════════════════════════════════════════
def make_vless_links(uuid_str: str, domain: str, remark: str) -> list:
    ws = (
        f"vless://{uuid_str}@{domain}:443?"
        f"encryption=none&security=tls&type=ws"
        f"&host={domain}&path=/ws/{uuid_str}"
        f"&sni={domain}&fp=chrome#{remark}-WS"
    )
    xhttp = (
        f"vless://{uuid_str}@{domain}:443?"
        f"encryption=none&security=tls&type=xhttp"
        f"&host={domain}&path=/xhttp/{uuid_str}"
        f"&sni={domain}&fp=chrome&alpn=h2&mode=auto#{remark}-XHTTP"
    )
    grpc = (
        f"vless://{uuid_str}@{domain}:443?"
        f"encryption=none&security=tls&type=grpc"
        f"&host={domain}&serviceName=grpc/{uuid_str}"
        f"&sni={domain}&fp=chrome#{remark}-gRPC"
    )
    return [ws, xhttp, grpc]


# ═══════════════════════════════════════════════════════════════════════════════
# بخش ۴: parse_vless_header
# ═══════════════════════════════════════════════════════════════════════════════
async def parse_vless_header(data: bytes):
    if len(data) < 24:
        raise ValueError("VLESS header too short")
    pos = 0
    pos += 1          # version
    pos += 16         # uuid
    addon_len = data[pos]; pos += 1
    pos += addon_len  # addon
    command = data[pos]; pos += 1
    port = int.from_bytes(data[pos:pos + 2], "big"); pos += 2
    addr_type = data[pos]; pos += 1
    if addr_type == 1:      # IPv4
        address = ".".join(str(b) for b in data[pos:pos + 4]); pos += 4
    elif addr_type == 2:    # domain
        dlen = data[pos]; pos += 1
        address = data[pos:pos + dlen].decode("utf-8", errors="ignore"); pos += dlen
    elif addr_type == 3:    # IPv6
        raw = data[pos:pos + 16]; pos += 16
        address = ":".join(f"{raw[i]:02x}{raw[i + 1]:02x}" for i in range(0, 16, 2))
    else:
        raise ValueError(f"Unknown addr_type: {addr_type}")
    return command, address, port, data[pos:]


# ═══════════════════════════════════════════════════════════════════════════════
# بخش ۷: helper های مشترک — آمار ترافیک
# ═══════════════════════════════════════════════════════════════════════════════
def _record_traffic(uuid_str: str, n: int):
    stats["total_bytes"] += n
    key = datetime.now().strftime("%H:00")
    hourly_traffic[key] = hourly_traffic.get(key, 0) + n
    if len(hourly_traffic) > 24:
        oldest = sorted(hourly_traffic.keys())[0]
        del hourly_traffic[oldest]
    if uuid_str in LINKS:
        LINKS[uuid_str]["used_bytes"] += n


# ═══════════════════════════════════════════════════════════════════════════════
# بخش ۸: مدیریت کاربران — quota check
# ═══════════════════════════════════════════════════════════════════════════════
async def check_quota(uuid_str: str, extra: int) -> bool:
    async with LINKS_LOCK:
        link = LINKS.get(uuid_str)
        if not link or not link["active"]:
            return False
        if link["limit_bytes"] > 0 and (link["used_bytes"] + extra) > link["limit_bytes"]:
            return False
        if link["max_connections"] > 0:
            active = sum(1 for c in connections.values() if c.get("uuid") == uuid_str)
            if active >= link["max_connections"]:
                return False
        return True


# ═══════════════════════════════════════════════════════════════════════════════
# بخش ۹: احراز هویت پنل
# ═══════════════════════════════════════════════════════════════════════════════
def _verify_token(token: str) -> bool:
    if not token:
        return False
    expire = SESSIONS.get(token, 0)
    if expire < time.time():
        SESSIONS.pop(token, None)
        return False
    return True


async def _require_auth(request: Request) -> bool:
    token = request.cookies.get(SESSION_COOKIE) or ""
    if not token:
        auth_header = request.headers.get("Authorization", "")
        if auth_header.startswith("Bearer "):
            token = auth_header[7:]
    if not _verify_token(token):
        return False
    async with SESSIONS_LOCK:
        if token in SESSIONS:
            SESSIONS[token] = time.time() + SESSION_TTL
    return True


# ═══════════════════════════════════════════════════════════════════════════════
# FastAPI App + Lifespan
# ═══════════════════════════════════════════════════════════════════════════════
@asynccontextmanager
async def lifespan(app_instance: FastAPI):
    uid = os.environ.get("DEFAULT_UUID") or generate_uuid("default")
    async with LINKS_LOCK:
        if not LINKS:
            LINKS[uid] = {
                "label": "Default",
                "limit_bytes": 0,
                "used_bytes": 0,
                "max_connections": 0,
                "active": True,
                "created_at": datetime.now().isoformat(),
            }
    asyncio.create_task(keep_alive_worker())
    yield
    for session_id in list(XHTTP_SESSIONS.keys()):
        session = XHTTP_SESSIONS.get(session_id)
        if session:
            session.closed = True
            await session.to_client.put(None)
    XHTTP_SESSIONS.clear()
    connections.clear()


app = FastAPI(docs_url=None, redoc_url=None, lifespan=lifespan)


# ─── Global Exception Handlers ────────────────────────────────────────────────
@app.exception_handler(ClientDisconnect)
async def client_disconnect_handler(request: Request, exc: ClientDisconnect):
    return Response(status_code=499)


# ═══════════════════════════════════════════════════════════════════════════════
# Health Check
# ═══════════════════════════════════════════════════════════════════════════════
@app.get("/")
async def root():
    return {"status": "ok"}


@app.get("/health")
async def health():
    return {"status": "ok", "connections": len(connections)}


# ═══════════════════════════════════════════════════════════════════════════════
# بخش ۴: WebSocket Transport
# ═══════════════════════════════════════════════════════════════════════════════
@app.websocket("/ws/{uuid}")
async def ws_proxy(websocket: WebSocket, uuid: str):
    stats["total_requests"] += 1
    conn_id = ""
    writer = None

    if not await check_quota(uuid, 0):
        await websocket.close(code=1008, reason="quota exceeded")
        return

    await websocket.accept()

    try:
        header_data = await asyncio.wait_for(websocket.receive_bytes(), timeout=30.0)
        command, address, port, initial_payload = await parse_vless_header(header_data)

        if command == 0x02:
            await websocket.close(code=1003, reason="UDP not supported over WebSocket")
            return

        _record_traffic(uuid, len(header_data))

        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(address, port), timeout=10.0
        )

        conn_id = secrets.token_urlsafe(8)
        connections[conn_id] = {
            "uuid": uuid,
            "target": f"{address}:{port}",
            "bytes": 0,
            "connected_at": datetime.now().isoformat(),
        }

        await websocket.send_bytes(b"\x00\x00")

        if initial_payload:
            _record_traffic(uuid, len(initial_payload))
            connections[conn_id]["bytes"] += len(initial_payload)
            writer.write(initial_payload)
            await writer.drain()

        async def ws_to_tcp():
            nonlocal quota_ok
            try:
                while True:
                    data = await websocket.receive_bytes()
                    if not data:
                        continue
                    n = len(data)
                    _record_traffic(uuid, n)
                    if conn_id in connections:
                        connections[conn_id]["bytes"] += n
                    writer.write(data)
                    await writer.drain()
                    if not quota_ok:
                        break
            except (WebSocketDisconnect, ClientDisconnect, Exception):
                pass

        async def tcp_to_ws():
            try:
                while True:
                    data = await asyncio.wait_for(reader.read(RELAY_BUF), timeout=300.0)
                    if not data:
                        break
                    n = len(data)
                    _record_traffic(uuid, n)
                    if conn_id in connections:
                        connections[conn_id]["bytes"] += n
                    await websocket.send_bytes(data)
            except (WebSocketDisconnect, ClientDisconnect, Exception):
                pass

        quota_ok = True
        task_up = asyncio.create_task(ws_to_tcp())
        task_down = asyncio.create_task(tcp_to_ws())
        done, pending = await asyncio.wait({task_up, task_down}, return_when=asyncio.FIRST_COMPLETED)
        for t in pending:
            t.cancel()
            try:
                await t
            except (asyncio.CancelledError, Exception):
                pass

    except (ClientDisconnect, WebSocketDisconnect):
        pass
    except Exception as exc:
        stats["total_errors"] += 1
        error_logs.append({"error": str(exc), "time": datetime.now().isoformat()})
    finally:
        if writer:
            try:
                writer.close()
                await writer.wait_closed()
            except Exception:
                pass
        try:
            await websocket.close()
        except Exception:
            pass
        connections.pop(conn_id, None)


# ═══════════════════════════════════════════════════════════════════════════════
# بخش ۵: XHTTP Transport
# ═══════════════════════════════════════════════════════════════════════════════
class XHTTPSession:
    def __init__(self, uuid_str: str):
        self.uuid = uuid_str
        self.conn_id: str = ""
        self.to_client: asyncio.Queue = asyncio.Queue(maxsize=64)
        self.from_client: asyncio.Queue = asyncio.Queue(maxsize=64)
        self.tcp_reader = None
        self.tcp_writer = None
        self.closed = False
        self.created_at = datetime.now().isoformat()


async def _get_or_create_session(uuid_str: str, session_id: str) -> XHTTPSession:
    async with XHTTP_SESSIONS_LOCK:
        session = XHTTP_SESSIONS.get(session_id)
        if session is None:
            session = XHTTPSession(uuid_str)
            session.conn_id = session_id
            XHTTP_SESSIONS[session_id] = session
            asyncio.create_task(xhttp_tcp_relay(session))
    return session


async def xhttp_tcp_relay(session: XHTTPSession):
    uuid_str = session.uuid
    conn_id = session.conn_id
    try:
        first_chunk = await asyncio.wait_for(session.from_client.get(), timeout=45.0)
        if first_chunk is None:
            return

        command, address, port, initial_payload = await parse_vless_header(first_chunk)

        if command == 0x02:
            return

        _record_traffic(uuid_str, len(first_chunk))

        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(address, port), timeout=10.0
        )
        session.tcp_reader = reader
        session.tcp_writer = writer

        connections[conn_id] = {
            "uuid": uuid_str,
            "target": f"{address}:{port}",
            "bytes": 0,
            "connected_at": session.created_at,
        }

        await session.to_client.put(b"\x00\x00")

        if initial_payload:
            _record_traffic(uuid_str, len(initial_payload))
            connections[conn_id]["bytes"] += len(initial_payload)
            writer.write(initial_payload)
            await writer.drain()

        async def client_to_tcp():
            try:
                while not session.closed:
                    try:
                        data = await asyncio.wait_for(session.from_client.get(), timeout=60.0)
                    except asyncio.TimeoutError:
                        continue
                    if data is None:
                        break
                    n = len(data)
                    _record_traffic(uuid_str, n)
                    if conn_id in connections:
                        connections[conn_id]["bytes"] += n
                    writer.write(data)
                    await writer.drain()
            except Exception:
                pass
            finally:
                try:
                    writer.write_eof()
                except Exception:
                    pass

        async def tcp_to_client():
            try:
                while not session.closed:
                    data = await reader.read(RELAY_BUF)
                    if not data:
                        break
                    n = len(data)
                    _record_traffic(uuid_str, n)
                    if conn_id in connections:
                        connections[conn_id]["bytes"] += n
                    await session.to_client.put(data)
            except Exception:
                pass
            finally:
                await session.to_client.put(None)

        task_up = asyncio.create_task(client_to_tcp())
        task_down = asyncio.create_task(tcp_to_client())
        await asyncio.wait({task_up, task_down}, return_when=asyncio.FIRST_COMPLETED)
        task_up.cancel()
        task_down.cancel()

    except Exception as exc:
        stats["total_errors"] += 1
        error_logs.append({"error": str(exc), "time": datetime.now().isoformat()})
    finally:
        session.closed = True
        await session.to_client.put(None)
        try:
            if session.tcp_writer:
                session.tcp_writer.close()
        except Exception:
            pass
        connections.pop(conn_id, None)
        async with XHTTP_SESSIONS_LOCK:
            XHTTP_SESSIONS.pop(conn_id, None)


@app.get("/xhttp/{uuid}/{session_id}")
async def xhttp_downstream(uuid: str, session_id: str, request: Request):
    stats["total_requests"] += 1
    session = await _get_or_create_session(uuid, session_id)

    async def generate():
        try:
            while True:
                try:
                    chunk = await asyncio.wait_for(session.to_client.get(), timeout=20.0)
                except asyncio.TimeoutError:
                    yield b"\x00"
                    continue
                if chunk is None:
                    break
                yield chunk
        except (ClientDisconnect, Exception):
            pass

    return StreamingResponse(
        generate(),
        media_type="application/octet-stream",
        headers={
            "Cache-Control": "no-store",
            "X-Accel-Buffering": "no",
        },
    )


@app.post("/xhttp/{uuid}/{session_id}/{seq}")
async def xhttp_upstream(uuid: str, session_id: str, seq: str, request: Request):
    stats["total_requests"] += 1
    session = await _get_or_create_session(uuid, session_id)
    try:
        body = await request.body()
    except ClientDisconnect:
        return Response(status_code=499, content=b"", media_type="application/octet-stream")
    if body:
        try:
            await asyncio.wait_for(session.from_client.put(body), timeout=10.0)
        except asyncio.TimeoutError:
            raise HTTPException(status_code=503, detail="buffer full")
    return Response(status_code=200, content=b"", media_type="application/octet-stream")


# ═══════════════════════════════════════════════════════════════════════════════
# بخش ۶: gRPC Transport
# ═══════════════════════════════════════════════════════════════════════════════
async def _grpc_handler(uuid: str, path: str, request: Request):
    stats["total_requests"] += 1
    if not await check_quota(uuid, 0):
        raise HTTPException(status_code=403, detail="quota exceeded")

    try:
        body = await request.body()
    except ClientDisconnect:
        return Response(status_code=499, content=b"", media_type="application/grpc+proto")
    if not body or len(body) < 5:
        raise HTTPException(status_code=400, detail="empty body")

    grpc_payloads = []
    pos = 0
    while pos + 5 <= len(body):
        frame_len = int.from_bytes(body[pos + 1:pos + 5], "big")
        pos += 5
        if pos + frame_len > len(body):
            break
        grpc_payloads.append(body[pos:pos + frame_len])
        pos += frame_len

    if not grpc_payloads:
        raise HTTPException(status_code=400, detail="no gRPC frames")

    try:
        command, address, port, initial_payload = await parse_vless_header(grpc_payloads[0])
    except Exception:
        raise HTTPException(status_code=400, detail="invalid VLESS header")

    if command == 0x02:
        raise HTTPException(status_code=400, detail="UDP not supported")

    try:
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(address, port), timeout=10.0
        )
    except Exception:
        raise HTTPException(status_code=502, detail="connection failed")

    conn_id = secrets.token_urlsafe(8)
    connections[conn_id] = {
        "uuid": uuid,
        "target": f"{address}:{port}",
        "bytes": 0,
        "connected_at": datetime.now().isoformat(),
    }

    _record_traffic(uuid, len(grpc_payloads[0]))

    if initial_payload:
        _record_traffic(uuid, len(initial_payload))
        connections[conn_id]["bytes"] += len(initial_payload)
        writer.write(initial_payload)

    for payload in grpc_payloads[1:]:
        _record_traffic(uuid, len(payload))
        if conn_id in connections:
            connections[conn_id]["bytes"] += len(payload)
        writer.write(payload)

    await writer.drain()

    async def generate():
        try:
            vless_resp = b"\x00\x00"
            yield b"\x00" + len(vless_resp).to_bytes(4, "big") + vless_resp
            while True:
                data = await asyncio.wait_for(reader.read(RELAY_BUF), timeout=300.0)
                if not data:
                    break
                n = len(data)
                _record_traffic(uuid, n)
                if conn_id in connections:
                    connections[conn_id]["bytes"] += n
                yield b"\x00" + n.to_bytes(4, "big") + data
        except (ClientDisconnect, Exception):
            pass
        finally:
            yield b"\x80\x00\x00\x00\x00"
            try:
                writer.close()
                await writer.wait_closed()
            except Exception:
                pass
            connections.pop(conn_id, None)

    return StreamingResponse(
        generate(),
        media_type="application/grpc+proto",
        headers={
            "Cache-Control": "no-store",
            "X-Accel-Buffering": "no",
        },
    )


@app.post("/grpc/{uuid}")
async def grpc_unary(uuid: str, request: Request):
    return await _grpc_handler(uuid, "", request)


@app.post("/grpc/{uuid}/{path:path}")
async def grpc_stream(uuid: str, path: str, request: Request):
    return await _grpc_handler(uuid, path, request)


# ═══════════════════════════════════════════════════════════════════════════════
# بخش ۹: Auth API
# ═══════════════════════════════════════════════════════════════════════════════
@app.post("/api/login")
async def api_login(request: Request):
    try:
        body = await request.json()
    except Exception:
        raise HTTPException(status_code=400, detail="invalid JSON")
    password = body.get("password", "")
    if hashlib.sha256(password.encode()).hexdigest() != ADMIN_PASSWORD_HASH:
        raise HTTPException(status_code=401, detail="wrong password")
    token = secrets.token_urlsafe(32)
    async with SESSIONS_LOCK:
        SESSIONS[token] = time.time() + SESSION_TTL
    response = JSONResponse({"ok": True})
    response.set_cookie(
        key=SESSION_COOKIE,
        value=token,
        max_age=SESSION_TTL,
        httponly=True,
        samesite="lax",
    )
    return response


@app.post("/api/logout")
async def api_logout(request: Request):
    token = request.cookies.get(SESSION_COOKIE) or ""
    async with SESSIONS_LOCK:
        SESSIONS.pop(token, None)
    response = JSONResponse({"ok": True})
    response.delete_cookie(SESSION_COOKIE)
    return response


@app.get("/api/me")
async def api_me(request: Request):
    if not await _require_auth(request):
        raise HTTPException(status_code=401)
    return {"ok": True}


# ═══════════════════════════════════════════════════════════════════════════════
# بخش ۱۲: Stats API
# ═══════════════════════════════════════════════════════════════════════════════
@app.get("/api/stats")
async def api_stats(request: Request):
    if not await _require_auth(request):
        raise HTTPException(status_code=401)
    uptime = time.time() - stats["start_time"]
    hours = int(uptime // 3600)
    minutes = int((uptime % 3600) // 60)
    seconds = int(uptime % 60)
    today_key = datetime.now().strftime("%H:00")
    today_traffic = hourly_traffic.get(today_key, 0)
    active_users = sum(1 for v in LINKS.values() if v["active"])
    return {
        "total_bytes": stats["total_bytes"],
        "total_requests": stats["total_requests"],
        "total_errors": stats["total_errors"],
        "active_connections": len(connections),
        "active_users": active_users,
        "total_users": len(LINKS),
        "uptime": f"{hours:02d}:{minutes:02d}:{seconds:02d}",
        "uptime_seconds": uptime,
        "today_traffic": today_traffic,
        "hourly_traffic": dict(hourly_traffic),
        "error_logs": list(error_logs),
        "connections": [
            {
                "id": k,
                "uuid": v["uuid"],
                "target": v["target"],
                "bytes": v["bytes"],
                "connected_at": v["connected_at"],
            }
            for k, v in connections.items()
        ],
    }


# ═══════════════════════════════════════════════════════════════════════════════
# بخش ۸: Links CRUD API
# ═══════════════════════════════════════════════════════════════════════════════
@app.post("/api/links")
async def api_create_link(request: Request):
    if not await _require_auth(request):
        raise HTTPException(status_code=401)
    try:
        body = await request.json()
    except Exception:
        raise HTTPException(status_code=400, detail="invalid JSON")
    label = body.get("label", "User")
    limit_gb = float(body.get("limit_gb", 0))
    max_connections = int(body.get("max_connections", 0))
    custom_uuid = body.get("custom_uuid", "")
    uid = custom_uuid.strip() if custom_uuid.strip() else str(uuid_mod.uuid4())
    try:
        uuid_mod.UUID(uid)
    except ValueError:
        raise HTTPException(status_code=400, detail="invalid UUID format")
    async with LINKS_LOCK:
        if uid in LINKS:
            raise HTTPException(status_code=409, detail="UUID already exists")
        LINKS[uid] = {
            "label": label,
            "limit_bytes": int(limit_gb * 1024 * 1024 * 1024),
            "used_bytes": 0,
            "max_connections": max_connections,
            "active": True,
            "created_at": datetime.now().isoformat(),
        }
    domain = get_domain()
    links = make_vless_links(uid, domain, label)
    return {
        "uuid": uid,
        "label": label,
        "limit_bytes": LINKS[uid]["limit_bytes"],
        "used_bytes": 0,
        "max_connections": max_connections,
        "active": True,
        "created_at": LINKS[uid]["created_at"],
        "links": links,
    }


@app.get("/api/links")
async def api_list_links(request: Request):
    if not await _require_auth(request):
        raise HTTPException(status_code=401)
    domain = get_domain()
    result = []
    async with LINKS_LOCK:
        for uid, link in LINKS.items():
            links = make_vless_links(uid, domain, link["label"])
            limit_gb = link["limit_bytes"] / (1024 ** 3) if link["limit_bytes"] > 0 else 0
            used_gb = link["used_bytes"] / (1024 ** 3)
            result.append({
                "uuid": uid,
                "label": link["label"],
                "limit_bytes": link["limit_bytes"],
                "limit_gb": round(limit_gb, 2),
                "used_bytes": link["used_bytes"],
                "used_gb": round(used_gb, 2),
                "max_connections": link["max_connections"],
                "active": link["active"],
                "created_at": link["created_at"],
                "links": links,
            })
    return result


@app.patch("/api/links/{uuid}")
async def api_update_link(uuid: str, request: Request):
    if not await _require_auth(request):
        raise HTTPException(status_code=401)
    try:
        body = await request.json()
    except Exception:
        raise HTTPException(status_code=400, detail="invalid JSON")
    async with LINKS_LOCK:
        link = LINKS.get(uuid)
        if not link:
            raise HTTPException(status_code=404, detail="user not found")
        if "label" in body:
            link["label"] = body["label"]
        if "limit_value" in body and "limit_unit" in body:
            val = float(body["limit_value"])
            unit = body["limit_unit"]
            if unit == "GB":
                link["limit_bytes"] = int(val * 1024 ** 3)
            elif unit == "MB":
                link["limit_bytes"] = int(val * 1024 ** 2)
        if "max_connections" in body:
            link["max_connections"] = int(body["max_connections"])
        if "active" in body:
            link["active"] = bool(body["active"])
        if body.get("reset_usage"):
            link["used_bytes"] = 0
        if "add_gb" in body:
            link["limit_bytes"] += int(float(body["add_gb"]) * 1024 ** 3)
    domain = get_domain()
    links = make_vless_links(uuid, domain, link["label"])
    return {
        "uuid": uuid,
        "label": link["label"],
        "limit_bytes": link["limit_bytes"],
        "used_bytes": link["used_bytes"],
        "max_connections": link["max_connections"],
        "active": link["active"],
        "links": links,
    }


@app.delete("/api/links/{uuid}")
async def api_delete_link(uuid: str, request: Request):
    if not await _require_auth(request):
        raise HTTPException(status_code=401)
    async with LINKS_LOCK:
        if uuid not in LINKS:
            raise HTTPException(status_code=404, detail="user not found")
        del LINKS[uuid]
    return {"ok": True}


@app.post("/api/change-password")
async def api_change_password(request: Request):
    if not await _require_auth(request):
        raise HTTPException(status_code=401)
    try:
        body = await request.json()
    except Exception:
        raise HTTPException(status_code=400, detail="invalid JSON")
    current = body.get("current_password", "")
    new_pass = body.get("new_password", "")
    global ADMIN_PASSWORD_HASH
    if hashlib.sha256(current.encode()).hexdigest() != ADMIN_PASSWORD_HASH:
        raise HTTPException(status_code=401, detail="wrong current password")
    if len(new_pass) < 4:
        raise HTTPException(status_code=400, detail="password too short")
    ADMIN_PASSWORD_HASH = hashlib.sha256(new_pass.encode()).hexdigest()
    async with SESSIONS_LOCK:
        SESSIONS.clear()
    return {"ok": True}


# ═══════════════════════════════════════════════════════════════════════════════
# بخش ۱۰: Keep-Alive
# ═══════════════════════════════════════════════════════════════════════════════
async def keep_alive_worker():
    await asyncio.sleep(60)
    while True:
        try:
            domain = get_domain()
            if domain and domain != "localhost":
                async with httpx.AsyncClient(timeout=10.0) as c:
                    await c.get(f"https://{domain}/health")
        except Exception:
            pass
        await asyncio.sleep(300)


# ═══════════════════════════════════════════════════════════════════════════════
# بخش ۱۱: پنل ادمین — HTML
# ═══════════════════════════════════════════════════════════════════════════════
ADMIN_HTML = r"""<!DOCTYPE html>
<html lang="fa" dir="rtl">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1.0">
<title>AURA Gateway</title>
<link href="https://fonts.googleapis.com/css2?family=Vazirmatn:wght@300;400;500;600;700&display=swap" rel="stylesheet">
<style>
*{margin:0;padding:0;box-sizing:border-box}
body{font-family:'Vazirmatn',sans-serif;background:#F0F4FF;color:#1E293B;min-height:100vh}
:root{--accent:#6366F1;--accent-h:#4F46E5;--ok:#10B981;--danger:#EF4444;--warn:#F59E0B;--muted:#64748B;--border:#E2E8F0;--card:#FFFFFF;--page-bg:#F0F4FF;--sidebar-w:220px}

/* ── Login ── */
#login-page{display:flex;align-items:center;justify-content:center;min-height:100vh;background:linear-gradient(135deg,#6366F1 0%,#8B5CF6 100%)}
.login-card{background:#fff;border-radius:16px;padding:48px 36px;width:380px;max-width:90vw;box-shadow:0 20px 60px rgba(0,0,0,.15);text-align:center}
.login-logo{font-size:42px;font-weight:700;color:var(--accent);margin-bottom:8px}
.login-sub{color:var(--muted);margin-bottom:28px;font-size:14px}
.login-input{width:100%;padding:12px 16px;border:2px solid var(--border);border-radius:10px;font-family:inherit;font-size:15px;outline:none;transition:border .2s}
.login-input:focus{border-color:var(--accent)}
.login-btn{width:100%;padding:12px;background:var(--accent);color:#fff;border:none;border-radius:10px;font-family:inherit;font-size:15px;font-weight:600;cursor:pointer;margin-top:16px;transition:background .2s}
.login-btn:hover{background:var(--accent-h)}
.login-error{color:var(--danger);margin-top:12px;font-size:13px;min-height:20px}

/* ── Main Layout ── */
#main-panel{display:none;min-height:100vh}
.sidebar{position:fixed;right:0;top:0;width:var(--sidebar-w);height:100vh;background:var(--card);border-left:1px solid var(--border);display:flex;flex-direction:column;z-index:100;padding:24px 0}
.sidebar-logo{padding:0 20px 24px;font-size:22px;font-weight:700;color:var(--accent);border-bottom:1px solid var(--border);margin-bottom:16px}
.sidebar-nav{flex:1;display:flex;flex-direction:column;gap:4px;padding:0 12px}
.nav-item{display:flex;align-items:center;gap:10px;padding:10px 14px;border-radius:10px;cursor:pointer;color:var(--muted);font-size:14px;font-weight:500;transition:all .2s;text-decoration:none}
.nav-item:hover,.nav-item.active{background:rgba(99,102,241,.1);color:var(--accent)}
.nav-item svg{width:20px;height:20px;flex-shrink:0}
.sidebar-footer{padding:12px;border-top:1px solid var(--border)}
.logout-btn{display:flex;align-items:center;gap:10px;padding:10px 14px;border-radius:10px;cursor:pointer;color:var(--danger);font-size:14px;font-weight:500;width:100%;background:none;border:none;font-family:inherit;transition:background .2s}
.logout-btn:hover{background:rgba(239,68,68,.1)}
.content{margin-right:var(--sidebar-w);padding:28px 32px;min-height:100vh}

/* ── Pages ── */
.page{display:none}
.page.active{display:block}
.page-title{font-size:22px;font-weight:700;margin-bottom:24px}

/* ── Stat Cards ── */
.stat-grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(200px,1fr));gap:16px;margin-bottom:28px}
.stat-card{background:var(--card);border-radius:14px;padding:20px;box-shadow:0 1px 3px rgba(0,0,0,.06)}
.stat-label{font-size:13px;color:var(--muted);margin-bottom:8px}
.stat-value{font-size:26px;font-weight:700}
.stat-card.accent .stat-value{color:var(--accent)}
.stat-card.ok .stat-value{color:var(--ok)}
.stat-card.warn .stat-value{color:var(--warn)}
.stat-card.danger .stat-value{color:var(--danger)}

/* ── Chart ── */
.chart-card{background:var(--card);border-radius:14px;padding:20px;box-shadow:0 1px 3px rgba(0,0,0,.06);margin-bottom:28px}
.chart-title{font-size:15px;font-weight:600;margin-bottom:16px}
.chart-svg{width:100%;height:180px}

/* ── Table ── */
.table-card{background:var(--card);border-radius:14px;padding:20px;box-shadow:0 1px 3px rgba(0,0,0,.06);overflow-x:auto}
.table-title{font-size:15px;font-weight:600;margin-bottom:16px}
table{width:100%;border-collapse:collapse;font-size:13px}
th{text-align:right;padding:10px 12px;color:var(--muted);font-weight:500;border-bottom:2px solid var(--border)}
td{padding:10px 12px;border-bottom:1px solid var(--border)}
tr:last-child td{border-bottom:none}

/* ── Progress Bar ── */
.progress-wrap{background:#E2E8F0;border-radius:6px;height:8px;width:100%;overflow:hidden;min-width:80px}
.progress-bar{height:100%;border-radius:6px;transition:width .3s}

/* ── Buttons ── */
.btn{padding:8px 18px;border-radius:8px;border:none;font-family:inherit;font-size:13px;font-weight:600;cursor:pointer;transition:all .2s;display:inline-flex;align-items:center;gap:6px}
.btn-primary{background:var(--accent);color:#fff}
.btn-primary:hover{background:var(--accent-h)}
.btn-sm{padding:5px 12px;font-size:12px;border-radius:6px}
.btn-outline{background:transparent;border:1.5px solid var(--border);color:var(--muted)}
.btn-outline:hover{border-color:var(--accent);color:var(--accent)}
.btn-danger{background:transparent;border:1.5px solid var(--danger);color:var(--danger)}
.btn-danger:hover{background:rgba(239,68,68,.1)}
.btn-success{background:var(--ok);color:#fff}

/* ── Toggle ── */
.toggle{position:relative;width:44px;height:24px;cursor:pointer}
.toggle input{opacity:0;width:0;height:0}
.toggle-slider{position:absolute;inset:0;background:#CBD5E1;border-radius:24px;transition:.2s}
.toggle-slider::before{content:'';position:absolute;width:18px;height:18px;left:3px;bottom:3px;background:#fff;border-radius:50%;transition:.2s}
.toggle input:checked+.toggle-slider{background:var(--ok)}
.toggle input:checked+.toggle-slider::before{transform:translateX(20px)}

/* ── Modal ── */
.modal-overlay{display:none;position:fixed;inset:0;background:rgba(0,0,0,.4);z-index:1000;align-items:center;justify-content:center}
.modal-overlay.open{display:flex}
.modal{background:var(--card);border-radius:16px;padding:28px;width:480px;max-width:92vw;max-height:90vh;overflow-y:auto;box-shadow:0 20px 60px rgba(0,0,0,.2)}
.modal-title{font-size:18px;font-weight:700;margin-bottom:20px}
.form-group{margin-bottom:16px}
.form-label{display:block;font-size:13px;font-weight:500;margin-bottom:6px;color:var(--muted)}
.form-input{width:100%;padding:10px 14px;border:1.5px solid var(--border);border-radius:8px;font-family:inherit;font-size:14px;outline:none;transition:border .2s}
.form-input:focus{border-color:var(--accent)}
.form-row{display:flex;gap:10px;align-items:flex-end}
.form-row .form-group{flex:1}
.modal-actions{display:flex;gap:10px;justify-content:flex-end;margin-top:20px}

/* ── Tabs ── */
.tabs{display:flex;gap:4px;margin-bottom:16px;background:#F1F5F9;border-radius:10px;padding:4px}
.tab-btn{padding:8px 16px;border-radius:8px;border:none;font-family:inherit;font-size:13px;font-weight:500;cursor:pointer;background:transparent;color:var(--muted);transition:all .2s}
.tab-btn.active{background:var(--accent);color:#fff}
.link-box{background:#F8FAFC;border:1px solid var(--border);border-radius:8px;padding:12px;margin-bottom:10px;word-break:break-all;font-size:12px;font-family:monospace;direction:ltr;text-align:left;line-height:1.6}
.link-actions{display:flex;gap:8px;margin-top:8px}

/* ── Settings ── */
.settings-section{background:var(--card);border-radius:14px;padding:24px;box-shadow:0 1px 3px rgba(0,0,0,.06);margin-bottom:20px}
.settings-title{font-size:16px;font-weight:600;margin-bottom:16px}
.info-grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(180px,1fr));gap:12px}
.info-item{padding:12px;background:#F8FAFC;border-radius:8px}
.info-label{font-size:12px;color:var(--muted);margin-bottom:4px}
.info-value{font-size:15px;font-weight:600}

/* ── Responsive ── */
@media(max-width:768px){
.sidebar{position:fixed;bottom:0;top:auto;left:0;right:0;width:100%;height:64px;flex-direction:row;border-left:none;border-top:1px solid var(--border);padding:0}
.sidebar-logo,.sidebar-footer{display:none}
.sidebar-nav{flex-direction:row;justify-content:space-around;padding:0;align-items:center;height:100%}
.nav-item{flex-direction:column;gap:2px;padding:8px;font-size:10px}
.nav-item span{display:none}
.content{margin-right:0;padding:16px 12px 80px}
.stat-grid{grid-template-columns:repeat(2,1fr)}
.form-row{flex-direction:column}
}
</style>
</head>
<body>

<!-- ═══ Login Page ═══ -->
<div id="login-page">
<div class="login-card">
<div class="login-logo">AURA</div>
<div class="login-sub">Gateway Management Panel</div>
<input type="password" id="login-pass" class="login-input" placeholder="رمز عبور" autocomplete="current-password">
<button class="login-btn" onclick="doLogin()">ورود</button>
<div class="login-error" id="login-error"></div>
</div>
</div>

<!-- ═══ Main Panel ═══ -->
<div id="main-panel">
<!-- Sidebar -->
<aside class="sidebar">
<div class="sidebar-logo">AURA</div>
<nav class="sidebar-nav">
<a class="nav-item active" onclick="navTo('dashboard')" id="nav-dashboard">
<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><rect x="3" y="3" width="7" height="7" rx="1"/><rect x="14" y="3" width="7" height="7" rx="1"/><rect x="3" y="14" width="7" height="7" rx="1"/><rect x="14" y="14" width="7" height="7" rx="1"/></svg>
<span>داشبورد</span>
</a>
<a class="nav-item" onclick="navTo('users')" id="nav-users">
<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M17 21v-2a4 4 0 0 0-4-4H5a4 4 0 0 0-4 4v2"/><circle cx="9" cy="7" r="4"/><path d="M23 21v-2a4 4 0 0 0-3-3.87"/><path d="M16 3.13a4 4 0 0 1 0 7.75"/></svg>
<span>کاربران</span>
</a>
<a class="nav-item" onclick="navTo('settings')" id="nav-settings">
<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="12" cy="12" r="3"/><path d="M19.4 15a1.65 1.65 0 0 0 .33 1.82l.06.06a2 2 0 1 1-2.83 2.83l-.06-.06a1.65 1.65 0 0 0-1.82-.33 1.65 1.65 0 0 0-1 1.51V21a2 2 0 0 1-4 0v-.09A1.65 1.65 0 0 0 9 19.4a1.65 1.65 0 0 0-1.82.33l-.06.06a2 2 0 1 1-2.83-2.83l.06-.06A1.65 1.65 0 0 0 4.68 15a1.65 1.65 0 0 0-1.51-1H3a2 2 0 0 1 0-4h.09A1.65 1.65 0 0 0 4.6 9a1.65 1.65 0 0 0-.33-1.82l-.06-.06a2 2 0 1 1 2.83-2.83l.06.06A1.65 1.65 0 0 0 9 4.68a1.65 1.65 0 0 0 1-1.51V3a2 2 0 0 1 4 0v.09a1.65 1.65 0 0 0 1 1.51 1.65 1.65 0 0 0 1.82-.33l.06-.06a2 2 0 1 1 2.83 2.83l-.06.06A1.65 1.65 0 0 0 19.4 9a1.65 1.65 0 0 0 1.51 1H21a2 2 0 0 1 0 4h-.09a1.65 1.65 0 0 0-1.51 1z"/></svg>
<span>تنظیمات</span>
</a>
</nav>
<div class="sidebar-footer">
<button class="logout-btn" onclick="doLogout()">
<svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M9 21H5a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h4"/><polyline points="16 17 21 12 16 7"/><line x1="21" y1="12" x2="9" y2="12"/></svg>
خروج
</button>
</div>
</aside>

<!-- Content -->
<main class="content">

<!-- Dashboard Page -->
<div class="page active" id="page-dashboard">
<div class="page-title">داشبورد</div>
<div class="stat-grid">
<div class="stat-card accent"><div class="stat-label">کاربران فعال</div><div class="stat-value" id="s-users">-</div></div>
<div class="stat-card ok"><div class="stat-label">ترافیک امروز</div><div class="stat-value" id="s-today">-</div></div>
<div class="stat-card warn"><div class="stat-label">اتصال‌های الان</div><div class="stat-value" id="s-conns">-</div></div>
<div class="stat-card"><div class="stat-label">آپتایم</div><div class="stat-value" id="s-uptime">-</div></div>
</div>
<div class="chart-card">
<div class="chart-title">ترافیک ۲۴ ساعته</div>
<svg class="chart-svg" id="traffic-chart" viewBox="0 0 720 180" preserveAspectRatio="none"></svg>
</div>
<div class="table-card">
<div class="chart-title">اتصال‌های فعال</div>
<table><thead><tr><th>UUID</th><th>مقصد</th><th>داده</th><th>زمان اتصال</th></tr></thead>
<tbody id="conns-table"><tr><td colspan="4" style="text-align:center;color:var(--muted)">اتصالی نیست</td></tr></tbody></table>
</div>
</div>

<!-- Users Page -->
<div class="page" id="page-users">
<div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:24px">
<div class="page-title" style="margin:0">کاربران</div>
<button class="btn btn-primary" onclick="openAddModal()">
<svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><line x1="12" y1="5" x2="12" y2="19"/><line x1="5" y1="12" x2="19" y2="12"/></svg>
کاربر جدید
</button>
</div>
<div class="table-card">
<table><thead><tr><th>نام</th><th>مصرف / سهمیه</th><th>اتصال همزمان</th><th>وضعیت</th><th>عملیات</th></tr></thead>
<tbody id="users-table"></tbody></table>
</div>
</div>

<!-- Settings Page -->
<div class="page" id="page-settings">
<div class="page-title">تنظیمات</div>
<div class="settings-section">
<div class="settings-title">تغییر رمز عبور</div>
<div class="form-group"><label class="form-label">رمز فعلی</label><input type="password" class="form-input" id="set-cur-pass"></div>
<div class="form-group"><label class="form-label">رمز جدید</label><input type="password" class="form-input" id="set-new-pass"></div>
<button class="btn btn-primary" onclick="changePassword()">تغییر رمز</button>
<div id="set-pass-msg" style="margin-top:10px;font-size:13px"></div>
</div>
<div class="settings-section">
<div class="settings-title">اطلاعات سیستم</div>
<div class="info-grid">
<div class="info-item"><div class="info-label">دامنه</div><div class="info-value" id="si-domain">-</div></div>
<div class="info-item"><div class="info-label">CPU</div><div class="info-value" id="si-cpu">-</div></div>
<div class="info-item"><div class="info-label">RAM</div><div class="info-value" id="si-ram">-</div></div>
<div class="info-item"><div class="info-label">آپتایم</div><div class="info-value" id="si-uptime">-</div></div>
</div>
</div>
</div>
</main>
</div>

<!-- ═══ Add User Modal ═══ -->
<div class="modal-overlay" id="modal-add">
<div class="modal">
<div class="modal-title">کاربر جدید</div>
<div class="form-group"><label class="form-label">نام</label><input class="form-input" id="add-label" placeholder="مثلاً: علی"></div>
<div class="form-row">
<div class="form-group"><label class="form-label">سهمیه (GB)</label><input type="number" class="form-input" id="add-limit" value="0" min="0" step="0.5"></div>
<div class="form-group"><label class="form-label">حداکثر اتصال</label><input type="number" class="form-input" id="add-maxconn" value="0" min="0"></div>
</div>
<div class="form-group"><label class="form-label">UUID سفارشی (اختیاری)</label><input class="form-input" id="add-uuid" placeholder="خالی = خودکار"></div>
<div class="modal-actions">
<button class="btn btn-outline" onclick="closeModal('modal-add')">انصراف</button>
<button class="btn btn-primary" onclick="createUser()">ایجاد</button>
</div>
</div>
</div>

<!-- ═══ Edit User Modal ═══ -->
<div class="modal-overlay" id="modal-edit">
<div class="modal">
<div class="modal-title">ویرایش کاربر</div>
<input type="hidden" id="edit-uuid">
<div class="form-group"><label class="form-label">نام</label><input class="form-input" id="edit-label"></div>
<div class="form-row">
<div class="form-group"><label class="form-label">سهمیه</label><input type="number" class="form-input" id="edit-limit-val" min="0" step="0.5"></div>
<div class="form-group"><label class="form-label">واحد</label><select class="form-input" id="edit-limit-unit"><option value="GB">GB</option><option value="MB">MB</option></select></div>
</div>
<div class="form-group"><label class="form-label">افزودن گیگابایت</label><input type="number" class="form-input" id="edit-add-gb" min="0" step="0.5" placeholder="0"></div>
<div class="form-group"><label class="form-label">حداکثر اتصال همزمان</label><input type="number" class="form-input" id="edit-maxconn" min="0"></div>
<div class="form-group" style="display:flex;align-items:center;gap:12px">
<label class="form-label" style="margin:0">وضعیت</label>
<label class="toggle"><input type="checkbox" id="edit-active" checked><span class="toggle-slider"></span></label>
</div>
<div class="modal-actions" style="justify-content:space-between">
<button class="btn btn-outline" style="color:var(--danger);border-color:var(--danger)" onclick="resetUsage()">ریست مصرف</button>
<div style="display:flex;gap:10px">
<button class="btn btn-outline" onclick="closeModal('modal-edit')">انصراف</button>
<button class="btn btn-primary" onclick="saveUser()">ذخیره</button>
</div>
</div>
</div>
</div>

<!-- ═══ Links Modal ═══ -->
<div class="modal-overlay" id="modal-links">
<div class="modal" style="width:560px">
<div class="modal-title">لینک‌های اتصال</div>
<input type="hidden" id="links-uuid">
<div class="tabs">
<button class="tab-btn active" onclick="switchTab(this,'link-ws')">WS</button>
<button class="tab-btn" onclick="switchTab(this,'link-xhttp')">XHTTP</button>
<button class="tab-btn" onclick="switchTab(this,'link-grpc')">gRPC</button>
</div>
<div id="link-ws" class="link-tab">
<div class="link-box" id="link-ws-text"></div>
<div class="link-actions">
<button class="btn btn-sm btn-outline" onclick="copyLink('link-ws-text')">کپی</button>
<button class="btn btn-sm btn-outline" onclick="showQR('link-ws-text')">QR Code</button>
</div>
<div id="link-ws-qr" style="margin-top:10px;text-align:center"></div>
</div>
<div id="link-xhttp" class="link-tab" style="display:none">
<div class="link-box" id="link-xhttp-text"></div>
<div class="link-actions">
<button class="btn btn-sm btn-outline" onclick="copyLink('link-xhttp-text')">کپی</button>
<button class="btn btn-sm btn-outline" onclick="showQR('link-xhttp-text')">QR Code</button>
</div>
<div id="link-xhttp-qr" style="margin-top:10px;text-align:center"></div>
</div>
<div id="link-grpc" class="link-tab" style="display:none">
<div class="link-box" id="link-grpc-text"></div>
<div class="link-actions">
<button class="btn btn-sm btn-outline" onclick="copyLink('link-grpc-text')">کپی</button>
<button class="btn btn-sm btn-outline" onclick="showQR('link-grpc-text')">QR Code</button>
</div>
<div id="link-grpc-qr" style="margin-top:10px;text-align:center"></div>
</div>
<div class="modal-actions" style="margin-top:20px">
<button class="btn btn-outline" onclick="closeModal('modal-links')">بستن</button>
</div>
</div>
</div>

<script>
/* ── State ── */
let currentPage='dashboard';
let linksCache={};
let refreshTimer=null;

/* ── Helpers ── */
function fmtBytes(b){
if(b===0)return'0 B';
const u=['B','KB','MB','GB','TB'];
const i=Math.floor(Math.log(b)/Math.log(1024));
return(b/Math.pow(1024,i)).toFixed(1)+' '+u[i];
}
function fmtBytesShort(b){
if(b<1024)return b+' B';
if(b<1048576)return(b/1024).toFixed(1)+' K';
if(b<1073741824)return(b/1048576).toFixed(1)+' M';
return(b/1073741824).toFixed(2)+' G';
}
async function api(path,opts={}){
const r=await fetch(path,opts);
if(r.status===401){showLogin();throw new Error('unauthorized');}
return r;
}
async function apiJSON(path,opts={}){
const r=await api(path,opts);
return r.json();
}

/* ── Auth ── */
async function checkAuth(){
try{await api('/api/me');showPanel();}catch(e){showLogin();}
}
function showLogin(){
document.getElementById('login-page').style.display='flex';
document.getElementById('main-panel').style.display='none';
if(refreshTimer){clearInterval(refreshTimer);refreshTimer=null;}
}
function showPanel(){
document.getElementById('login-page').style.display='none';
document.getElementById('main-panel').style.display='block';
loadData();
if(!refreshTimer)refreshTimer=setInterval(loadData,5000);
}
async function doLogin(){
const pass=document.getElementById('login-pass').value;
const err=document.getElementById('login-error');
try{
const r=await fetch('/api/login',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({password:pass})});
if(r.ok){err.textContent='';showPanel();}
else{err.textContent='رمز عبور اشتباه است';}
}catch(e){err.textContent='خطا در اتصال';}
}
async function doLogout(){
await api('/api/logout',{method:'POST'});
showLogin();
}
document.getElementById('login-pass').addEventListener('keydown',function(e){if(e.key==='Enter')doLogin();});

/* ── Navigation ── */
function navTo(page){
document.querySelectorAll('.page').forEach(p=>p.classList.remove('active'));
document.querySelectorAll('.nav-item').forEach(n=>n.classList.remove('active'));
document.getElementById('page-'+page).classList.add('active');
document.getElementById('nav-'+page).classList.add('active');
currentPage=page;
if(page==='settings')loadSettings();
if(page==='users')loadUsers();
}

/* ── Load Data ── */
async function loadData(){
try{
const s=await apiJSON('/api/stats');
document.getElementById('s-users').textContent=s.active_users;
document.getElementById('s-today').textContent=fmtBytesShort(s.today_traffic);
document.getElementById('s-conns').textContent=s.active_connections;
document.getElementById('s-uptime').textContent=s.uptime;
renderChart(s.hourly_traffic);
renderConns(s.connections);
if(currentPage==='users')loadUsers();
if(currentPage==='settings'){document.getElementById('si-uptime').textContent=s.uptime;document.getElementById('si-domain').textContent=window.location.hostname;}
}catch(e){}
}

/* ── Chart ── */
function renderChart(ht){
const svg=document.getElementById('traffic-chart');
if(!ht||Object.keys(ht).length===0){svg.innerHTML='<text x="360" y="95" text-anchor="middle" fill="#94A3B8" font-size="14" font-family="Vazirmatn">داده‌ای نیست</text>';return;}
const keys=Object.keys(ht).sort();
const vals=keys.map(k=>ht[k]);
const maxV=Math.max(...vals,1);
const w=720,h=180,pad=30,barW=Math.max(8,Math.floor((w-pad*2)/keys.length)-4);
const chartH=h-pad;
let rects='';
keys.forEach((k,i)=>{
const x=pad+i*((w-pad*2)/keys.length)+2;
const barH=Math.max(2,(vals[i]/maxV)*chartH);
const y=chartH-barH;
rects+=`<rect x="${x}" y="${y}" width="${barW}" height="${barH}" rx="3" fill="#6366F1" opacity="0.85"/>`;
rects+=`<text x="${x+barW/2}" y="${h-4}" text-anchor="middle" fill="#94A3B8" font-size="8" font-family="Vazirmatn">${k.replace(':00','')}</text>`;
});
svg.innerHTML=rects;
}

/* ── Connections Table ── */
function renderConns(conns){
const tb=document.getElementById('conns-table');
if(!conns||conns.length===0){tb.innerHTML='<tr><td colspan="4" style="text-align:center;color:var(--muted)">اتصالی نیست</td></tr>';return;}
tb.innerHTML=conns.map(c=>`<tr><td style="font-family:monospace;font-size:11px">${c.uuid.substring(0,8)}...</td><td>${c.target}</td><td>${fmtBytes(c.bytes)}</td><td>${c.connected_at}</td></tr>`).join('');
}

/* ── Users ── */
async function loadUsers(){
try{
const users=await apiJSON('/api/links');
linksCache={};
users.forEach(u=>linksCache[u.uuid]=u);
renderUsers(users);
}catch(e){}
}
function renderUsers(users){
const tb=document.getElementById('users-table');
if(!users||users.length===0){tb.innerHTML='<tr><td colspan="5" style="text-align:center;color:var(--muted)">کاربری وجود ندارد</td></tr>';return;}
tb.innerHTML=users.map(u=>{
const pct=u.limit_bytes>0?Math.min(100,(u.used_bytes/u.limit_bytes)*100):0;
const barColor=pct<70?'var(--ok)':pct<90?'var(--warn)':'var(--danger)';
const limitText=u.limit_bytes>0?fmtBytes(u.limit_bytes):'نامحدود';
const activeConns=0;
return`<tr>
<td><strong>${u.label}</strong><br><span style="font-size:11px;color:var(--muted);font-family:monospace">${u.uuid.substring(0,8)}...</span></td>
<td><div style="display:flex;align-items:center;gap:8px"><div class="progress-wrap" style="flex:1"><div class="progress-bar" style="width:${pct}%;background:${barColor}"></div></div><span style="font-size:12px;white-space:nowrap">${fmtBytesShort(u.used_bytes)} / ${limitText}</span></div></td>
<td>${u.max_connections>0?u.max_connections:'نامحدود'}</td>
<td>${u.active?'<span style="color:var(--ok);font-weight:600">فعال</span>':'<span style="color:var(--danger);font-weight:600">غیرفعال</span>'}</td>
<td style="white-space:nowrap">
<button class="btn btn-sm btn-outline" onclick="openEditModal('${u.uuid}')">ویرایش</button>
<button class="btn btn-sm btn-outline" onclick="openLinksModal('${u.uuid}')">لینک‌ها</button>
<button class="btn btn-sm btn-danger" onclick="deleteUser('${u.uuid}')">حذف</button>
</td></tr>`;
}).join('');
}

/* ── Create User ── */
function openAddModal(){document.getElementById('modal-add').classList.add('open');}
async function createUser(){
const label=document.getElementById('add-label').value||'User';
const limit=document.getElementById('add-limit').value||'0';
const maxconn=document.getElementById('add-maxconn').value||'0';
const custom=document.getElementById('add-uuid').value;
try{
await api('/api/links',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({label,limit_gb:parseFloat(limit),max_connections:parseInt(maxconn),custom_uuid:custom})});
closeModal('modal-add');
loadUsers();
document.getElementById('add-label').value='';
document.getElementById('add-limit').value='0';
document.getElementById('add-maxconn').value='0';
document.getElementById('add-uuid').value='';
}catch(e){}
}

/* ── Edit User ── */
function openEditModal(uuid){
const u=linksCache[uuid];
if(!u)return;
document.getElementById('edit-uuid').value=uuid;
document.getElementById('edit-label').value=u.label;
document.getElementById('edit-limit-val').value=u.limit_gb||0;
document.getElementById('edit-limit-unit').value='GB';
document.getElementById('edit-add-gb').value='';
document.getElementById('edit-maxconn').value=u.max_connections;
document.getElementById('edit-active').checked=u.active;
document.getElementById('modal-edit').classList.add('open');
}
async function saveUser(){
const uuid=document.getElementById('edit-uuid').value;
const body={
label:document.getElementById('edit-label').value,
limit_value:parseFloat(document.getElementById('edit-limit-val').value||0),
limit_unit:document.getElementById('edit-limit-unit').value,
max_connections:parseInt(document.getElementById('edit-maxconn').value||0),
active:document.getElementById('edit-active').checked,
};
const addGb=parseFloat(document.getElementById('edit-add-gb').value||0);
if(addGb>0)body.add_gb=addGb;
try{
await api('/api/links/'+uuid,{method:'PATCH',headers:{'Content-Type':'application/json'},body:JSON.stringify(body)});
closeModal('modal-edit');
loadUsers();
}catch(e){}
}
async function resetUsage(){
const uuid=document.getElementById('edit-uuid').value;
try{
await api('/api/links/'+uuid,{method:'PATCH',headers:{'Content-Type':'application/json'},body:JSON.stringify({reset_usage:true})});
closeModal('modal-edit');
loadUsers();
}catch(e){}
}

/* ── Delete User ── */
async function deleteUser(uuid){
if(!confirm('آیا از حذف این کاربر اطمینان دارید؟'))return;
try{await api('/api/links/'+uuid,{method:'DELETE'});loadUsers();}catch(e){}
}

/* ── Links Modal ── */
function openLinksModal(uuid){
const u=linksCache[uuid];
if(!u)return;
document.getElementById('links-uuid').value=uuid;
document.getElementById('link-ws-text').textContent=u.links[0];
document.getElementById('link-xhttp-text').textContent=u.links[1];
document.getElementById('link-grpc-text').textContent=u.links[2];
document.getElementById('link-ws-qr').innerHTML='';
document.getElementById('link-xhttp-qr').innerHTML='';
document.getElementById('link-grpc-qr').innerHTML='';
document.getElementById('modal-links').classList.add('open');
document.querySelectorAll('.tab-btn').forEach((b,i)=>b.classList.toggle('active',i===0));
document.querySelectorAll('.link-tab').forEach((t,i)=>t.style.display=i===0?'block':'none');
}
function switchTab(btn,tabId){
btn.parentElement.querySelectorAll('.tab-btn').forEach(b=>b.classList.remove('active'));
btn.classList.add('active');
document.querySelectorAll('.link-tab').forEach(t=>t.style.display='none');
document.getElementById(tabId).style.display='block';
}
function copyLink(elId){
const text=document.getElementById(elId).textContent;
navigator.clipboard.writeText(text).then(()=>{
const btn=event.target;
const orig=btn.textContent;btn.textContent='کپی شد!';setTimeout(()=>btn.textContent=orig,1500);
});
}
function showQR(elId){
const text=document.getElementById(elId).textContent;
const qrDiv=document.getElementById(elId+'-qr');
const url='https://api.qrserver.com/v1/create-qr-code/?size=180x180&data='+encodeURIComponent(text);
qrDiv.innerHTML='<img src="'+url+'" alt="QR Code" style="border-radius:8px">';
}

/* ── Settings ── */
async function loadSettings(){
try{
const s=await apiJSON('/api/system');
document.getElementById('si-cpu').textContent=s.cpu_percent+'%';
document.getElementById('si-ram').textContent=Math.round(s.mem_used/1048576)+' / '+Math.round(s.mem_total/1048576)+' MB ('+s.mem_percent+'%)';
document.getElementById('si-uptime').textContent=s.uptime?formatUptime(s.uptime):'-';
document.getElementById('si-domain').textContent=s.domain||'-';
}catch(e){}
}
function formatUptime(sec){
const h=Math.floor(sec/3600);const m=Math.floor((sec%3600)/60);const s=Math.floor(sec%60);
return h+':'+String(m).padStart(2,'0')+':'+String(s).padStart(2,'0');
}
async function changePassword(){
const cur=document.getElementById('set-cur-pass').value;
const nw=document.getElementById('set-new-pass').value;
const msg=document.getElementById('set-pass-msg');
try{
const r=await api('/api/change-password',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({current_password:cur,new_password:nw})});
if(r.ok){msg.style.color='var(--ok)';msg.textContent='رمز عبور تغییر یافت. لطفاً دوباره وارد شوید.';setTimeout(doLogout,2000);}
else{msg.style.color='var(--danger)';msg.textContent='خطا در تغییر رمز';}
}catch(e){msg.style.color='var(--danger)';msg.textContent='خطا در ارتباط';}
}

/* ── System info refresh ── */
setInterval(async()=>{
if(currentPage==='settings'){try{await loadSettings();}catch(e){}}
},15000);

/* ── Modal Helpers ── */
function closeModal(id){document.getElementById(id).classList.remove('open');}
document.querySelectorAll('.modal-overlay').forEach(o=>{
o.addEventListener('click',function(e){if(e.target===this)this.classList.remove('open');});
});

/* ── Init ── */
checkAuth();
</script>
</body>
</html>"""


# ═══════════════════════════════════════════════════════════════════════════════
# بخش ۱۲: Admin Routes
# ═══════════════════════════════════════════════════════════════════════════════
@app.get(f"/{ADMIN_PATH}", response_class=HTMLResponse)
async def admin_index():
    return HTMLResponse(content=ADMIN_HTML)


@app.get(f"/{ADMIN_PATH}/{{rest:path}}", response_class=HTMLResponse)
async def admin_catchall(rest: str = ""):
    return HTMLResponse(content=ADMIN_HTML)


# ═══════════════════════════════════════════════════════════════════════════════
# API — System Info (for settings page)
# ═══════════════════════════════════════════════════════════════════════════════
@app.get("/api/system")
async def api_system(request: Request):
    if not await _require_auth(request):
        raise HTTPException(status_code=401)
    try:
        cpu_pct = psutil.cpu_percent(interval=0.5)
        mem = psutil.virtual_memory()
        mem_pct = mem.percent
        mem_used = mem.used
        mem_total = mem.total
    except Exception:
        cpu_pct = 0
        mem_pct = 0
        mem_used = 0
        mem_total = 0
    uptime = time.time() - stats["start_time"]
    return {
        "cpu_percent": cpu_pct,
        "mem_percent": mem_pct,
        "mem_used": mem_used,
        "mem_total": mem_total,
        "domain": get_domain(),
        "uptime": uptime,
    }


# ═══════════════════════════════════════════════════════════════════════════════
# بخش ۱۵: Main Entry
# ═══════════════════════════════════════════════════════════════════════════════
if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=PORT, no_access_log=True)
