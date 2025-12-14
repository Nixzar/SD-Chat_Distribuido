"""
Servidor de chat WebSocket usando aiohttp.

Funcionalidades:
- Autenticação via token JWT (integra com o módulo de autenticação do projeto)
- Armazenamento de mensagens em SQLite (usa MessageStore em `db.py`)
- Roteamento WebSocket em `/ws` e endpoint `/history` para recuperar histórico

Formato de mensagens (JSON):
{ "type": "message", "to": "recipient_username" | "broadcast", "content": "..." }

Ao conectar, o cliente deve enviar o token como query param `?token=...` ou no header `Authorization: Bearer ...`.
"""
from __future__ import annotations

import asyncio
import json
import logging
from typing import Dict, Any, Optional

from aiohttp import web, WSCloseCode

from db import MessageStore

import importlib
import importlib.util
import pathlib
import sys
import os

LOG = logging.getLogger("chat")


def load_auth_module():
    # Procurar um arquivo de autenticação no diretório atual começando por 'autent'
    cwd = pathlib.Path(".")
    for p in cwd.glob("autent*.py"):
        try:
            spec = importlib.util.spec_from_file_location("auth_module", str(p))
            mod = importlib.util.module_from_spec(spec)
            sys.modules["auth_module"] = mod
            spec.loader.exec_module(mod)  # type: ignore
            return mod
        except Exception:
            continue

    # fallback: tentar importar nomes sem acento comuns
    candidates = ["autenticacao", "autentificacao", "auth", "authentication"]
    for name in candidates:
        try:
            return importlib.import_module(name)
        except Exception:
            continue

    raise ImportError("Módulo de autenticação não encontrado. Certifique-se de que o arquivo de autenticação existe no diretório do projeto.")


class ChatServer:
    def __init__(self, host: str = "0.0.0.0", port: int = 8080, db_path: str = "messages.db"):
        self.host = host
        self.port = port
        self.app = web.Application()
        # API routes
        self.app.add_routes([
            web.get("/ws", self.ws_handler),
            web.get("/history/{user}", self.history_handler),
            web.get("/api/users", self.users_handler),
            web.get("/history", self.history_all_handler),
            web.post("/api/login", self.login_handler),
            web.post("/api/register", self.register_handler),
        ])

        # static frontend files (served under /static) and index at /
        static_path = pathlib.Path(__file__).parent / "frontend"
        # index route
        self.app.router.add_get("/", self.index_handler)
        # static assets
        if static_path.exists():
            self.app.router.add_static("/static/", str(static_path), show_index=True)
        self.store = MessageStore(db_path)
        self.clients: Dict[str, web.WebSocketResponse] = {}
        self.auth = load_auth_module()

    async def start(self):
        await self.store.init_db()
        runner = web.AppRunner(self.app)
        await runner.setup()
        site = web.TCPSite(runner, self.host, self.port)
        LOG.info(f"Starting chat server on {self.host}:{self.port}")
        await site.start()
        # keep running
        while True:
            await asyncio.sleep(3600)

    def _get_token_from_request(self, request: web.Request) -> Optional[str]:
        # check query param
        token = request.query.get("token")
        if token:
            return token
        # check Authorization header
        authh = request.headers.get("Authorization")
        if authh and authh.lower().startswith("bearer "):
            return authh.split(" ", 1)[1]
        return None

    def _verify_token(self, token: str) -> str:
        secret = self.auth._ensure_secret()
        payload = self.auth.verify_access_token(token, secret)
        sub = payload.get("sub")
        if not sub:
            raise web.HTTPUnauthorized(reason="Token sem 'sub'")
        return sub

    async def ws_handler(self, request: web.Request) -> web.WebSocketResponse:
        token = self._get_token_from_request(request)
        if not token:
            raise web.HTTPUnauthorized(text="Token não fornecido")
        try:
            username = self._verify_token(token)
        except Exception as e:
            raise web.HTTPUnauthorized(text=str(e))

        ws = web.WebSocketResponse()
        await ws.prepare(request)
        # register client
        self.clients[username] = ws
        LOG.info(f"User connected: {username}")

        # deliver undelivered messages
        undelivered = await self.store.get_undelivered(username)
        for msg in undelivered:
            await ws.send_json({"type": "message", "id": msg["id"], "sender": msg["sender"], "content": msg["content"], "timestamp": msg["timestamp"]})
            await self.store.mark_delivered(msg["id"])

        try:
            async for msg in ws:
                if msg.type == web.WSMsgType.TEXT:
                    try:
                        data = json.loads(msg.data)
                    except Exception:
                        await ws.send_json({"type": "error", "message": "JSON inválido"})
                        continue

                    if data.get("type") == "message":
                        to = data.get("to")
                        content = data.get("content")
                        if not to or not content:
                            await ws.send_json({"type": "error", "message": "Mensagem precisa de 'to' e 'content'"})
                            continue

                        # store message
                        msg_id = await self.store.save_message(username, to, content)
                        payload = {"type": "message", "id": msg_id, "sender": username, "content": content}

                        if to == "broadcast":
                            # persist per-recipient so offline users will receive when reconnecting
                            # fetch all registered users from auth module
                            db_path = os.environ.get("AUTH_DB_PATH")
                            try:
                                if db_path:
                                    all_users = self.auth.list_users(db_path=db_path)
                                else:
                                    all_users = self.auth.list_users()
                            except Exception:
                                # fallback: deliver to currently connected clients only
                                all_users = list(self.clients.keys())

                            for recipient in all_users:
                                if recipient == username:
                                    continue
                                try:
                                    # save a per-recipient message
                                    msg_id = await self.store.save_message(username, recipient, content)
                                except Exception:
                                    LOG.exception("Erro salvando mensagem de broadcast para %s", recipient)
                                    continue

                                # if recipient is connected, send immediately and mark delivered
                                recipient_ws = self.clients.get(recipient)
                                if recipient_ws:
                                    try:
                                        await recipient_ws.send_json({"type": "message", "id": msg_id, "sender": username, "content": content})
                                        await self.store.mark_delivered(msg_id)
                                    except Exception:
                                        LOG.exception("Erro enviando broadcast para usuário online %s", recipient)
                        else:
                            recipient_ws = self.clients.get(to)
                            if recipient_ws:
                                try:
                                    await recipient_ws.send_json(payload)
                                    # mark delivered
                                    await self.store.mark_delivered(msg_id)
                                except Exception:
                                    LOG.exception("Erro enviando para usuário online")
                        # ack sender
                        await ws.send_json({"type": "ack", "id": msg_id})

                elif msg.type == web.WSMsgType.ERROR:
                    LOG.error(f"WebSocket connection closed with exception {ws.exception()}")

        finally:
            # cleanup
            if username in self.clients and self.clients[username] is ws:
                del self.clients[username]
            LOG.info(f"User disconnected: {username}")

        return ws

    async def login_handler(self, request: web.Request) -> web.Response:
        try:
            data = await request.json()
        except Exception:
            return web.json_response({"success": False, "message": "JSON inválido"}, status=400)

        username = data.get("username")
        password = data.get("password")
        if not username or not password:
            return web.json_response({"success": False, "message": "username e password necessários"}, status=400)

        # use auth module to verify
        db_path = os.environ.get("AUTH_DB_PATH")
        ok = False
        try:
            if db_path:
                ok = self.auth.authenticate_user(username, password, db_path=db_path)
            else:
                ok = self.auth.authenticate_user(username, password)
        except Exception:
            ok = False

        if not ok:
            return web.json_response({"success": False, "message": "Credenciais inválidas"}, status=401)

        secret = self.auth._ensure_secret()
        token = self.auth.create_access_token({"sub": username}, secret)
        return web.json_response({"success": True, "token": token})

    async def register_handler(self, request: web.Request) -> web.Response:
        try:
            data = await request.json()
        except Exception:
            return web.json_response({"success": False, "message": "JSON inválido"}, status=400)

        username = data.get("username")
        password = data.get("password")
        if not username or not password:
            return web.json_response({"success": False, "message": "username e password necessários"}, status=400)

        db_path = os.environ.get("AUTH_DB_PATH")
        try:
            if db_path:
                result = self.auth.register_user(username, password, db_path=db_path)
            else:
                result = self.auth.register_user(username, password)
        except Exception as e:
            return web.json_response({"success": False, "message": str(e)}, status=500)

        if not result.get("success"):
            return web.json_response(result, status=409)

        return web.json_response({"success": True, "message": "Usuário registrado com sucesso"})

    async def index_handler(self, request: web.Request) -> web.Response:
        root = pathlib.Path(__file__).parent / "frontend"
        index_file = root / "index.html"
        if index_file.exists():
            return web.FileResponse(str(index_file))
        return web.Response(text="Frontend não encontrado", status=404)

    async def history_handler(self, request: web.Request) -> web.Response:
        # protected endpoint: token must be provided
        token = self._get_token_from_request(request)
        if not token:
            raise web.HTTPUnauthorized(text="Token não fornecido")
        try:
            username = self._verify_token(token)
        except Exception as e:
            raise web.HTTPUnauthorized(text=str(e))

        other = request.match_info.get("user")
        history = await self.store.get_history(username, other)
        return web.json_response({"success": True, "history": history})

    async def history_all_handler(self, request: web.Request) -> web.Response:
        # returns all messages involving the authenticated user
        token = self._get_token_from_request(request)
        if not token:
            raise web.HTTPUnauthorized(text="Token não fornecido")
        try:
            username = self._verify_token(token)
        except Exception as e:
            raise web.HTTPUnauthorized(text=str(e))

        history = await self.store.get_history(username)
        return web.json_response({"success": True, "history": history})

    async def users_handler(self, request: web.Request) -> web.Response:
        # return list of registered usernames
        db_path = os.environ.get("AUTH_DB_PATH")
        try:
            if db_path:
                users = self.auth.list_users(db_path=db_path)
            else:
                users = self.auth.list_users()
        except Exception:
            users = []
        # include broadcast option
        users_sorted = sorted(users)
        return web.json_response({"success": True, "users": ["broadcast"] + users_sorted})


def make_app(host: str = "0.0.0.0", port: int = 8080, db_path: str = "messages.db") -> ChatServer:
    return ChatServer(host=host, port=port, db_path=db_path)
