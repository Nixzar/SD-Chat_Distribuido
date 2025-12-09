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
        self.app.add_routes([
            web.get("/ws", self.ws_handler),
            web.get("/history/{user}" , self.history_handler),
        ])
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
                            # broadcast to all connected
                            for u, c in list(self.clients.items()):
                                try:
                                    await c.send_json(payload)
                                except Exception:
                                    LOG.exception("Erro enviando broadcast")
                            # mark delivered for all connected recipients
                            # for simplicity we won't mark delivered per user here
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


def make_app(host: str = "0.0.0.0", port: int = 8080, db_path: str = "messages.db") -> ChatServer:
    return ChatServer(host=host, port=port, db_path=db_path)
