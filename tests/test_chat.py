import asyncio
import importlib.util
import os
import tempfile
import pathlib

import pytest
from aiohttp import web
from aiohttp.test_utils import TestServer, TestClient

from chat import ChatServer


HERE = pathlib.Path(__file__).resolve().parent.parent
AUTH_PATH = HERE / "autenticação.py"


def load_auth_module(path: str):
    spec = importlib.util.spec_from_file_location("autenticacao_module", path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


@pytest.mark.asyncio
async def test_message_delivery_and_offline_storage(tmp_path, aiohttp_unused_port):
    # prepare temp DBs and env
    auth_db = str(tmp_path / "auth_test.db")
    messages_db = str(tmp_path / "messages_test.db")
    os.environ.setdefault("AUTH_SECRET", "tests-secret-key")
    os.environ.setdefault("AUTH_DB_PATH", auth_db)

    auth = load_auth_module(str(AUTH_PATH))

    # register users
    r1 = auth.register_user("alice", "password123", db_path=auth_db)
    r2 = auth.register_user("bob", "password456", db_path=auth_db)
    assert r1.get("success") and r2.get("success")

    secret = os.environ.get("AUTH_SECRET")
    token_alice = auth.create_access_token({"sub": "alice"}, secret)
    token_bob = auth.create_access_token({"sub": "bob"}, secret)

    # create chat server app
    server = ChatServer(host="127.0.0.1", port=0, db_path=messages_db)
    await server.store.init_db()

    test_server = TestServer(server.app)
    await test_server.start_server()
    client_alice = TestClient(test_server)
    client_bob = TestClient(test_server)
    await client_alice.start_server()
    await client_bob.start_server()

    # connect both
    ws_alice = await client_alice.ws_connect(f"/ws?token={token_alice}")
    ws_bob = await client_bob.ws_connect(f"/ws?token={token_bob}")

    # alice sends message to bob
    await ws_alice.send_json({"type": "message", "to": "bob", "content": "Hello Bob"})

    # bob should receive it
    msg = await ws_bob.receive_json()
    assert msg["type"] == "message"
    assert msg["sender"] == "alice"
    assert msg["content"] == "Hello Bob"

    # alice should receive ack
    ack = await ws_alice.receive_json()
    assert ack["type"] == "ack"

    # Now test offline storage: disconnect bob
    await ws_bob.close()

    # alice sends message while bob offline
    await ws_alice.send_json({"type": "message", "to": "bob", "content": "Are you there?"})
    ack2 = await ws_alice.receive_json()
    assert ack2["type"] == "ack"

    # reconnect bob and he should receive undelivered
    ws_bob2 = await client_bob.ws_connect(f"/ws?token={token_bob}")
    undelivered = await ws_bob2.receive_json()
    assert undelivered["type"] == "message"
    assert undelivered["sender"] == "alice"
    assert undelivered["content"] in ("Are you there?", "Hello Bob")

    # cleanup
    await ws_alice.close()
    await ws_bob2.close()
    await client_alice.close()
    await client_bob.close()
    await test_server.close()
