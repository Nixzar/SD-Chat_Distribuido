"""Script de teste automatizado para o módulo de autenticação.

Este script importa o arquivo `autenticação.py` diretamente pelo caminho
e executa uma sequência de operações: registro, autenticação, emissão e
verificação de token.
"""
import importlib.util
import os
import sys


HERE = os.path.dirname(os.path.abspath(__file__))
MODULE_PATH = os.path.join(HERE, "autenticação.py")


def load_module(path: str):
    spec = importlib.util.spec_from_file_location("autenticacao_module", path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def main():
    os.environ.setdefault("AUTH_DB_PATH", os.path.join(HERE, "test_auth.db"))
    os.environ.setdefault("AUTH_SECRET", "tests-secret-key")

    if os.path.exists(os.environ["AUTH_DB_PATH"]):
        try:
            os.remove(os.environ["AUTH_DB_PATH"])
        except Exception:
            pass

    mod = load_module(MODULE_PATH)

    # Registrar
    r = mod.register_user("alice", "password123", db_path=os.environ["AUTH_DB_PATH"])
    print("register:", r)
    if not r.get("success"):
        print("Falha no registro")
        return 2

    # Autenticar
    ok = mod.authenticate_user("alice", "password123", db_path=os.environ["AUTH_DB_PATH"])
    print("authenticate:", ok)
    if not ok:
        print("Falha na autenticação")
        return 3

    # Emitir token
    secret = os.environ.get("AUTH_SECRET")
    token = mod.create_access_token({"sub": "alice"}, secret)
    print("token:", token)

    # Verificar token
    try:
        payload = mod.verify_access_token(token, secret)
        print("verify payload:", payload)
    except Exception as e:
        print("Falha na verificação do token:", e)
        return 4

    print("TESTS OK")
    return 0


if __name__ == "__main__":
    sys.exit(main())
