"""Utilitário para gerenciar o banco de autenticação (users SQLite).

Permite listar usuários, deletar um usuário e resetar (apagar) o banco.

Uso:
  python tools/manage_auth_db.py --db auth_users.db list
  python tools/manage_auth_db.py --db auth_users.db delete --username alice
  python tools/manage_auth_db.py --db auth_users.db reset --yes

O caminho do DB padrão é lido da variável de ambiente `AUTH_DB_PATH` ou
usa `auth_users.db` no diretório do projeto.
"""
from __future__ import annotations

import argparse
import os
import shutil
import sqlite3
import sys
from typing import Optional


def get_db_path(db: Optional[str]) -> str:
    if db:
        return db
    return os.environ.get("AUTH_DB_PATH", "auth_users.db")


def list_users(db_path: str) -> None:
    if not os.path.exists(db_path):
        print("DB não encontrado:", db_path)
        return
    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row
    cur = conn.cursor()
    cur.execute("SELECT id, username, created_at FROM users ORDER BY id")
    rows = cur.fetchall()
    if not rows:
        print("Nenhum usuário encontrado")
    else:
        for r in rows:
            print(f"{r['id']:3d}  {r['username']:20s}  {r['created_at']}")
    conn.close()


def delete_user(db_path: str, username: str) -> None:
    if not os.path.exists(db_path):
        print("DB não encontrado:", db_path)
        return
    confirm = input(f"Confirma exclusão do usuário '{username}' do DB {db_path}? [y/N]: ")
    if confirm.lower() != 'y':
        print("Operação cancelada")
        return
    conn = sqlite3.connect(db_path)
    cur = conn.cursor()
    cur.execute("DELETE FROM users WHERE username = ?", (username,))
    conn.commit()
    deleted = cur.rowcount
    conn.close()
    print(f"Registros deletados: {deleted}")


def reset_db(db_path: str, yes: bool = False) -> None:
    if os.path.exists(db_path):
        if not yes:
            confirm = input(f"Isto apagará o arquivo {db_path} (perderá todos os usuários). Confirmar? [y/N]: ")
            if confirm.lower() != 'y':
                print("Operação cancelada")
                return
        # make backup
        bak = db_path + ".bak"
        shutil.copy2(db_path, bak)
        os.remove(db_path)
        print(f"DB original movido para backup: {bak}")
    else:
        print("DB não existe; nada a apagar")


def main(argv=None):
    p = argparse.ArgumentParser(description="Gerenciar auth DB (listar, deletar, resetar)")
    p.add_argument("--db", help="Caminho do DB (ou use AUTH_DB_PATH env)")
    sub = p.add_subparsers(dest="cmd")

    sub.add_parser("list", help="Listar usuários")

    pd = sub.add_parser("delete", help="Deletar usuário")
    pd.add_argument("--username", required=True)

    pr = sub.add_parser("reset", help="Resetar (apagar) o DB; cria backup .bak")
    pr.add_argument("--yes", action="store_true", help="Não pedir confirmação")

    args = p.parse_args(argv)
    db_path = get_db_path(args.db)

    if args.cmd == 'list':
        list_users(db_path)
    elif args.cmd == 'delete':
        delete_user(db_path, args.username)
    elif args.cmd == 'reset':
        reset_db(db_path, yes=args.yes)
    else:
        p.print_help()


if __name__ == '__main__':
    main()
