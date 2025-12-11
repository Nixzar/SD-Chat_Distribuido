"""
Módulo de autenticação simples para sistema distribuído.

Funcionalidades:
- Registro de usuário (armazenado em SQLite)
- Hash de senhas com bcrypt
- Login (verifica senha e emite JWT)
- Verificação de token JWT

Uso (CLI):
  python autenticação.py register <username>
  python autenticação.py login <username>
  python autenticação.py verify <token>

Configuração:
- Variável de ambiente AUTH_SECRET para assinar JWTs (opcional). Se não fornecida, uma chave temporária será criada e mostrada.

"""
from __future__ import annotations

import argparse
import datetime
import json
import os
import sqlite3
import sys
from typing import Optional, Dict, Any

import bcrypt
import jwt

# Configurações
DB_PATH = os.environ.get("AUTH_DB_PATH", "auth_users.db")
JWT_SECRET = os.environ.get("AUTH_SECRET")  # se None, será gerada uma chave temporária
JWT_ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 60


def init_db(db_path: str = DB_PATH) -> None:
	"""Cria a tabela de usuários se não existir."""
	with sqlite3.connect(db_path) as conn:
		cur = conn.cursor()
		cur.execute(
			"""
			CREATE TABLE IF NOT EXISTS users (
				id INTEGER PRIMARY KEY AUTOINCREMENT,
				username TEXT UNIQUE NOT NULL,
				password_hash BLOB NOT NULL,
				created_at TEXT NOT NULL
			)
			"""
		)
		conn.commit()


def _get_user_row(username: str, db_path: str = DB_PATH) -> Optional[sqlite3.Row]:
	conn = sqlite3.connect(db_path)
	conn.row_factory = sqlite3.Row
	cur = conn.cursor()
	cur.execute("SELECT * FROM users WHERE username = ?", (username,))
	row = cur.fetchone()
	conn.close()
	return row


def register_user(username: str, password: str, db_path: str = DB_PATH) -> Dict[str, Any]:
	"""Registra um novo usuário com hash da senha.

	Retorna um dicionário com sucesso True/False e mensagem.
	"""
	if not username or not password:
		return {"success": False, "message": "username e password são necessários"}

	init_db(db_path)

	existing = _get_user_row(username, db_path)
	if existing:
		return {"success": False, "message": "Usuário já existe"}

	pw_hash = bcrypt.hashpw(password.encode("utf-8"), bcrypt.gensalt())
	created = datetime.datetime.utcnow().isoformat() + "Z"

	with sqlite3.connect(db_path) as conn:
		cur = conn.cursor()
		cur.execute(
			"INSERT INTO users (username, password_hash, created_at) VALUES (?, ?, ?)",
			(username, pw_hash, created),
		)
		conn.commit()

	return {"success": True, "message": "Usuário registrado com sucesso"}


def authenticate_user(username: str, password: str, db_path: str = DB_PATH) -> bool:
	"""Verifica se o username/password combinam."""
	row = _get_user_row(username, db_path)
	if not row:
		return False
	stored_hash = row["password_hash"]
	if isinstance(stored_hash, str):
		stored_hash = stored_hash.encode("latin1")
	return bcrypt.checkpw(password.encode("utf-8"), stored_hash)


def create_access_token(data: Dict[str, Any], secret: str, expires_minutes: int = ACCESS_TOKEN_EXPIRE_MINUTES) -> str:
	to_encode = data.copy()
	expire = datetime.datetime.utcnow() + datetime.timedelta(minutes=expires_minutes)
	to_encode.update({"exp": expire, "iat": datetime.datetime.utcnow()})
	return jwt.encode(to_encode, secret, algorithm=JWT_ALGORITHM)


def verify_access_token(token: str, secret: str) -> Dict[str, Any]:
	try:
		payload = jwt.decode(token, secret, algorithms=[JWT_ALGORITHM])
		return payload
	except jwt.ExpiredSignatureError:
		raise ValueError("Token expirado")
	except jwt.DecodeError:
		raise ValueError("Token inválido")


def _ensure_secret() -> str:
	global JWT_SECRET
	if JWT_SECRET:
		return JWT_SECRET
	# gerar uma chave temporária (não segura para produção)
	JWT_SECRET = bcrypt.gensalt().decode('utf-8')
	print("Aviso: AUTH_SECRET não definido; gerando chave temporária (use variável de ambiente AUTH_SECRET para produção)")
	return JWT_SECRET


def main(argv=None):
	parser = argparse.ArgumentParser(description="CLI de autenticação simples")
	sub = parser.add_subparsers(dest="cmd")

	p_register = sub.add_parser("register", help="Register a new user")
	p_register.add_argument("username")
	p_register.add_argument("-p", "--password", help="Senha (opcional; use com cuidado, evita prompt interativo)")

	p_login = sub.add_parser("login", help="Authenticate and get token")
	p_login.add_argument("username")
	p_login.add_argument("-p", "--password", help="Senha (opcional; use com cuidado, evita prompt interativo)")

	p_verify = sub.add_parser("verify", help="Verify token")
	p_verify.add_argument("token")

	args = parser.parse_args(argv)

	if args.cmd == "register":
		if getattr(args, "password", None):
			password = args.password
		else:
			password = _prompt_password()
		out = register_user(args.username, password)
		print(json.dumps(out, ensure_ascii=False))
		return 0

	if args.cmd == "login":
		if getattr(args, "password", None):
			password = args.password
		else:
			password = _prompt_password()
		ok = authenticate_user(args.username, password)
		if not ok:
			print(json.dumps({"success": False, "message": "Credenciais inválidas"}, ensure_ascii=False))
			return 1
		secret = _ensure_secret()
		token = create_access_token({"sub": args.username}, secret)
		print(json.dumps({"success": True, "token": token}, ensure_ascii=False))
		return 0

	if args.cmd == "verify":
		secret = _ensure_secret()
		try:
			payload = verify_access_token(args.token, secret)
			print(json.dumps({"success": True, "payload": payload}, default=_json_converter, ensure_ascii=False))
			return 0
		except ValueError as e:
			print(json.dumps({"success": False, "message": str(e)}, ensure_ascii=False))
			return 1

	parser.print_help()
	return 2


def _prompt_password() -> str:
	# Tenta usar getpass em terminais interativos.
	# Se não houver tty (ex.: execução em ambiente não interativo), tenta ler a senha
	# da variável de ambiente `AUTH_PASSWORD` como fallback ou instrui o usuário
	# a usar a opção `--password`.
	import getpass

	if not sys.stdin or not sys.stdin.isatty():
		env_pw = os.environ.get("AUTH_PASSWORD")
		if env_pw:
			return env_pw
		raise RuntimeError("Entrada não interativa: forneça a senha via --password ou variavel AUTH_PASSWORD")

	try:
		return getpass.getpass("Senha: ")
	except Exception:
		# último recurso: input (menos seguro porque ecoa no terminal)
		return input("Senha: ")


def _json_converter(obj):
	if isinstance(obj, (datetime.datetime, datetime.date)):
		return obj.isoformat()
	raise TypeError("Type not serializable")


if __name__ == "__main__":
	sys.exit(main())

