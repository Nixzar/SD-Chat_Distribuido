# Sistema de Autenticação (simples)

Este repositório contém um módulo Python simples de autenticação com:

- Registro de usuários (SQLite)
- Hashing de senhas usando bcrypt
- Emissão e verificação de tokens JWT (PyJWT)

Como usar (exemplo):

1. Instale dependências

```powershell
pip install -r requirements.txt
```

2. Registrar usuário

```powershell
python autenticação.py register meu_usuario
# será solicitado a senha
```

3. Logar e obter token

```powershell
python autenticação.py login meu_usuario
```

4. Verificar token

```powershell
python autenticação.py verify <token>
```

Configuração adicional:

- Variável de ambiente `AUTH_SECRET` para definir a chave usada para assinar JWTs (recomendada para produção).
- Variável de ambiente `AUTH_DB_PATH` para alterar o arquivo do banco de dados SQLite.
