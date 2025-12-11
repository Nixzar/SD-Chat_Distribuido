# SD-Chat_Distribuido — Chat distribuído (exemplo)

Este repositório contém um exemplo simples de sistema de mensagens para um sistema distribuído.

Principais arquivos:

- `autenticação.py`: Módulo de autenticação (registro, hash de senha, JWT).
- `db.py`: Armazenamento de mensagens (assíncrono, `aiosqlite`).
- `chat.py`: Servidor WebSocket (`aiohttp`) com lógica de envio/recebimento/transmissão.
- `run_chat.py`: Entrypoint para executar o servidor de chat.
- `test_auth.py`: Script de teste para o módulo de autenticação.
- `tests/test_chat.py`: Testes assíncronos para o chat (mensagens online/offline).

Requisitos

- Python 3.8+ (testado com 3.13 no ambiente de desenvolvimento)
- Dependências listadas em `requirements.txt`.

Instalação

No PowerShell (Windows):

```powershell
C:/Python313/python.exe -m pip install -r requirements.txt
```

Executando o servidor

1. Defina a chave JWT (opcional, útil para reproduzir tokens):

```powershell
setx AUTH_SECRET "uma-chave-secreta-teste" /M
$env:AUTH_SECRET = "uma-chave-secreta-teste"
```

2. Inicie o servidor:

```powershell
C:/Python313/python.exe run_chat.py
```

Obtendo um token (CLI de autenticação)

1. Registrar um usuário:

```powershell
C:/Python313/python.exe autenticação.py register alice
# digite a senha quando solicitado
```

Você também pode evitar o prompt interativo passando a senha diretamente (útil em scripts ou ambientes sem TTY):

```powershell
C:/Python313/python.exe autenticação.py register alice --password "minhaSenhaSegura"
```

Ou definindo a variável de ambiente temporariamente:

```powershell
$env:AUTH_PASSWORD = 'minhaSenhaSegura'
C:/Python313/python.exe autenticação.py register alice
```

2. Fazer login para obter token:

```powershell
C:/Python313/python.exe autenticação.py login alice
# imprime JSON com campo "token"
```

Exemplos de uso (WebSocket)

- Conectar-se (query string): `ws://127.0.0.1:8080/ws?token=<TOKEN>`
- Enviar mensagem privada:

```json
{ "type": "message", "to": "bob", "content": "Olá Bob" }
```

- Enviar broadcast:

```json
{ "type": "message", "to": "broadcast", "content": "Olá a todos" }
```

- Endpoints HTTP:
  - `GET /history/{user}?token=<TOKEN>` — retorna histórico entre requester e `{user}`.

Testes

- Teste de autenticação (script):

```powershell
C:/Python313/python.exe test_auth.py
```

- Testes do chat (pytest):

```powershell
C:/Python313/python.exe -m pytest -q
```

Observações e recomendações

- Em produção, use uma chave JWT robusta e TLS (`wss://`) para proteger conexões WebSocket.
- O estado de clientes é mantido em memória — para múltiplas instâncias, adicione um broker/pubsub (ex.: Redis) e persista entrega/ack centralmente.
- Para testes e desenvolvimento, os DBs usados por `autenticação.py` e `db.py` são arquivos SQLite locais.

Contribuições

Se quiser que eu adicione testes adicionais, melhorias de segurança ou integração com um broker, diga qual componente prefere que eu implemente a seguir.
# SD-Chat_Distribuido
Trabalho final da matéria de Sistemas Distribuídos, com o objetivo de fazer um Sistema de Chat Distribuído 
