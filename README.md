# FastDelta

FastDelta é uma biblioteca de autenticação OIDC/OAuth2 nativa para FastAPI, focada em segurança, alta performance e escalabilidade. Ela implementa o fluxo Authorization Code com PKCE e armazena o estado das sessões utilizando Redis.

## Funcionalidades Principais

- Autenticação OAuth2 / OpenID Connect (Authorization Code + PKCE)
- Gerenciamento de Sessão Stateful distribuído com Redis
- Renovação automática de Tokens (Refresh Tokens) blindada contra *race conditions*
- Injeção de dependências nativa para FastAPI (`Depends`)

## Instalação

```bash
pip install fastdelta
```

## Configuração e Inicialização

Crie as configurações da sua aplicação e inicie a instância principal da biblioteca acoplando sua conexão do Redis.

```python
import redis.asyncio as redis
from fastapi import FastAPI
from fastdelta import FastDelta, DeltaSettings, RedisSessionStore


settings = DeltaSettings(
    client_id="seu-client-id",
    client_secret="seu-client-secret",
    redirect_uri="https://sua-api.com/auth/callback",
    token_endpoint="https://idp.empresa.com/token",
    authorization_endpoint="https://idp.empresa.com/auth",
    jwks_endpoint="https://idp.empresa.com/certs",
    scopes="openid profile email",
    session_ttl_seconds=3600,
    issuer="https://idp.empresa.com",
    audience="seu-client-id"
)

redis_client = redis.Redis.from_url("redis://localhost:6379/0", decode_responses=True)
session_store = RedisSessionStore(redis_client=redis_client)

fast_delta = FastDelta(
    settings=settings,
    redis_client=redis_client,
    session_store=session_store
)

app = FastAPI()
```

## Criando as Rotas de Autenticação

Para o fluxo funcionar, exponha as rotas de *login*, *callback* e *logout* na sua aplicação FastAPI.

```python
from fastapi import Request, Response

@app.get("/auth/login")
async def login():
    return await fast_delta.login()


@app.get("/auth/callback")
async def callback(request: Request, response: Response):
    return await fast_delta.callback(request, response)


@app.post("/auth/logout")
async def logout(request: Request, response: Response):
    await fast_delta.logout(request, response)
    return {"status": "deslogado"}
```

## Protegendo Suas Rotas (Uso Básico)

A biblioteca exporta atalhos nativos para proteger rotas usando injeção de dependências. A dependência `fast_delta.require_session` garante que apenas usuários com uma sessão válida acessem a rota, retornando `HTTP 401` caso contrário.

```python
from fastapi import Depends
from fastdelta.core.models import DeltaSession

@app.get("/api/recurso-protegido")
async def buscar_recurso(session: DeltaSession = Depends(fast_delta.require_session)):
    return {
        "usuario": session.user_info.sub,
        "email": session.user_info.email,
        "token": session.access_token
    }
```

## Uso Opcional da Sessão

Em rotas onde a autenticação não é obrigatória, mas altera o comportamento do sistema caso exista (como exibir o perfil do usuário ou a página inicial padrão), utilize o método `get_session`.

```python
@app.get("/api/vitrine")
async def vitrine(session: DeltaSession | None = Depends(fast_delta.get_session)):
    if session:
        return {"dados": "Vitrine Personalizada"}
    return {"dados": "Vitrine Genérica"}
```