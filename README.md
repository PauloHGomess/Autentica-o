# 🔐 Autenticação e Gerenciamento de Usuários (Flask)

## Visão Geral

Este projeto implementa uma API RESTful e um painel web simples utilizando **Flask** para demonstrar diferentes estratégias de autenticação e gerenciamento de usuários.

### Funcionalidades Chave:

  * **Autenticação Tripla:** Suporte para login via **Sessão**, **JSON Web Token (JWT)** e **Basic Authentication** na mesma rota protegida.
  * **Controle de Acesso (RBAC):** Uso da *role* (`admin` ou `user`) para restringir o acesso às rotas de gerenciamento (`/users`).
  * **Gerenciamento de Usuários (CRUD):** Funções de **C**riar, **L**istar e **D**eletar usuários via API.
  * **Logging de Segurança:** Logs detalhados de *DEBUG* para rastrear tentativas de login e emissão de tokens.

## 🛠️ Como Executar

1.  **Clone o Repositório:**

    ```bash
    git clone <repo-url>
    cd web1-auth-<seunome>
    ```

2.  **Crie e Ative o Ambiente Virtual:**

    ```bash
    python -m venv venv
    source venv/bin/activate  # Windows: .\venv\Scripts\activate
    ```

3.  **Instale as Dependências:**

    ```bash
    pip install -r requirements.txt
    ```

4.  **Configure o Ambiente:**
    Crie o arquivo **`.env`** a partir do `.env.example` e preencha o `JWT_SECRET` e o `SECRET_KEY_SESSION` com valores longos e seguros.

5.  **Inicie a Aplicação (Recomendado):**

    ```bash
    python -m src.app
    ```

O servidor estará rodando em `http://127.0.0.1:5000/`.

-----

## 🔑 Endpoints de Teste e Autenticação

Acesse `http://127.0.0.1:5000/` no navegador para testar o login por **Sessão**. Para testar o JWT e Basic Auth, use o token gerado ou as credenciais de `admin:1234` (ou a senha que você configurou no `users.json`).

| Rota | Método | Função | Permissão |
| :--- | :--- | :--- | :--- |
| `/` | `GET` | Página inicial e links. | Pública |
| `/login` | `GET`/`POST` | Formulário de autenticação. Emite **Sessão** e **JWT**. | Pública |
| `/dashboard` | `GET` | **Rota Protegida Principal.** Verifica Sessão, JWT e Basic Auth. | Autenticado (qualquer método) |
| `/logout` | `POST` | Encerra a sessão ativa. | Autenticado |
| `/users` | `GET`/`POST` | CRUD de usuários. | **Admin** |
| `/users/<id>` | `DELETE` | Remove um usuário específico. | **Admin** |

## 🐞 Logs de Segurança (DEBUG)

Para atender ao requisito de auditoria, o sistema registra logs de segurança.

  * **Ativação:** Certifique-se de que o `.env` contenha: `LOG_LEVEL=DEBUG`.
  * **Conteúdo dos Logs:** O terminal mostrará detalhes sobre **tentativas de login** (com a senha mascarada `***`), resultado de autenticação e a **emissão de JWT**.

*Exemplo de Log no Terminal:*

```
[2025-09-28 21:00:00] [DEBUG] Tentativa de login: user='admin', IP='127.0.0.1', senha='***'
[2025-09-28 21:00:01] [INFO] Acesso permitido. User: admin | Método: Session
```

-----

## 🗂️ Estrutura do Projeto

```
web1-auth-<seunome>/
├── src/
│   ├── app.py          # Lógica principal, rotas e decorators
│   ├── config.py       # Carrega variáveis de ambiente
│   ├── helper.py       # Funções de hashing e CRUD de users.json
│   ├── logger.py       # Sistema de logs condicional (DEBUG/INFO)
│   └── users.json      # Dados dos usuários (com senhas HASHED)
├── templates/
│   ├── index.html      # (Página Inicial)
│   ├── login.html      # (Formulário de Login)
│   └── dashboard.html  # (Página Protegida)
├── .env                # Variáveis de ambiente secretas
├── .gitignore
└── requirements.txt
```
