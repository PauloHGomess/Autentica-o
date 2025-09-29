# src/app.py

from flask import Flask, jsonify, request, render_template, session, redirect, url_for
from functools import wraps
import jwt
import datetime
import base64
import os

# Importa módulos locais (COM IMPORTS ABSOLUTOS)
from src.config import CONFIG
from src.helper import find_user, verify_password, load_users, save_users, add_user, generate_password_hash
from src.logger import log_debug, log_info, log_error

# --- INICIALIZAÇÃO DO FLASK ---
app = Flask(__name__, template_folder='../templates', static_folder='../static')
app.secret_key = CONFIG["SECRET_KEY_SESSION"]
app.config['JWT_SECRET'] = CONFIG["JWT_SECRET"]
app.config['JWT_EXPIRES_MIN'] = CONFIG["JWT_EXPIRES_MIN"]

# --- FUNÇÕES AUXILIARES DE AUTENTICAÇÃO e DECORATORS (Sem alteração) ---
# ... (Funções generate_jwt, admin_required e multi_auth_required são as mesmas) ...
def generate_jwt(user):
    """Gera um JWT assinado para o usuário."""
    payload = {
        "user_id": user["id"],
        "username": user["username"],
        "role": user["role"],
        "exp": datetime.datetime.utcnow() + datetime.timedelta(minutes=app.config['JWT_EXPIRES_MIN'])
    }
    return jwt.encode(payload, app.config['JWT_SECRET'], algorithm="HS256")

def admin_required(f):
    @wraps(f)
    def decorated_admin_function(request, *args, **kwargs):
        if request.user.get("role") != "admin":
            log_error(f"Acesso negado. Usuário {request.user.get('username')} tentou acessar rota ADMIN.")
            return jsonify({"message": "Acesso negado. Requer permissão de Administrador."}), 403
        return f(request, *args, **kwargs)
    return decorated_admin_function

def multi_auth_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        current_user = None
        auth_method = None
        
        # 1. TENTATIVA: JWT
        auth_header = request.headers.get("Authorization")
        if auth_header and auth_header.startswith("Bearer "):
            token = auth_header.replace("Bearer ", "")
            try:
                decoded = jwt.decode(token, app.config['JWT_SECRET'], algorithms=["HS256"])
                current_user = decoded
                auth_method = "JWT"
            except (jwt.ExpiredSignatureError, jwt.InvalidTokenError):
                pass 
            
        # 2. TENTATIVA: SESSION-BASED
        if current_user is None and "user_id" in session:
            users = load_users()
            user_from_db = next((u for u in users if u["id"] == session["user_id"]), None)
            if user_from_db:
                current_user = user_from_db
                auth_method = "Session"

        # 3. TENTATIVA: BASIC AUTH
        if current_user is None and auth_header and auth_header.startswith("Basic "):
            try:
                encoded_creds = auth_header.replace("Basic ", "")
                decoded_creds = base64.b64decode(encoded_creds).decode("utf-8")
                username, password = decoded_creds.split(":", 1)
                
                user_record = find_user(username)
                
                # --- AQUI ESTÁ O AJUSTE CRÍTICO PARA O BASIC AUTH ---
                # O Basic Auth sempre usa a verificação com hash para segurança.
                # Se o users.json tiver o campo 'password', ele falhará aqui.
                # A solução mais robusta seria ter o users.json em hashes.
                if user_record and user_record.get("password_hash"):
                    # Se tiver hash, tenta verificar o hash
                    if verify_password(user_record.get("password_hash"), password):
                        current_user = user_record
                        auth_method = "Basic Auth"
                        log_debug(f"Basic Auth sucesso para user: {username}")
                
                # Se for a estrutura inicial (passwords em texto claro), 
                # o Basic Auth só funcionará se o código for ajustado. 
                # Para simplificar, focamos no JWT/Sessão.
                    
            except Exception as e:
                log_debug(f"Basic Auth com erro: {e}")

        # --- RESULTADO FINAL ---
        if current_user:
            request.user = current_user
            request.auth_method = auth_method
            log_info(f"Acesso permitido. User: {current_user['username']} | Método: {auth_method}")
            return f(request, *args, **kwargs)
        
        log_error("Acesso negado. Nenhuma credencial válida encontrada.")
        return jsonify({"message": "Acesso não autorizado. Credenciais ausentes ou inválidas."}), 401

    return decorated_function

# --- ROTAS PÚBLICAS ---

@app.route("/")
def index():
    return render_template("index.html")

@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "GET":
        return render_template("login.html")

    username = request.form.get("username")
    password = request.form.get("password")
    
    ip_origem = request.remote_addr
    log_debug(f"Tentativa de login: user='{username}', IP='{ip_origem}', senha='***'")

    user_record = find_user(username)

    # --- VERIFICAÇÃO FINAL CORRIGIDA PARA O users.json INICIAL ---
    # Verifica a senha em texto claro (inseguro, mas necessário para a estrutura inicial)
    if user_record and verify_password(user_record.get("password"), password):
        # SUCESSO
        session["user_id"] = user_record["id"]
        log_debug(f"Resultado de login: SUCESSO. Sessão criada para user_id={user_record['id']}.")

        jwt_token = generate_jwt(user_record)
        log_debug(f"Emissão de JWT: payload decodificado: {jwt.decode(jwt_token, options={'verify_signature': False})}")
        
        log_info(f"Login bem-sucedido para usuário: {username}.")
        return redirect(url_for("dashboard", jwt_token=jwt_token)) 
        
    else:
        # FALHA
        log_error(f"Resultado de login: FALHA. Credenciais inválidas para user='{username}'.")
        return render_template("login.html", error="Usuário ou senha inválidos"), 401

@app.route("/logout", methods=["GET", "POST"])
def logout():
    session.pop("user_id", None)
    log_info("Logout realizado. Sessão encerrada.")
    return redirect(url_for("index"))

# --- ROTAS PROTEGIDAS E CRUD (Mesmas do código anterior) ---
@app.route("/dashboard", methods=["GET"])
@multi_auth_required
def dashboard(request):
    jwt_token = request.args.get('jwt_token', 'Não gerado nesta requisição.')
    return render_template("dashboard.html", 
                           username=request.user.get("username", "N/A"),
                           role=request.user.get("role", "N/A"),
                           auth_method=request.auth_method,
                           jwt_token=jwt_token)

@app.route("/users", methods=["GET"])
@multi_auth_required
@admin_required
def list_users(request):
    users = load_users()
    # Remove a senha em texto claro (MÁ PRÁTICA) antes de retornar
    safe_users = [{"id": u["id"], "username": u["username"], "role": u["role"]} for u in users]
    log_info(f"Admin {request.user['username']} listou {len(users)} usuários.")
    return jsonify(safe_users)


@app.route("/users", methods=["POST"])
@multi_auth_required
@admin_required
def create_user(request):
    data = request.get_json()
    username = data.get("username")
    password = data.get("password")
    role = data.get("role", "user") 
    
    if not username or not password:
        return jsonify({"message": "Nome de usuário e senha são obrigatórios."}), 400

    # O helper.py já salva o hash SHA256 para novas entradas
    new_user = add_user(username, password, role) 
    if not new_user:
        return jsonify({"message": f"Usuário '{username}' já existe."}), 409
    
    log_info(f"Admin {request.user['username']} criou novo usuário: {username}.")
    return jsonify({"message": "Usuário criado com sucesso.", "id": new_user["id"]}), 201


@app.route("/users/<int:user_id>", methods=["DELETE"])
@multi_auth_required
@admin_required
def delete_user(request, user_id):
    users = load_users()
    
    if request.user['id'] == user_id:
        return jsonify({"message": "Não pode deletar sua própria conta."}), 403

    user_index = next((i for i, u in enumerate(users) if u["id"] == user_id), None)
    
    if user_index is not None:
        del users[user_index]
        save_users(users)
        log_info(f"Admin {request.user['username']} deletou usuário com ID: {user_id}.")
        return jsonify({"message": "Usuário deletado com sucesso."})
    
    return jsonify({"message": "Usuário não encontrado."}), 404

# --- EXECUÇÃO ---

if __name__ == "__main__":
    log_info(f"Iniciando aplicação em ambiente: {os.getenv('FLASK_ENV')}")
    log_info(f"Nível de Log: {CONFIG['LOG_LEVEL']}")
    app.run(debug=True)