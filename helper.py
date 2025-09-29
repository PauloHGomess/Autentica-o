# src/helper.py

import json
import os
import hashlib

# Define o caminho para o arquivo de dados
USER_FILE = "src/users.json"

# --- FUNÇÕES DE HASHING E VERIFICAÇÃO SIMPLES ---

def simple_sha256_hash(password):
    """Gera um hash SHA256 simples a partir da senha."""
    return hashlib.sha256(password.encode('utf-8')).hexdigest()

def verify_password(stored_password_in_db, input_password):
    """Verifica se a senha de entrada corresponde à senha em texto claro (para o login inicial)."""
    # A verificação na rota /login usa essa função para comparar o texto claro.
    return stored_password_in_db == input_password

# --- FUNÇÕES DE GERENCIAMENTO DE ARQUIVOS (CRUD) ---

def load_users():
    """Lê e retorna a lista de usuários do arquivo JSON."""
    if not os.path.exists(USER_FILE):
        return []
    try:
        with open(USER_FILE, 'r', encoding='utf-8') as f:
            return json.load(f)
    except json.JSONDecodeError:
        return []

def save_users(users_list):
    """Salva a lista de usuários de volta no arquivo JSON."""
    with open(USER_FILE, 'w', encoding='utf-8') as f:
        json.dump(users_list, f, indent=2)

def find_user(username):
    """Busca um usuário pelo username e retorna o registro."""
    users = load_users()
    for user in users:
        if user["username"] == username:
            return user
    return None

def add_user(username, password, role="user"):
    """Adiciona um novo usuário ao sistema com hash SHA256."""
    if find_user(username):
        return None # Usuário já existe
    
    users = load_users()
    new_id = users[-1]["id"] + 1 if users else 1
    
    # Hashing OBRIGATÓRIO da senha (para a nova entrada)
    password_hash = simple_sha256_hash(password)
    
    new_user = {
        "id": new_id,
        "username": username,
        "password_hash": password_hash, # Salva o hash (melhor prática)
        "role": role
    }
    
    # ⚠️ Importante: Para o CRUD, a estrutura final DEVE ter 'password_hash', 
    #                e não 'password'. O código assume que após o login,
    #                o users.json será corrigido para usar hashes.
    
    users.append(new_user)
    save_users(users)
    return new_user

# Exporta a função de hash simples para o app.py (para o CRUD)
generate_password_hash = simple_sha256_hash