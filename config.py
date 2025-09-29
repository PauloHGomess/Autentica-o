# src/config.py

import os
from dotenv import load_dotenv

# Carrega as variáveis de ambiente do arquivo .env
load_dotenv()

# --- CONFIGURAÇÕES DE SEGURANÇA E AMBIENTE ---
# Nível de Log
LOG_LEVEL = os.getenv("LOG_LEVEL", "INFO")

# JWT
JWT_SECRET = os.getenv("JWT_SECRET", "troque-este-segredo-default-inseguro")
try:
    # Garante que o tempo de expiração seja um número inteiro
    JWT_EXPIRES_MIN = int(os.getenv("JWT_EXPIRES_MIN", 15))
except ValueError:
    JWT_EXPIRES_MIN = 15 # Valor padrão em caso de erro

# Chave de Sessão do Flask (Usada pelo app.secret_key)
SECRET_KEY_SESSION = os.getenv("SECRET_KEY_SESSION", "esta-chave-da-sessao-deve-ser-longa-e-secreta")

# Dicionário de configuração para fácil acesso em outros módulos
CONFIG = {
    "LOG_LEVEL": LOG_LEVEL,
    "JWT_SECRET": JWT_SECRET,
    "JWT_EXPIRES_MIN": JWT_EXPIRES_MIN,
    "SECRET_KEY_SESSION": SECRET_KEY_SESSION
}