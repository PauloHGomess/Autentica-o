# src/logger.py

import logging
# LINHA CORRIGIDA
from src.config import CONFIG # Importa a configuração do .env

# Obtém o nível de log do CONFIG, com INFO como padrão seguro
LOG_LEVEL = CONFIG.get("LOG_LEVEL", "INFO")

# Configura o logger
logging.basicConfig(level=getattr(logging, LOG_LEVEL.upper(), logging.INFO),
                    format='[%(asctime)s] [%(levelname)s] %(message)s',
                    datefmt='%Y-%m-%d %H:%M:%S')

def log_debug(message):
    """Loga a mensagem se LOG_LEVEL for DEBUG."""
    logging.debug(message)

def log_info(message):
    """Loga a mensagem de nível INFO."""
    logging.info(message)
    
def log_error(message):
    """Loga a mensagem de erro."""
    logging.error(message)