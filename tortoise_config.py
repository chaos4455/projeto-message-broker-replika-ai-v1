"""
Configuração do Tortoise ORM para o Message Broker.
Autor: Elias Andrade
Data: 2024-03-19
Versão: 1.0.0
"""

from typing import List

TORTOISE_ORM = {
    "connections": {
        "default": "sqlite://db.sqlite3"
    },
    "apps": {
        "models": {
            "models": ["message_broker_v1"],  # Nome do módulo onde estão os modelos
            "default_connection": "default",
        }
    },
    "use_tz": False,
    "timezone": "America/Sao_Paulo"
}

# Lista de modelos para migração automática
MODELS: List[str] = [
    "message_broker_v1.Queue",
    "message_broker_v1.Message"
] 