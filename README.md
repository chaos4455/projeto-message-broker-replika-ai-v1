# Message Broker com FastAPI e Tortoise ORM

## 📝 Descrição
Message Broker é um sistema de filas de mensagens assíncrono construído com FastAPI e Tortoise ORM. O sistema permite a criação de filas, publicação e consumo de mensagens de forma eficiente e escalável.

## 🚀 Tecnologias
- FastAPI
- Tortoise ORM
- SQLite
- Redis (para SSE)
- Python 3.8+

## 🛠️ Instalação

1. Clone o repositório:
```bash
git clone https://github.com/seu-usuario/message-broker.git
cd message-broker
```

2. Crie um ambiente virtual e ative-o:
```bash
python -m venv venv
source venv/bin/activate  # Linux/Mac
.\venv\Scripts\activate   # Windows
```

3. Instale as dependências:
```bash
pip install -r requirements.txt
```

## ⚙️ Configuração

1. Crie um arquivo `.env` na raiz do projeto:
```env
DATABASE_URL=sqlite://db.sqlite3
REDIS_URL=redis://localhost:6379
SECRET_KEY=sua-chave-secreta
```

2. Configure o Tortoise ORM:
O arquivo `tortoise_config.py` já está configurado para usar SQLite. Se necessário, ajuste as configurações.

## 🏃‍♂️ Executando

1. Inicie o servidor:
```bash
uvicorn message_broker_v1:app --reload
```

2. Acesse a documentação da API:
- Swagger UI: http://localhost:8000/docs
- ReDoc: http://localhost:8000/redoc

## 📚 Endpoints

### Filas (Queues)
- `POST /queues` - Cria uma nova fila
- `GET /queues` - Lista todas as filas
- `GET /queues/{queue_name}` - Obtém detalhes de uma fila
- `DELETE /queues/{queue_name}` - Remove uma fila

### Mensagens
- `POST /queues/{queue_name}/messages` - Publica uma mensagem
- `GET /queues/{queue_name}/messages` - Consome uma mensagem

## 🔄 Migrações

Para criar e aplicar migrações:

```bash
aerich init -t tortoise_config.TORTOISE_ORM
aerich init-db
aerich migrate
aerich upgrade
```

## 📊 Monitoramento

O sistema inclui:
- Logs detalhados com Loguru
- Métricas de performance
- Eventos em tempo real via SSE

## 👨‍💻 Autor
Elias Andrade - Arquiteto de Soluções
- Email: seu-email@exemplo.com
- LinkedIn: [seu-linkedin](https://linkedin.com/in/seu-usuario)

## 📄 Licença
Este projeto está sob a licença MIT. Veja o arquivo [LICENSE](LICENSE) para mais detalhes.

## 🤝 Contribuindo
Contribuições são bem-vindas! Por favor, leia o [CONTRIBUTING.md](CONTRIBUTING.md) para detalhes sobre nosso código de conduta e o processo para enviar pull requests. 