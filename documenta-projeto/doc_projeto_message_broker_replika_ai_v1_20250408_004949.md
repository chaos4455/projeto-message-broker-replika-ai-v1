# 📄 Documentação do Projeto: projeto message broker replika ai v1

**Gerado em:** 2025-04-08 00:49:49
**Plataforma:** Windows 10
**Modelo IA:** gemini-2.0-flash-thinking-exp-01-21
**Arquivos Analisados:**
- `projeto message broker replika ai v1\message-broker-v3-clean.py`

---

```markdown
# 🚀 Message Broker API v3.1.5 Documentation 📚

**Versão:** 0.3.1.5-fastapi-tortoise-fixes 🛠️

---

## 🌟 Visão Geral e Propósito 🎯

Este projeto implementa uma API de **Message Broker** assíncrona robusta e eficiente, construída utilizando tecnologias de ponta como **FastAPI**, **Tortoise ORM**, e **SQLite**. Projetada para facilitar a comunicação desacoplada entre diferentes serviços e componentes de software, esta API atua como um hub centralizado para o envio, armazenamento e recebimento de mensagens.

**Problema que Resolve:**

No desenvolvimento de sistemas distribuídos e microsserviços, a comunicação síncrona direta pode levar a gargalos, dependências fortes e falhas em cascata. Um Message Broker introduz um padrão de comunicação **assíncrona**, permitindo que os serviços enviem mensagens para filas sem precisar esperar por uma resposta imediata, e outros serviços podem consumir essas mensagens no seu próprio ritmo. Isso resulta em:

*   **Desacoplamento:** Serviços não precisam conhecer a localização ou o estado uns dos outros.
*   **Escalabilidade:** Facilita a escalabilidade independente de diferentes partes do sistema.
*   **Resiliência:** A falha de um serviço consumidor não afeta os serviços produtores.
*   **Flexibilidade:** Suporta diferentes padrões de comunicação, como *publish-subscribe* e *point-to-point* (neste caso, focado em filas *point-to-point*).
*   **Confiabilidade:** Garante a entrega de mensagens, mesmo em caso de falhas temporárias.

**Em essência, esta API de Message Broker simplifica a criação de arquiteturas de software mais modulares, escaláveis e resilientes.**

---

## ✨ Funcionalidades Chave 🔑

A API de Message Broker oferece um conjunto abrangente de funcionalidades, divididas em categorias principais para facilitar o uso e a gestão.

### 📥 Gestão de Filas (Queues) 🗄️

*   **Criação de Filas (POST `/queues`):** Permite criar novas filas de mensagens de forma dinâmica. Os nomes das filas devem ser únicos e seguir um padrão alfanumérico (caracteres alfanuméricos, underscores e hífens).
    *   **Exemplo:** Criar uma fila chamada `order-processing`.
    *   **Validação:** Nomes de fila seguem regex `^[a-zA-Z0-9_-]+$`, comprimento máximo de 255 caracteres.
    *   **Resposta:** Retorna detalhes da fila criada, incluindo ID, nome e timestamps de criação e atualização.

*   **Listagem de Filas (GET `/queues`):** Recupera a lista de todas as filas existentes no sistema, ordenadas alfabeticamente.
    *   **Resposta:** Retorna uma lista de objetos `QueueResponse`, cada um contendo detalhes da fila e a contagem atual de mensagens na fila.

*   **Detalhes da Fila (GET `/queues/{queue_name}`):** Obtém informações detalhadas sobre uma fila específica, identificada pelo seu nome.
    *   **Parâmetro:** `queue_name` (string) - Nome da fila a ser consultada.
    *   **Resposta:** Retorna um objeto `QueueResponse` com detalhes da fila e a contagem de mensagens.
    *   **Erro 404:** Se a fila não for encontrada.

*   **Exclusão de Filas (DELETE `/queues/{queue_name}`):** Remove permanentemente uma fila e todas as mensagens associadas a ela.
    *   **Parâmetro:** `queue_name` (string) - Nome da fila a ser excluída.
    *   **Resposta 204 No Content:** Em caso de sucesso na exclusão.
    *   **CUIDADO:** Esta operação é irreversível e apaga todas as mensagens da fila.

### ✉️ Gestão de Mensagens 📬

*   **Publicação de Mensagens (POST `/queues/{queue_name}/messages`):** Permite enviar uma nova mensagem para uma fila específica.
    *   **Parâmetros:**
        *   `queue_name` (string) - Nome da fila de destino.
        *   Payload no corpo da requisição (JSON):
            ```json
            {
              "content": "Sua mensagem aqui"
            }
            ```
            O campo `content` é uma string arbitrária que representa o payload da mensagem.
    *   **Resposta 201 Created:** Retorna um objeto `MessagePublishResponse` confirmando a publicação e fornecendo o ID da mensagem.

*   **Consumo de Mensagens (GET `/queues/{queue_name}/messages/consume`):** Recupera e marca a próxima mensagem pendente de uma fila como "em processamento".
    *   **Parâmetro:** `queue_name` (string) - Nome da fila da qual consumir a mensagem.
    *   **Resposta 200 OK:** Retorna um objeto `MessageResponse` com os detalhes da mensagem consumida (ID, conteúdo, status "processing", timestamps).
    *   **Resposta 204 No Content:** Se não houver mensagens pendentes na fila.
    *   **Mecanismo de Consumo:** Utiliza `SELECT FOR UPDATE` no banco de dados para garantir que apenas um consumidor processe cada mensagem, evitando condições de corrida.

*   **Acknowledge de Mensagens (ACK) (POST `/messages/{message_id}/ack`):** Confirma o processamento bem-sucedido de uma mensagem. Move a mensagem para o status "processed".
    *   **Parâmetro:** `message_id` (integer) - ID da mensagem a ser confirmada.
    *   **Resposta 200 OK:** Retorna um objeto JSON `{ "detail": "Message {message_id} acknowledged successfully." }`.
    *   **Validação:** A mensagem deve estar no status "processing" para ser confirmada.
    *   **Erro 409 Conflict:** Se a mensagem não estiver no status "processing".
    *   **Erro 404 Not Found:** Se a mensagem não for encontrada.

*   **Negative Acknowledge de Mensagens (NACK) (POST `/messages/{message_id}/nack`):** Indica que o processamento de uma mensagem falhou. Permite requeuear a mensagem (status "pending") ou marcá-la como falha (status "failed").
    *   **Parâmetros:**
        *   `message_id` (integer) - ID da mensagem a ser negativamente confirmada.
        *   Query parameter `requeue` (boolean, opcional, default=false): Se `true`, a mensagem é retornada para a fila com status "pending" para reprocessamento. Se `false`, a mensagem é marcada como "failed".
    *   **Resposta 200 OK:** Retorna um objeto JSON `{ "detail": "Message {message_id} successfully {action}." }`, onde `{action}` é "requeued (pending)" ou "marked as failed".
    *   **Validação:** A mensagem deve estar no status "processing" para ser negativamente confirmada.
    *   **Erro 409 Conflict:** Se a mensagem não estiver no status "processing".
    *   **Erro 404 Not Found:** Se a mensagem não for encontrada.

### 🔑 Autenticação e Segurança 🛡️

*   **Autenticação JWT (JSON Web Tokens):** Todas as rotas (exceto `/login` e `/`) são protegidas e exigem autenticação via JWT.
    *   **Login (POST `/login`):** Endpoint para obter tokens de acesso e refresh. Utiliza `OAuth2PasswordRequestForm` para receber `username` e `password`.
        *   **Credenciais Padrão (INSEGURAS):** `admin`/`admin` (apenas para testes e desenvolvimento, **NÃO USE EM PRODUÇÃO!**).
        *   **Resposta:** Retorna um objeto `Token` contendo `access_token` e `refresh_token`.

    *   **Refresh Token (POST `/refresh`):** Endpoint para obter um novo par de tokens de acesso e refresh utilizando um refresh token válido.
        *   **Autenticação:** Espera um `Bearer` token no cabeçalho `Authorization` que seja um refresh token válido.
        *   **Resposta:** Retorna um novo objeto `Token`.

    *   **Validação de Token:** Funções `get_current_user` e `validate_refresh_token` utilizam a biblioteca `python-jose` para decodificar e validar tokens JWT, garantindo a segurança das rotas protegidas.

*   **CORS (Cross-Origin Resource Sharing):** Configurado com `CORSMiddleware` para permitir requisições de diferentes origens.
    *   **Configuração:** `ALLOWED_ORIGINS` pode ser configurado via variável de ambiente ou no código.
    *   **Padrão Inseguro em Produção:** Por padrão, `ALLOWED_ORIGINS` é `["*"]`, o que é **altamente inseguro para produção**. É crucial configurar origens permitidas específicas em ambientes de produção.

*   **Geração de Certificados SSL/TLS:** Script para gerar certificados autoassinados para HTTPS, melhorando a segurança das comunicações.
    *   **Função:** `generate_self_signed_cert` utiliza a biblioteca `cryptography` para criar chaves privadas RSA e certificados X.509.
    *   **Utilização:** Usado no bloco `if __name__ == '__main__':` para verificar e gerar certificados se não existirem, permitindo que o servidor Uvicorn seja executado com HTTPS.

### ⏱️ Rate Limiting (Limitação de Taxa) 🚦

*   **Implementação:** Utiliza a biblioteca `slowapi` para limitar o número de requisições que podem ser feitas para a API em um determinado período.
    *   **Configuração:**
        *   `DEFAULT_RATE_LIMIT`: Limite padrão para a maioria das rotas (padrão: "200/minute").
        *   `HIGH_TRAFFIC_RATE_LIMIT`: Limite para rotas de alta frequência como publicação e consumo de mensagens (padrão: "200/second").
    *   **Middleware:** `SlowAPIMiddleware` é adicionado ao aplicativo FastAPI para aplicar os limites de taxa.
    *   **Decorator `@limiter.limit()`:** Usado em cada endpoint para definir o limite de taxa específico.
    *   **Exceção `RateLimitExceeded`:** Gerada quando o limite de taxa é excedido, tratada por `_rate_limit_exceeded_handler` que retorna uma resposta HTTP 429 Too Many Requests.

### 📊 Monitoring e Estatísticas 📈

*   **Endpoint de Estatísticas (GET `/stats`):** Retorna informações detalhadas sobre o estado da API e do sistema. Requer autenticação JWT.
    *   **Dados Retornados (ver `StatsResponse` model):**
        *   **Tempo de atividade (uptime):** `start_time`, `uptime_seconds`, `uptime_human`.
        *   **Estatísticas de requisições:** `requests_total`, `requests_by_route`, `requests_by_status`.
        *   **Estatísticas do Message Broker:** `queues_total`, `messages_total`, `messages_pending`, `messages_processing`, `messages_processed`, `messages_failed`.
        *   **Último erro:** `last_error`, `last_error_timestamp`.
        *   **Informações do sistema:** `system` (versão Python, plataforma, CPU, memória, disco).
        *   **Informações específicas do broker:** `broker_specific` (framework, versão, banco de dados, autenticação, rate limit, GraphQL).
    *   **Utilização de `psutil`:** Para coletar métricas detalhadas do sistema (CPU, memória, disco), se a biblioteca estiver instalada.

*   **Endpoint de Logs (GET `/logs` e GET `/logs/{filename}`):** Permite listar arquivos de log e visualizar o conteúdo dos arquivos de log JSON. Requer autenticação JWT.
    *   **Listar arquivos de log (GET `/logs`):** Retorna uma lista de nomes de arquivos JSON no diretório de logs.
    *   **Obter conteúdo do arquivo de log (GET `/logs/{filename}`):** Retorna o conteúdo de um arquivo de log JSON específico como uma lista de objetos JSON.
        *   **Parâmetros opcionais:** `start`, `end`, `tail` para controlar quais linhas do log são retornadas.
        *   **Segurança:** Validação do nome do arquivo para prevenir acesso a arquivos arbitrários. Utiliza `werkzeug.utils.secure_filename`.

### 🍓 GraphQL API 🍇

*   **Endpoint GraphQL (POST `/graphql` e interface GraphiQL/Apollo Sandbox em GET `/graphql`):** Oferece uma interface GraphQL alternativa para interagir com o Message Broker.
    *   **Esquema GraphQL:** Definido utilizando a biblioteca `strawberry-graphql`.
        *   **Queries:**
            *   `all_queues`: Retorna todas as filas.
            *   `queue_by_name(name: String!)`: Retorna uma fila específica pelo nome.
            *   `message_by_id(id: ID!)`: Retorna uma mensagem específica pelo ID.
        *   **Mutations:**
            *   `create_queue(name: String!)`: Cria uma nova fila.
            *   `delete_queue(name: String!)`: Exclui uma fila.
            *   `publish_message(queueName: String!, content: String!)`: Publica uma mensagem em uma fila.
        *   **Tipos GraphQL:** `QueueGQL`, `MessageGQL`.
    *   **Autenticação:** O endpoint GraphQL também pode ser protegido por JWT. O contexto GraphQL (`get_graphql_context`) tenta autenticar o usuário com base no token Bearer no cabeçalho `Authorization`.
    *   **Interface Apollo Sandbox:** Integrada para facilitar a exploração e teste da API GraphQL em `GET /graphql`.

---

## 🏗️ Estrutura do Projeto (Inferida) 🧩

O projeto é implementado em um único arquivo Python: `message-broker-v3-clean.py`. A estrutura interna pode ser visualizada da seguinte forma:

```
message-broker-v3-clean.py
├── Settings Class: Configurações gerais da API (portas, secrets, paths, etc.)
├── Logging Setup: Inicialização do sistema de logging (console e arquivo JSON)
├── Database Models (Tortoise ORM):
│   ├── Queue Model: Define a estrutura da tabela de filas
│   └── Message Model: Define a estrutura da tabela de mensagens
├── FastAPI Application (app):
│   ├── Lifespan Event Handler: Inicialização e shutdown do aplicativo (DB, logs)
│   ├── Middleware:
│   │   ├── CORS Middleware: Configuração de CORS
│   │   ├── Rate Limiting Middleware (SlowAPI): Aplicação de limites de taxa
│   │   └── Stats Middleware: Coleta de estatísticas de requisição
│   ├── Authentication Endpoints (/login, /refresh): Geração e refresh de tokens JWT
│   ├── Monitoring Endpoints (/stats, /logs, /logs/{filename}): Estatísticas e visualização de logs
│   ├── Queue Endpoints (/queues, /queues/{queue_name}): Criação, listagem, detalhes e exclusão de filas
│   ├── Message Endpoints (/queues/{queue_name}/messages, /queues/{queue_name}/messages/consume, /messages/{message_id}/ack, /messages/{message_id}/nack): Publicação, consumo e acknowledgements de mensagens
│   ├── GraphQL Router (/graphql): Integração da API GraphQL (Strawberry)
│   ├── Exception Handlers: Tratamento de exceções (DB, validação, HTTP, genéricas)
│   └── Startup Block (if __name__ == '__main__':): Inicialização do servidor Uvicorn, configuração de SSL
└── GraphQL Schema (Strawberry):
    ├── QueryGQL: Queries GraphQL (all_queues, queue_by_name, message_by_id)
    ├── MutationGQL: Mutations GraphQL (create_queue, delete_queue, publish_message)
    ├── Types (QueueGQL, MessageGQL): Definição dos tipos GraphQL
    └── Context Getter (get_graphql_context): Contexto para requisições GraphQL (autenticação)
```

**Fluxo de Dados e Controle Principal:**

1.  **Requisição HTTP/GraphQL:** Um cliente faz uma requisição para um endpoint da API.
2.  **Middleware Pipeline:** A requisição passa por middlewares (CORS, Rate Limiting, Stats).
3.  **Autenticação:** Para rotas protegidas, o token JWT é validado.
4.  **Roteamento FastAPI:** A requisição é roteada para a função de endpoint correspondente.
5.  **Lógica de Negócio:** A função de endpoint interage com o banco de dados via Tortoise ORM para realizar operações (criar/ler/atualizar/deletar filas e mensagens).
6.  **Resposta HTTP/GraphQL:** A função de endpoint retorna uma resposta, que é processada pelos middlewares (Stats) e enviada de volta ao cliente.
7.  **Logging:** Em vários pontos do fluxo, eventos e erros são registrados utilizando o sistema de logging configurado.

---

## 🧩 Componentes Importantes ⚙️

### ⚙️ `Settings` Class ⚙️

A classe `Settings` no início do código é crucial para a configuração da API. Ela define variáveis como:

*   `PROJECT_NAME`, `VERSION`: Nome e versão do projeto.
*   `API_PORT`: Porta em que a API será executada (padrão: 8777).
*   `JWT_SECRET_KEY`: Chave secreta para geração e validação de tokens JWT. **CRÍTICO: Deve ser alterada em produção!**
*   `ALGORITHM`: Algoritmo de encriptação JWT (padrão: "HS256").
*   `ACCESS_TOKEN_EXPIRE_MINUTES`, `REFRESH_TOKEN_EXPIRE_DAYS`: Tempo de expiração dos tokens.
*   `DB_DIR`, `DB_FILENAME`, `DB_PATH`, `DATABASE_URL`: Configurações do banco de dados SQLite.
*   `LOG_DIR`, `CERT_DIR`, `CERT_FILE`, `KEY_FILE`: Diretórios e arquivos para logs e certificados SSL.
*   `ALLOWED_ORIGINS`: Origens permitidas para CORS.
*   `DEFAULT_RATE_LIMIT`, `HIGH_TRAFFIC_RATE_LIMIT`: Limites de taxa da API.
*   `LOG_LEVEL_STR`, `LOG_LEVEL`: Nível de logging.
*   `APP_ENV`: Ambiente da aplicação ("production" ou "development").

**Importância:** Centraliza todas as configurações, facilitando a modificação e o gerenciamento de parâmetros da API. Utiliza variáveis de ambiente para configurações sensíveis como `JWT_SECRET_KEY` e `LOG_LEVEL`.

### 📝 Logging System (Formatters, Handlers, Log Functions) 📝

O sistema de logging é essencial para monitorar o comportamento da API, diagnosticar problemas e auditar eventos.

*   **Formatters (`ColoramaFormatter`, `JsonFormatter`):**
    *   `ColoramaFormatter`: Formata logs para o console com cores e ícones para melhor legibilidade.
    *   `JsonFormatter`: Formata logs como objetos JSON para facilitar a análise estruturada e integração com ferramentas de log management.
*   **Handlers (`StreamHandler`, `FileHandler`):**
    *   `StreamHandler`: Envia logs para o console (stdout).
    *   `FileHandler`: Escreve logs em arquivos JSON no diretório `settings.LOG_DIR`.
*   **Logger (`logger = logging.getLogger("MessageBroker")`):** Instância principal do logger, configurada com os handlers e nível de log definido em `settings.LOG_LEVEL`.
*   **Funções de Log (`log_debug`, `log_info`, `log_warning`, `log_error`, `log_critical`, `log_pipeline`, `log_success`):** Funções de conveniência para registrar mensagens em diferentes níveis de log, adicionando ícones e dados extras para contexto.

**Importância:** Fornece um sistema de logging flexível e detalhado, crucial para operação, debugging e monitoramento da API. A formatação em JSON é especialmente útil para análise de logs com ferramentas externas.

### 💾 Database Models (`Queue`, `Message`) 💾

Os modelos Tortoise ORM `Queue` e `Message` definem a estrutura do banco de dados SQLite e a interação com ele.

*   **`Queue` Model:**
    *   `id`: ID primário da fila (integer, auto-increment).
    *   `name`: Nome único da fila (string, indexado).
    *   `created_at`, `updated_at`: Timestamps de criação e atualização (datetime, auto-gerenciados).
    *   `messages`: Relação reversa para acessar as mensagens associadas à fila.
    *   **Meta Class:** Define nome da tabela (`queues`) e ordenação padrão (`name`).

*   **`Message` Model:**
    *   `id`: ID primário da mensagem (integer, auto-increment).
    *   `queue`: Chave estrangeira para o modelo `Queue`, indicando a fila à qual a mensagem pertence.
    *   `content`: Payload da mensagem (string, texto longo).
    *   `status`: Status da mensagem ("pending", "processing", "processed", "failed", string, indexado).
    *   `created_at`, `updated_at`: Timestamps de criação e atualização (datetime, auto-gerenciados, `created_at` indexado).
    *   **Meta Class:** Define nome da tabela (`messages`), índices compostos (`queue_id`, `status`, `created_at`), e ordenação padrão (`created_at`).

**Importância:** Abstraem a interação com o banco de dados, permitindo que a API opere com filas e mensagens como objetos Python, facilitando o desenvolvimento e a manutenção. Tortoise ORM simplifica operações CRUD e relacionamentos entre tabelas.

### 🚀 FastAPI Application (`app`) e Rotas 🌐

A instância `app = FastAPI(...)` é o coração da API, definindo todos os endpoints, middleware e configurações.

*   **`FastAPI(...)` Initialization:**
    *   `title`, `version`, `description`: Metadados da API para documentação Swagger UI e ReDoc.
    *   `lifespan=lifespan`: Função `lifespan` para inicialização e shutdown do aplicativo (configuração do banco de dados, etc.).
    *   `docs_url`, `redoc_url`, `openapi_tags`: Configurações para documentação interativa.

*   **Rotas (Endpoints):** Decoradas com `@app.get`, `@app.post`, `@app.delete`, etc., definindo os endpoints REST da API. Cada rota é associada a uma função Python que processa a requisição e retorna a resposta.
    *   Exemplos: `/`, `/login`, `/stats`, `/logs`, `/queues`, `/queues/{queue_name}`, `/queues/{queue_name}/messages`, `/messages/{message_id}/ack`, etc.

*   **Middleware:** Adicionados usando `app.add_middleware(...)`, processam requisições e respostas globalmente.
    *   CORS, Rate Limiting, Stats Middleware (já mencionados).

*   **Exception Handlers:** Funções decoradas com `@app.exception_handler(...)` para tratamento de exceções específicas (e.g., `DoesNotExist`, `IntegrityError`, `ValidationError`, `HTTPException`, `Exception`).

**Importância:** FastAPI fornece uma estrutura robusta e eficiente para construir APIs RESTful e GraphQL em Python. O sistema de roteamento, middleware e tratamento de exceções simplifica o desenvolvimento e garante a qualidade da API.

### 🍓 GraphQL Integration (Strawberry) 🍓

A integração com GraphQL através da biblioteca Strawberry oferece uma alternativa ao REST para interagir com o Message Broker.

*   **GraphQL Schema (`gql_schema`):** Definido com `strawberry.Schema(query=QueryGQL, mutation=MutationGQL)`.
    *   `QueryGQL`: Classe que define as queries GraphQL (leitura de dados).
    *   `MutationGQL`: Classe que define as mutations GraphQL (escrita/modificação de dados).
    *   `QueueGQL`, `MessageGQL`: Tipos GraphQL que representam filas e mensagens.
*   **GraphQL Router (`graphql_app`):** Criado com `GraphQLRouter(gql_schema, ...)`.
    *   `context_getter=get_graphql_context`: Função para fornecer contexto (usuário autenticado, requisição, resposta) para os resolvers GraphQL.
    *   `graphiql=False, graphql_ide="apollo-sandbox"`: Configuração da interface de desenvolvimento GraphQL para Apollo Sandbox.
*   **Endpoint GraphQL (/graphql):** Adicionado ao aplicativo FastAPI com `app.include_router(graphql_app, prefix="/graphql", tags=["GraphQL"], include_in_schema=True)`.

**Importância:** GraphQL oferece uma forma mais flexível e eficiente para os clientes consumirem dados da API, permitindo que eles solicitem exatamente os dados de que precisam, reduzindo over-fetching e under-fetching. A integração com Strawberry facilita a criação de APIs GraphQL com Python e FastAPI.

---

## 🚀 Como Usar/Executar 🚦

Para executar a API de Message Broker, siga os seguintes passos:

1.  **Pré-requisitos:**
    *   **Python:** Certifique-se de ter Python 3.7 ou superior instalado.
    *   **pip:** O gerenciador de pacotes pip deve estar instalado.

2.  **Instalar Dependências:**
    Abra um terminal e navegue até o diretório onde você salvou o arquivo `message-broker-v3-clean.py`. Execute o seguinte comando para instalar todas as dependências necessárias:

    ```bash
    pip install fastapi uvicorn[standard] tortoise-orm aiosqlite pydantic[email] python-jose[cryptography] colorama cryptography psutil Werkzeug slowapi strawberry-graphql[fastapi] Jinja2 ipaddress passlib Werkzeug
    ```

3.  **Configurar Variáveis de Ambiente (Opcional, mas Recomendado para Produção):**
    *   **`JWT_SECRET_KEY`:** Defina uma variável de ambiente `JWT_SECRET_KEY` com uma chave secreta forte e única para proteger os tokens JWT em produção. Se não definida, uma chave padrão insegura será usada (apenas para desenvolvimento).
    *   **`LOG_LEVEL`:** Defina a variável de ambiente `LOG_LEVEL` para controlar o nível de logging (e.g., `DEBUG`, `INFO`, `WARNING`, `ERROR`, `CRITICAL`). Padrão é `INFO`.
    *   **`APP_ENV`:** Defina `APP_ENV` para `"production"` ou `"development"` para controlar comportamentos específicos do ambiente (e.g., mensagens de erro detalhadas, auto-reload). Padrão é `"production"`.

4.  **Executar a API:**
    No mesmo terminal, execute o script Python:

    ```bash
    python message-broker-v3-clean.py
    ```

    A API será iniciada no endereço `https://0.0.0.0:8777`.

5.  **Acessar a API:**
    Abra seu navegador web e acesse os seguintes URLs:

    *   **Raiz da API:** `https://localhost:8777/` - Retorna uma mensagem de boas-vindas e status.
    *   **Documentação Swagger UI:** `https://localhost:8777/docs` - Documentação interativa da API REST.
    *   **Documentação ReDoc:** `https://localhost:8777/redoc` - Documentação alternativa da API REST.
    *   **Interface GraphQL (Apollo Sandbox):** `https://localhost:8777/graphql` - Interface para executar queries e mutations