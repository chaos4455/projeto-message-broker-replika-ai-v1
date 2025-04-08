# 📄 Documentação do Projeto: projeto message broker replika ai v1

**Gerado em:** 2025-04-08 00:48:06
**Plataforma:** Windows 10
**Modelo IA:** gemini-1.5-flash
**Arquivos Analisados:**
- `projeto message broker replika ai v1\message-broker-v3-clean.py`

---

# Documentação Técnica: Message Broker API V3.1.5

Este documento fornece uma visão geral abrangente da Message Broker API V3.1.5, um projeto Python que implementa uma API RESTful e GraphQL para gerenciamento de filas de mensagens assíncronas.  A API utiliza `FastAPI`, `Tortoise ORM` e `SQLite` para fornecer alta performance e escalabilidade.

## 1. Visão Geral e Propósito

O Message Broker API V3.1.5 resolve o problema de gerenciamento de filas de mensagens em um ambiente distribuído. Ele permite a publicação e consumo de mensagens em filas nomeadas, oferecendo funcionalidades de rastreamento, monitoramento e controle de acesso.  A API é projetada para ser robusta, escalável e segura, utilizando melhores práticas de desenvolvimento de software.

## 2. Funcionalidades Chave

A API oferece as seguintes funcionalidades principais:

* **Gerenciamento de Filas:** Criação, listagem, detalhamento e remoção de filas de mensagens.  Cada fila é identificada por um nome único.
* **Publicação de Mensagens:** Publicação de mensagens em uma fila específica. A mensagem é armazenada no banco de dados com status "pendente".
* **Consumo de Mensagens:** Consumo de mensagens de uma fila.  A API retorna a mensagem com o status atualizado para "processando".
* **Acionamento (ACK) e Recusa (NACK) de Mensagens:**  Após o processamento, as mensagens podem ser confirmadas (ACK) ou recusadas (NACK). O NACK permite re-enfileiramento ou marcação como falha.
* **Autenticação e Autorização:**  Utiliza JWT (JSON Web Tokens) para autenticação e controle de acesso, com tokens de acesso e refresh.
* **Monitoramento:**  Endpoints para obtenção de estatísticas do sistema, incluindo métricas de desempenho da API, do banco de dados e do sistema operacional.  Também permite a visualização de logs.
* **API GraphQL:** Uma interface GraphQL para acesso aos dados de filas e mensagens, oferecendo flexibilidade adicional para os clientes.
* **Gerenciamento de Logs:**  Logs detalhados em formato JSON, armazenados em arquivos separados por data e hora, com informações de tempo, nível de severidade, rastreio de pilha (em modo de desenvolvimento) e metadados adicionais.
* **Gerenciamento de Certificados SSL:**  Capacidade de gerar um certificado auto-assinado para HTTPS, garantindo comunicação segura.
* **Limitação de Taxa (Rate Limiting):** Implementa um sistema de rate limiting para prevenir ataques de força bruta e garantir estabilidade.


## 3. Estrutura do Projeto

O projeto é estruturado em um único arquivo `message-broker-v3-clean.py`. Ele contém:

* **Configurações:** A classe `Settings` define as configurações da aplicação, como porta, chave secreta JWT, caminho do banco de dados, etc.  Muitas configurações são carregadas de variáveis de ambiente.
* **Loggin:** Implementação customizada de logging com formatação colorida para console e logs estruturados em JSON para arquivos, permitindo análise eficiente.
* **Geração de Certificados:** Função `generate_self_signed_cert` para geração de certificados auto-assinados para HTTPS.
* **Modelos de Dados (Tortoise ORM):**  As classes `Queue` e `Message` definem os modelos de dados para filas e mensagens, respectivamente.
* **Modelos Pydantic:** Classes Pydantic (`QueueBase`, `MessageBase`, etc.) para validação de dados de entrada e saída da API.
* **Endpoints FastAPI:**  Diversos endpoints FastAPI (`@app.get`, `@app.post`, `@app.delete`) que implementam as funcionalidades da API REST.
* **Endpoints GraphQL (Strawberry):**  Integração do Strawberry para fornecer uma API GraphQL.
* **Tratamento de Exceções:**  Tratamento customizado de exceções usando `@app.exception_handler` para lidar com erros de forma consistente e informativa.
* **Middleware:** Utilizado para atualizar estatísticas de requisições e aplicar rate limiting.
* **Bloco `if __name__ == '__main__':`:**  Ponto de entrada principal da aplicação, responsável pela inicialização do servidor Uvicorn.


## 4. Componentes Importantes

### 4.1. `Settings`

Esta classe encapsula todas as configurações da aplicação, permitindo fácil configuração e gerenciamento.  A maioria das configurações pode ser sobrescrita por variáveis de ambiente, aumentando a flexibilidade.

### 4.2. `logger`

O `logger` é uma instância customizada da classe `logging.Logger`, configurado para registrar eventos em console e em arquivos JSON.  Ele utiliza formatadores customizados (`ColoramaFormatter` e `JsonFormatter`) para fornecer logs legíveis e estruturados.

### 4.3. `Queue` e `Message` (Modelos Tortoise ORM)

* `Queue`: Representa uma fila de mensagens no banco de dados. Possui atributos `id`, `name`, `created_at` e `updated_at`.
* `Message`: Representa uma mensagem individual. Possui atributos `id`, `queue` (chave estrangeira para `Queue`), `content`, `status`, `created_at` e `updated_at`.

### 4.4. Modelos Pydantic

Classes Pydantic como `QueueCreatePayload`, `MessagePayload`, `QueueResponse`, `MessageResponse`, etc., fornecem validação de dados, garantindo a integridade dos dados e a segurança da API.

### 4.5. Endpoints FastAPI

Os endpoints FastAPI são os pontos de entrada para a API REST.  Cada endpoint lida com uma operação específica, como criação de filas, publicação de mensagens, consumo de mensagens, etc.

### 4.6.  Endpoints GraphQL (Strawberry)

Os tipos e resolvers do Strawberry (`QueryGQL`, `MutationGQL`, `MessageGQL`, `QueueGQL`) expõem as funcionalidades da API via GraphQL.

### 4.7.  `update_request_stats` e `update_broker_stats`

Estas funções assíncronas atualizam as estatísticas da API, incluindo o número total de requests, requests por rota e por código de status, e métricas do broker como número de mensagens pendentes, processando, etc.

### 4.8. Middleware `update_stats_middleware`

Este middleware intercepta todas as requisições HTTP e atualiza as estatísticas da aplicação. Ele também mede o tempo de processamento e adiciona um cabeçalho `X-Process-Time` à resposta.

## 5. Como Usar/Executar

1. **Instalação de Dependências:** Execute `pip install -r requirements.txt` (assumindo que um arquivo `requirements.txt` foi criado com base nos imports do código).
2. **Configuração:** Defina as variáveis de ambiente necessárias (JWT_SECRET_KEY, LOG_LEVEL, APP_ENV, etc.).
3. **Execução:** Execute o script `message-broker-v3-clean.py`. O servidor Uvicorn iniciará, escutando em `https://0.0.0.0:8777` (a menos que a porta seja alterada nas configurações).

O script verifica a existência de um certificado SSL e gera um auto-assinado se necessário.


## 6. Dependências Externas

O projeto depende das seguintes bibliotecas:

* `asyncio`
* `json`
* `logging`
* `os`
* `platform`
* `secrets`
* `sys`
* `time`
* `traceback`
* `re`
* `contextlib`
* `datetime`
* `typing`
* `collections`
* `hashlib`
* `ipaddress`
* `tortoise`
* `fastapi`
* `uvicorn`
* `jose`
* `pydantic`
* `colorama`
* `cryptography`
* `psutil`
* `werkzeug`
* `slowapi`
* `strawberry`


## 7. Rotas de Estatísticas e Dados para KPIs

A rota `/stats` retorna um JSON com dados para gerar dashboards e KPIs.  A estrutura é definida pela classe `StatsResponse`.  Os dados incluem:

* **`start_time`**: Data e hora de início da aplicação.
* **`uptime_seconds` e `uptime_human`**: Tempo de atividade da aplicação em segundos e em formato legível (dias, horas, minutos, segundos).
* **`requests_total`**: Número total de requisições recebidas.
* **`requests_by_route`**: Dicionário com o número de requisições por rota e método HTTP (GET, POST, DELETE).  Exemplo: `{"/queues": {"GET": 10, "POST": 5}}`.  **KPI:**  Taxa de requisições por rota, identificando endpoints com maior carga.
* **`requests_by_status`**: Dicionário com o número de requisições por código de status HTTP (200, 404, 500, etc.).  **KPI:** Taxa de erros (4xx e 5xx), monitorando a estabilidade da API.
* **`queues_total`**: Número total de filas.  **KPI:**  Número de filas ativas, indicando o crescimento do sistema.
* **`messages_total`, `messages_pending`, `messages_processing`, `messages_processed`, `messages_failed`**:  Métricas sobre as mensagens, incluindo o total, as pendentes, as em processamento, as processadas com sucesso e as que falharam.  **KPI:**  Taxa de processamento de mensagens, identificando gargalos e problemas de processamento.
* **`last_error` e `last_error_timestamp`**: Detalhes do último erro ocorrido e sua data/hora.  **KPI:**  Frequência de erros, indicando a necessidade de manutenção ou correções.
* **`system`**:  Métricas do sistema operacional coletadas pelo `psutil`, incluindo uso de CPU, memória, disco, etc.  **KPI:**  Uso de recursos do sistema, identificando potenciais problemas de performance.
* **`broker_specific`**: Informações específicas do broker, como framework, versão, banco de dados, método de autenticação, etc.


A rota `/logs` lista os arquivos de log disponíveis, e a rota `/logs/{filename}` permite a recuperação do conteúdo de um arquivo de log específico, com opções de paginação e busca (start, end, tail). Os dados dos logs são estruturados, facilitando a criação de um log viewer com filtros e gráficos.  **KPI:** Análise da frequência e tipo de erros em logs, para identificar padrões e problemas recorrentes.


Todos os dados retornados por `/stats` e `/logs` podem ser usados para gerar dashboards, KPIs e um log viewer.  As métricas fornecem uma visão completa do desempenho da API e do broker, permitindo monitoramento proativo e identificação de problemas.  A estrutura JSON dos dados facilita a integração com ferramentas de monitoramento e visualização de dados.

