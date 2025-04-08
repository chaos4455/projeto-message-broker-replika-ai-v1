# 📊 Monitoramento e Dashboards para a API Message Broker V3.1.5

Este documento detalha todas as fontes de dados, métricas e logs fornecidos pela API do Message Broker (baseada em FastAPI/Tortoise) que podem ser utilizadas para construir dashboards de monitoramento, rastrear Key Performance Indicators (KPIs) e analisar a saúde e performance do sistema.

## 📜 Visão Geral

A API atua como um **Message Broker Assíncrono**. Suas funções principais são:

1.  **Receber Mensagens (Publish):** Aceitar dados de produtores.
2.  **Enfileirar Mensagens:** Armazenar essas mensagens de forma organizada em filas nomeadas.
3.  **Entregar Mensagens (Consume):** Permitir que consumidores recuperem mensagens para processamento.
4.  **Gerenciar o Ciclo de Vida:** Lidar com confirmações (ACK - Acknowledge) e rejeições (NACK - Negative Acknowledge) das mensagens processadas.

Monitorar este sistema é crucial para garantir:

*   **Fluxo de Mensagens (Throughput):** Quantas mensagens estão sendo processadas com sucesso.
*   **Acúmulo (Backlog):** Quantas mensagens estão esperando para serem processadas.
*   **Latência:** Quanto tempo as mensagens levam para serem processadas.
*   **Taxa de Erros:** Quantas mensagens falham no processamento.
*   **Saúde do Sistema:** Uso de recursos (CPU, memória, disco) pelo servidor.
*   **Disponibilidade:** Se a API está respondendo corretamente.

## 🔬 Fontes Principais de Dados para Dashboards

A API oferece várias maneiras de obter dados para monitoramento:

1.  **📈 Endpoint `/stats` (REST API):** A fonte **mais rica** e primária para métricas agregadas e KPIs. Retorna um snapshot do estado atual e histórico de contadores. **Requer Autenticação.**
2.  **📁 Endpoints `/queues` (REST API):** Fornecem informações sobre as filas existentes e a contagem *total* de mensagens nelas. **Requer Autenticação.**
3.  **💬 Endpoints de Ações de Mensagem (REST API):** Rotas como `/messages/publish`, `/messages/consume`, `/messages/ack`, `/messages/nack`. Embora não retornem estatísticas *diretamente*, a **taxa** e o **resultado** (sucesso/erro) dessas chamadas são KPIs fundamentais, refletidos nos contadores do `/stats`. **Requer Autenticação.**
4.  **🍓 Endpoint `/graphql` (GraphQL API):** Uma interface alternativa para consultar dados sobre filas e mensagens, incluindo contagens e filtros. **Requer Autenticação (via Bearer Token).**
5.  **📄 Endpoints `/logs` (REST API):** Permitem listar e visualizar o conteúdo dos arquivos de log JSON gerados pelo servidor. Útil para análise profunda de erros e eventos específicos, geralmente em conjunto com ferramentas externas de agregação de logs. **Requer Autenticação.**
6.  **⏱️ Cabeçalho `X-Process-Time`:** Presente nas respostas HTTP, indica o tempo de processamento da requisição *dentro do servidor*.

---

## 📍 Análise Detalhada dos Endpoints REST API

### 1. Endpoint `/stats`

*   **Rota:** `GET /stats`
*   **Autenticação:** ✅ Obrigatória (JWT Access Token via `Authorization: Bearer <token>`)
*   **Rate Limit:** `30/minute` (padrão)
*   **Propósito Principal:** Fornecer um painel abrangente de métricas de performance, saúde do sistema e atividade do broker. É a **base principal** para dashboards.
*   **Formato Retornado:** Objeto JSON (`StatsResponse`)

**Métricas Detalhadas no `/stats`:**

| Campo                  | Emoji | Tipo                 | Descrição                                                                 | Relevância para Dashboard/KPI                                                                                                   |
| :--------------------- | :---- | :------------------- | :------------------------------------------------------------------------ | :------------------------------------------------------------------------------------------------------------------------------ |
| `start_time`           | 🕰️    | Datetime (ISO UTC)   | Timestamp de início do servidor.                                          | Contexto temporal, cálculo manual de uptime se necessário.                                                                      |
| `uptime_seconds`       | ⏳    | Float                | Tempo de atividade em segundos.                                           | **KPI:** Uptime do Serviço (numérico). Monitorar reinicializações inesperadas.                                                |
| `uptime_human`         | 🗣️    | String               | Tempo de atividade em formato legível (ex: "1d 2h 3m 4s").                  | **KPI:** Uptime do Serviço (visual).                                                                                            |
| `requests_total`       | 🔢    | Integer (Counter)    | Total de requisições HTTP recebidas (exclui docs, stats, etc.).           | **KPI:** Carga Geral da API. Tendências de uso ao longo do tempo.                                                               |
| `requests_by_route`    | 🗺️    | Dict[str, Dict[str, int]] | Contagem de requisições por Rota (path template) e Método HTTP.         | **KPIs:** Taxa de Publicação, Taxa de Consumo (tentativa), Taxa de ACK/NACK. Identificar endpoints mais usados ou com problemas. |
| `requests_by_status`   |🚦    | Dict[str, int]       | Contagem de respostas por Código de Status HTTP (2xx, 4xx, 5xx).          | **KPIs:** Taxa de Sucesso Geral (2xx), Taxa de Erro do Cliente (4xx), Taxa de Erro do Servidor (5xx). Monitorar picos de erros. |
| `queues_total`         | 📁    | Integer (Gauge)      | Número total de filas existentes.                                         | Visão geral da configuração do broker.                                                                                         |
| `messages_total`       | ✉️    | Integer (Counter)    | Número total de mensagens já registradas no sistema (soma de todos status). | **KPI:** Volume Total Processado. Indica a atividade histórica geral.                                                           |
| `messages_pending`     | 📥    | Integer (Gauge)      | Mensagens esperando para serem consumidas (status 'pending').             | **KPI Crítico:** Backlog / Tamanho da Fila Pendente. Indica acúmulo e potencial lentidão no processamento.                       |
| `messages_processing`  | ⚙️    | Integer (Gauge)      | Mensagens consumidas, aguardando ACK/NACK (status 'processing').          | **KPI:** Mensagens em Voo / Trabalho em Progresso. Picos podem indicar consumidores lentos ou travados.                         |
| `messages_processed`   | ✅    | Integer (Counter)    | Total de mensagens processadas com sucesso (status 'processed').          | **KPI Crítico:** Throughput / Vazão de Sucesso. Mede a capacidade efetiva do sistema.                                           |
| `messages_failed`      | ❌    | Integer (Counter)    | Total de mensagens que falharam permanentemente (status 'failed').        | **KPI:** Taxa de Falha Permanente. Indica problemas persistentes no processamento que exigem investigação manual.                 |
| `last_error`           | 🔥    | String / Null        | Descrição do último erro grave não tratado ou erro interno de stats.        | Alerta rápido para problemas críticos recentes.                                                                                 |
| `last_error_timestamp` | 📅    | Datetime / Null      | Timestamp do último erro grave.                                           | Contextualiza quando o último problema grave ocorreu.                                                                           |
| `system`               | 💻    | Dict                 | Métricas do Sistema Operacional e do Processo (via `psutil`).             | **KPIs de Saúde do Host e Aplicação:** Monitoramento essencial de recursos.                                                     |
| `system.cpu_percent`   | <0xF0><0x9F><0xA7><0xAF> | Float (Gauge)        | Uso % CPU do sistema.                                                     | **KPI:** Saúde do Host. Alertas para uso excessivo.                                                                              |
| `system.memory_*_gb`   | 🧠    | Float (Gauge)        | Uso de Memória RAM do sistema (Total, Disponível, Usada).                 | **KPI:** Saúde do Host. Alertas para baixa memória disponível.                                                                 |
| `system.memory_percent`| ％    | Float (Gauge)        | Uso % Memória RAM do sistema.                                             | **KPI:** Saúde do Host (percentual).                                                                                            |
| `system.disk_usage`    | 💾    | Dict (Gauge)         | Uso de Disco por partição (% usado, GB livres, etc.).                     | **KPI:** Saúde do Host / Risco de Esgotamento. Crítico para persistência de dados (DB e logs).                                 |
| `system.process_memory_*_mb` | 💭 | Float (Gauge)      | Uso de Memória (RSS, VMS) pelo processo da API.                           | **KPI:** Consumo de Recursos da Aplicação. Detectar memory leaks.                                                              |
| `system.process_cpu_percent` | <0xF0><0x9F><0xA7><0xAF> | Float (Gauge)    | Uso % CPU pelo processo da API.                                           | **KPI:** Consumo de Recursos da Aplicação. Identificar gargalos de processamento na API.                                        |
| `system.load_average`  | 🏋️    | Tuple[float]/str     | Média de carga do sistema (Unix-like).                                    | **KPI:** Carga do Host. Indica demanda geral sobre o sistema.                                                                  |
| `system.open_file_descriptors` | 🗂️ | Int/str (Gauge)    | Arquivos abertos pelo processo.                                           | Monitoramento de limites do sistema operacional.                                                                               |
| `system.thread_count`  |🧵     | Int/str (Gauge)      | Threads do processo.                                                      | Monitoramento interno da aplicação (relevante para concorrência).                                                              |
| `broker_specific`      | 🛠️    | Dict                 | Metadados da API (versão, DB, auth, etc.).                                | Contexto para diagnóstico e versionamento.                                                                                      |

**Potenciais KPIs derivados de `/stats`:**

*   **Taxa de Publicação:** `requests_by_route["/queues/{queue_name}/messages"]["POST"]` por unidade de tempo.
*   **Taxa de Consumo (Tentativas):** `requests_by_route["/queues/{queue_name}/messages/consume"]["GET"]` por unidade de tempo.
*   **Taxa de Consumo (Sucesso):** Variação de `messages_pending` (diminui) e `messages_processing` (aumenta) por unidade de tempo.
*   **Taxa de ACK:** `requests_by_route["/messages/{message_id}/ack"]["POST"]` por unidade de tempo OU variação de `messages_processing` (diminui) e `messages_processed` (aumenta).
*   **Taxa de NACK (Falha):** Variação de `messages_processing` (diminui) e `messages_failed` (aumenta) quando `requeue=false`.
*   **Taxa de NACK (Requeue):** Variação de `messages_processing` (diminui) e `messages_pending` (aumenta) quando `requeue=true`.
*   **Percentual de Erros:** (`requests_by_status["5xx"]` + `requests_by_status["4xx"]`) / `requests_total` * 100.
*   **Tempo Médio em Processamento (Estimado):** Se `messages_processing` está alto e a Taxa de ACK está baixa, indica lentidão.

---

### 2. Endpoints `/queues`

*   **Rotas:**
    *   `GET /queues`: Lista todas as filas.
    *   `GET /queues/{queue_name}`: Detalhes de uma fila específica.
    *   `POST /queues`: Cria uma nova fila.
    *   `DELETE /queues/{queue_name}`: Remove uma fila e suas mensagens.
*   **Autenticação:** ✅ Obrigatória (JWT Access Token)
*   **Rate Limit:** Varia (`60/minute` para GET, `30/minute` para POST, `10/minute` para DELETE)
*   **Propósito Principal:** Gerenciar filas e obter uma visão geral do inventário e tamanho total das filas.
*   **Formato Retornado (GET):** Lista de `QueueResponse` ou um único `QueueResponse`.

**Métricas Detalhadas no `QueueResponse`:**

| Campo           | Emoji | Tipo     | Descrição                                                    | Relevância para Dashboard/KPI                                                                         |
| :-------------- | :---- | :------- | :----------------------------------------------------------- | :---------------------------------------------------------------------------------------------------- |
| `id`            | 🆔    | Integer  | ID da fila no banco de dados.                                | Identificador único.                                                                                  |
| `name`          | 🏷️    | String   | Nome da fila.                                                | Identificador legível, usado para filtrar/agrupar métricas por fila.                                   |
| `created_at`    | ➕    | Datetime | Timestamp de criação da fila.                                | Contexto histórico.                                                                                   |
| `updated_at`    | ✨    | Datetime | Timestamp da última atualização (geralmente na criação).     | Contexto histórico.                                                                                   |
| `message_count` | 🔢    | Integer  | Contagem **total** de mensagens associadas a esta fila (todos os status). | **Indicador:** Tamanho geral da fila. **Atenção:** Não representa o backlog (`messages_pending`). |

**Potenciais KPIs derivados de `/queues`:**

*   **Inventário de Filas:** Contagem total de filas (`len(response)` em `GET /queues`).
*   **Tamanho Total por Fila:** O valor `message_count` para cada fila. Útil para identificar filas "grandes", mas precisa ser correlacionado com `messages_pending` do `/stats` para entender o backlog real.

---

### 3. Endpoints de Ações de Mensagem

*   **Rotas:**
    *   `POST /queues/{queue_name}/messages` (Publish)
    *   `GET /queues/{queue_name}/messages/consume` (Consume)
    *   `POST /messages/{message_id}/ack` (Acknowledge)
    *   `POST /messages/{message_id}/nack` (Negative Acknowledge)
*   **Autenticação:** ✅ Obrigatória (JWT Access Token)
*   **Rate Limit:** `HIGH_TRAFFIC_RATE_LIMIT` (`200/second` padrão)
*   **Propósito Principal:** Executar o fluxo principal do message broker. As **taxas** e **sucesso/falha** destas operações são KPIs essenciais.
*   **Formato Retornado:** Varia (ID da mensagem, detalhes da mensagem consumida, confirmação de status).

**Relevância para Dashboards/KPIs:**

*   Monitorar as **contagens de chamadas** a estas rotas (via `/stats` -> `requests_by_route`).
*   Monitorar os **códigos de status** das respostas (via `/stats` -> `requests_by_status`, especialmente 200, 201, 204, 404, 409, 500 para estas rotas específicas).
*   Correlacionar essas taxas com as **mudanças nos contadores** `messages_pending`, `messages_processing`, `messages_processed`, `messages_failed` no `/stats`.

**Exemplos:**

*   **Dashboard de Throughput:** Plotar a taxa de `messages_processed` (derivada do `/stats`) ao longo do tempo.
*   **Dashboard de Backlog:** Plotar `messages_pending` (do `/stats`) ao longo do tempo, possivelmente segmentado por nome da fila (requer lógica adicional ou GraphQL).
*   **Dashboard de Erros de Processamento:** Plotar a taxa de `messages_failed` (derivada do `/stats`) e a taxa de chamadas NACK (via `requests_by_route`).

---

## 🍓 Análise do Endpoint GraphQL (`/graphql`)

*   **Rota:** `POST /graphql` (normalmente)
*   **Autenticação:** ✅ Obrigatória (JWT Access Token via `Authorization: Bearer <token>`) - Verificada no `get_graphql_context`.
*   **Rate Limit:** Aplicado globalmente pela middleware, mas não específico por query/mutation por padrão neste código.
*   **Propósito Principal:** Oferecer uma interface de consulta flexível para dados de filas e mensagens, complementar ao REST.
*   **Ferramenta:** Inclui IDE Apollo Sandbox (`https://localhost:8777/graphql`) para exploração interativa.

**Queries e Mutações Relevantes para Monitoramento:**

*   **`query all_queues`:** Similar a `GET /queues`. Retorna `[QueueGQL]`.
    *   `QueueGQL.message_count`: Igual ao REST `message_count` (total de mensagens na fila).
*   **`query queue_by_name(name: String!)`:** Similar a `GET /queues/{queue_name}`. Retorna `QueueGQL`.
*   **`query message_by_id(id: ID!)`:** Busca uma mensagem específica. Retorna `MessageGQL`.
*   **`QueueGQL.messages(status: String, limit: Int, offset: Int)`:** **Muito útil!** Permite buscar mensagens *dentro* de uma fila, filtrando por `status` ('pending', 'processing', 'processed', 'failed') e com paginação.
    *   **Relevância:** Permite criar dashboards que mostram não apenas a *contagem* de pendentes/falhas, mas também *exemplos* dessas mensagens recentes para diagnóstico.
*   **Mutações (`create_queue`, `delete_queue`, `publish_message`):** Equivalentes às operações REST, mas via GraphQL. O monitoramento das *taxas de chamada* a estas mutações (se possível através de logs ou APM externo) é relevante.

**Vantagens do GraphQL para Dashboards:**

*   Buscar dados específicos de múltiplas fontes (ex: contagem pendente de 3 filas específicas) em uma única requisição.
*   Filtrar mensagens por status diretamente na query (ex: buscar as 10 últimas mensagens 'failed' da fila 'X').

---

## 📄 Análise dos Endpoints de Logs (`/logs`)

*   **Rotas:**
    *   `GET /logs`: Lista os arquivos de log `.json` disponíveis no diretório `logs_v3`.
    *   `GET /logs/{filename}`: Retorna o conteúdo de um arquivo de log específico, com opções de paginação (`start`, `end`) e `tail`.
*   **Autenticação:** ✅ Obrigatória (JWT Access Token)
*   **Rate Limit:** `10/minute` para listar, `60/minute` para ler conteúdo.
*   **Propósito Principal:** Permitir a inspeção manual e programática dos logs detalhados de eventos do servidor para *troubleshooting* e análise forense. **Não ideal para dashboards em tempo real** diretamente via API, mas essencial para ferramentas de agregação.
*   **Formato do Log (JSON por linha):**

```json
{
  "timestamp": "2023-10-27T10:30:00.123Z", // ISO 8601 UTC
  "level": "INFO", // DEBUG, INFO, WARNING, ERROR, CRITICAL
  "name": "MessageBroker", // Logger name
  "pid": 12345,
  "thread": "MainThread",
  "message": "✅ Message ID 567 acknowledged successfully by 'admin' (status -> processed).", // Mensagem principal
  "pathname": "/app/server.py", // Arquivo de origem
  "lineno": 850, // Linha de origem
  "icon_type": "MSG", // Ícone/Categoria (definido nas chamadas log_*)
  "extra_data": { // Dados adicionais, se fornecidos
    "client": "127.0.0.1",
    "user": "admin"
  },
  "exception": { // Presente apenas em logs de erro com traceback
    "type": "IntegrityError",
    "value": "UNIQUE constraint failed: queues.name",
    "traceback": "Traceback (most recent call last): ..." // (Oculto em produção por padrão)
  }
}


Uso dos Logs para Dashboards (Com Ferramentas Externas - ELK, Loki, Splunk, etc.):

Contagem de Erros Específicos: Agregação de logs com level: ERROR ou CRITICAL para identificar padrões.

Frequência de Eventos: Contagem de logs com icon_type específicos (ex: 'AUTH', 'DB', 'SEC') para monitorar atividades específicas.

Análise de Performance: Se tempos de processamento forem logados em extra_data, podem ser extraídos e agregados.

Auditoria: Rastrear eventos de login (icon_type: AUTH), criação/deleção de filas (icon_type: QUEUE), etc.

Diagnóstico Detalhado: Filtrar logs por message_id ou queue_name (se logados em extra_data ou message) para entender o ciclo de vida de uma mensagem específica.

⏱️ Monitoramento de Latência (X-Process-Time)
Cada resposta da API (exceto erros muito precoces) inclui o cabeçalho X-Process-Time.

Exemplo: X-Process-Time: 0.0123s

Significado: Tempo gasto dentro do servidor para processar a requisição específica (não inclui latência de rede).

Relevância para Dashboard/KPI:

Coletar este valor para endpoints críticos (publish, consume, ack).

Calcular médias, percentis (p95, p99) e plotar ao longo do tempo.

KPI: Latência de Processamento da API. Picos indicam lentidão no servidor ou no banco de dados.

🎯 Resumo dos KPIs Chave para Dashboards
Aqui está uma lista consolidada dos KPIs mais importantes que você pode derivar dos dados fornecidos:

Performance e Throughput:

✅ Taxa de Mensagens Processadas com Sucesso (ACK Rate): (Derivado de /stats: messages_processed ou requests_by_route para /ack) - Quantas mensagens úteis o sistema processa.

📤 Taxa de Publicação: (Derivado de /stats: requests_by_route para /publish) - Quão rápido novas mensagens entram.

📥 Taxa de Consumo (Sucesso): (Derivado de /stats: variação messages_pending/messages_processing) - Quão rápido as mensagens são retiradas para processamento.

⏱️ Latência de Processamento (p95/p99): (Derivado do header X-Process-Time) - Quão rápido a API responde internamente.

Backlog e Filas:

📥 Tamanho do Backlog (Pending Messages): (/stats: messages_pending) - Quantas mensagens estão esperando. KPI crítico de acúmulo.

⚙️ Mensagens em Processamento (In-Flight): (/stats: messages_processing) - Quantas mensagens estão sendo trabalhadas. Picos podem indicar problemas nos consumidores.

📁 Contagem de Filas Ativas: (/stats: queues_total) - Visão geral da configuração.

Erros e Falhas:

❌ Taxa de Falha Permanente (Failed Messages): (Derivado de /stats: messages_failed ou requests_by_route para /nack com requeue=false) - Quantas mensagens não puderam ser processadas.

🔄 Taxa de Re-enfileiramento (NACK com Requeue): (Derivado de /stats: requests_by_route para /nack com requeue=true) - Quantas mensagens falharam temporariamente e voltaram para a fila.

🚦 Taxa de Erros HTTP (4xx/5xx): (/stats: requests_by_status) - Problemas gerais na comunicação com a API.

🔥 Contagem de Erros Críticos/Exceções: (Derivado de Logs ou /stats: last_error) - Indicador de problemas graves.

Saúde do Sistema:

<0xF0><0x9F><0xA7><0xAF> Uso de CPU (Sistema e Processo): (/stats: system.*cpu*) - Saturação de processamento.

🧠 Uso de Memória (Sistema e Processo): (/stats: system.*memory*) - Risco de falta de memória / memory leaks.

💾 Uso de Disco: (/stats: system.disk_usage) - Risco de esgotamento de espaço (crítico para DB/logs).

⏳ Uptime: (/stats: uptime_seconds) - Disponibilidade do serviço.

🛡️ Dados de Contexto e Segurança
Embora não sejam KPIs diretos, informações como:

Versão da API (/, /stats)

Configuração de CORS (settings.ALLOWED_ORIGINS)

Método de Autenticação (JWT - /login, /refresh)

Configuração do Banco de Dados (settings.DATABASE_URL)

...são úteis para entender o ambiente e diagnosticar problemas relacionados à configuração ou segurança, e podem ser exibidas em seções informativas do dashboard.

✅ Conclusão
A API Message Broker V3.1.5 fornece um conjunto robusto de métricas e dados através de seus endpoints REST (/stats, /queues, /logs), do cabeçalho X-Process-Time e da interface GraphQL (/graphql). Combinando essas fontes, é possível construir dashboards abrangentes para monitorar a performance, o backlog, as taxas de erro e a saúde geral do sistema, permitindo uma operação confiável e a identificação rápida de problemas. A chave é focar nos contadores e gauges do endpoint /stats para KPIs em tempo real e usar logs para análises mais profundas quando necessário.



