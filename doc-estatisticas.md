Okay, vamos analisar detalhadamente o código Python desse servidor FastAPI para entender todos os tipos de dados, estatísticas e KPIs que ele fornece e que podem ser usados para criar dashboards.

O servidor é uma API de Message Broker, o que significa que seu propósito principal é receber mensagens, armazená-las em filas e permitir que consumidores as processem. Os dados gerados refletem essa funcionalidade, além de métricas operacionais e de sistema.

Fontes Principais de Dados para Dashboards:

Endpoint /stats (Monitoramento): Este é o endpoint mais rico em dados agregados e estatísticas, projetado especificamente para monitoramento e, consequentemente, dashboards.

Endpoints de Filas (/queues): Fornecem informações sobre as filas existentes e a contagem de mensagens nelas.

Endpoints de Mensagens (/messages e sub-rotas): As ações nesses endpoints (publicar, consumir, ack, nack) geram eventos cujas taxas e resultados são cruciais para dashboards, refletidos principalmente no endpoint /stats.

Endpoint /graphql: Oferece uma forma alternativa (via GraphQL) de buscar dados sobre filas e mensagens, incluindo contagens e listas.

Logs (/logs e /logs/{filename}): Embora não sejam uma fonte direta para dashboards em tempo real via API, os logs (especialmente os JSON) contêm dados detalhados sobre cada evento. Ferramentas externas de agregação de logs (como ELK, Loki, Splunk) podem processá-los para gerar métricas mais granulares para dashboards.

Tipos de Dados e Estatísticas Detalhadas:

1. Dados do Endpoint /stats (Modelo StatsResponse)

Este endpoint requer autenticação e retorna um objeto JSON com as seguintes informações:

Métricas Gerais do Servidor:

start_time: Timestamp (ISO 8601 UTC) de quando o servidor foi iniciado. (Tipo: Datetime) - Útil para saber há quanto tempo está no ar.

uptime_seconds: Tempo de atividade do servidor em segundos. (Tipo: Float) - KPI: Uptime.

uptime_human: Tempo de atividade do servidor em formato legível (ex: "2d 5h 10m 3s"). (Tipo: String) - KPI: Uptime (visual).

Métricas de Requisições HTTP:

requests_total: Número total de requisições HTTP recebidas pelo servidor desde o início (excluindo rotas de documentação/internas). (Tipo: Integer - Contador) - KPI: Carga Total.

requests_by_route: Dicionário detalhando quantas vezes cada rota (endpoint + método HTTP) foi acessada. Ex: {"/queues/{queue_name}/messages": {"POST": 1500}, "/messages/{message_id}/ack": {"POST": 1200}}. (Tipo: Dict[str, Dict[str, int]] - Contadores) - KPIs: Taxa de Publicação, Taxa de Consumo (tentativas), Taxa de ACK, Taxa de NACK, Uso de API por endpoint.

requests_by_status: Dicionário detalhando quantas respostas foram enviadas para cada código de status HTTP (ex: "200", "201", "404", "500"). (Tipo: Dict[str, int] - Contadores) - KPIs: Taxa de Sucesso, Taxa de Erro (4xx, 5xx).

Métricas do Message Broker (KPIs Fundamentais):

queues_total: Número total de filas existentes no momento. (Tipo: Integer - Gauge) - Visão geral da configuração.

messages_total: Número total de mensagens que já passaram pelo sistema (soma de todos os status). (Tipo: Integer - Contador) - Volume total processado.

messages_pending: Número de mensagens atualmente na fila esperando para serem consumidas (status 'pending'). (Tipo: Integer - Gauge) - KPI: Backlog / Tamanho da Fila Pendente.

messages_processing: Número de mensagens que foram consumidas mas ainda não foram confirmadas (ACK/NACK) (status 'processing'). (Tipo: Integer - Gauge) - KPI: Mensagens em Voo / Trabalho em Progresso.

messages_processed: Número total de mensagens que foram processadas com sucesso (status 'processed'). (Tipo: Integer - Contador) - KPI: Throughput / Vazão de Sucesso.

messages_failed: Número total de mensagens que falharam no processamento e não foram recolocadas na fila (status 'failed'). (Tipo: Integer - Contador) - KPI: Taxa de Falha Permanente.

Monitoramento de Erros:

last_error: Descrição do último erro grave (não tratado ou erro na atualização de stats). (Tipo: String / Null) - Alerta de problemas recentes.

last_error_timestamp: Timestamp do último erro grave. (Tipo: Datetime / Null) - Contexto temporal do erro.

Informações do Sistema (via psutil):

system: Dicionário com informações estáticas (versão Python, plataforma OS) e dinâmicas (requer psutil instalado):

cpu_percent: Uso percentual da CPU do sistema inteiro. (Tipo: Float - Gauge) - KPI: Saúde do Host.

memory_total_gb, memory_available_gb, memory_used_gb, memory_percent: Uso de memória RAM do sistema. (Tipo: Float/Integer - Gauge) - KPI: Saúde do Host.

disk_usage: Dicionário com uso de disco por partição (total, usado, livre, percentual). (Tipo: Dict - Gauge) - KPI: Saúde do Host / Risco de Esgotamento.

process_memory_rss_mb, process_memory_vms_mb, process_memory_mb: Uso de memória pelo processo do servidor. (Tipo: Float - Gauge) - KPI: Consumo de Recursos da Aplicação.

process_cpu_percent: Uso percentual da CPU pelo processo do servidor. (Tipo: Float - Gauge) - KPI: Consumo de Recursos da Aplicação.

load_average: Média de carga do sistema (em sistemas Unix-like). (Tipo: Tuple[float] / String "N/A" - Gauge) - KPI: Carga do Host.

cpu_count_logical, cpu_count_physical: Número de CPUs. (Tipo: Integer) - Info de Contexto.

open_file_descriptors: Número de arquivos abertos pelo processo. (Tipo: Integer / String "N/A" - Gauge) - Monitoramento de Limites.

thread_count: Número de threads do processo. (Tipo: Integer / String "N/A" - Gauge) - Monitoramento Interno.

Informações Específicas do Broker:

broker_specific: Dicionário com metadados sobre a configuração do broker (framework, versão, DB, auth, etc.). (Tipo: Dict) - Info de Contexto/Diagnóstico.

2. Dados dos Endpoints de Filas (/queues e /queues/{queue_name})

/queues (GET): Retorna uma lista de objetos QueueResponse.

Cada QueueResponse contém:

id: ID da fila no banco de dados. (Tipo: Integer)

name: Nome da fila. (Tipo: String)

created_at, updated_at: Timestamps. (Tipo: Datetime)

message_count: Número total de mensagens associadas a essa fila no banco de dados (independente do status: pending, processing, etc.). (Tipo: Integer - Gauge) - Pode ser usado para visualizar o tamanho total de cada fila individualmente.

/queues/{queue_name} (GET): Retorna um único QueueResponse para a fila especificada, com os mesmos campos acima.

3. Dados Implícitos das Ações (Publicar, Consumir, ACK, NACK)

Embora os endpoints de ação não retornem estatísticas diretamente, as taxas com que são chamados e seus resultados (sucesso/erro, refletido nos status codes e mudanças nos contadores do /stats) são KPIs essenciais:

Taxa de Publicação: Número de chamadas bem-sucedidas (201 Created) para POST /queues/{queue_name}/messages por unidade de tempo. (Derivado de /stats -> requests_by_route).

Taxa de Consumo (Tentativas): Número de chamadas para GET /queues/{queue_name}/messages/consume por unidade de tempo. (Derivado de /stats -> requests_by_route). Inclui tentativas que retornam 204 (fila vazia).

Taxa de Consumo (Sucesso): Número de chamadas bem-sucedidas (200 OK) para GET /queues/{queue_name}/messages/consume. (Derivado de /stats -> requests_by_status['200'] correlacionado com a rota, ou pela diminuição em messages_pending e aumento em messages_processing).

Taxa de ACK (Processamento com Sucesso): Número de chamadas bem-sucedidas (200 OK) para POST /messages/{message_id}/ack. (Derivado de /stats -> requests_by_route ou pela diminuição em messages_processing e aumento em messages_processed).

Taxa de NACK (Falha/Reprocessamento): Número de chamadas bem-sucedidas (200 OK) para POST /messages/{message_id}/nack. (Derivado de /stats -> requests_by_route ou pela diminuição em messages_processing e aumento em messages_failed ou messages_pending).

Latência: O header X-Process-Time adicionado nas respostas indica o tempo de processamento dentro do servidor para aquela requisição específica. Monitorar a média/percentis desse valor para endpoints críticos (publish, consume) é um KPI importante. (Tipo: Float - segundos).

4. Dados do Endpoint /graphql

Permite buscar dados de forma flexível:

all_queues: Similar ao REST /queues, retorna lista de QueueGQL (id, name, created_at, updated_at).

queue_by_name: Similar ao REST /queues/{queue_name}.

message_by_id: Busca detalhes de uma mensagem específica (MessageGQL: id, queue_name, content, status, etc.).

Campos dentro de QueueGQL:

message_count: Igual ao REST, conta todas as mensagens da fila.

messages: Permite buscar uma lista paginada de mensagens (MessageGQL) dentro de uma fila, com opção de filtrar por status. Útil para dashboards que precisam mostrar exemplos de mensagens recentes (ex: últimas falhas).

5. Dados dos Logs (/logs, /logs/{filename})

Fornece acesso aos arquivos de log JSON brutos.

Cada linha do log JSON (JsonFormatter) contém: timestamp, level, name, pid, thread, message, pathname, lineno, icon_type (se houver), extra_data (se houver), exception (se houver erro, com traceback em dev).

Dashboard Use (com ferramentas externas):

Contagem de erros específicos (filtrando por level: ERROR ou CRITICAL e message).

Frequência de eventos específicos (filtrando por message ou icon_type).

Análise de performance por tipo de operação (extraindo tempos de message se logados).

Auditoria de segurança (rastreando logins, acessos negados, etc., se logados).

Resumo para Criação de Dashboards:

Para criar dashboards eficazes com os dados deste servidor:

Principal Fonte: Use o endpoint /stats para obter a maioria dos KPIs agregados (contagens de mensagens por status, taxas de requisição, uso de recursos).

Visão Geral das Filas: Use /queues para listar as filas e seus tamanhos totais.

Monitoramento de Taxas: Monitore as taxas de chamadas aos endpoints de ação (publish, consume, ack, nack) usando requests_by_route do /stats. Combine isso com as mudanças nos contadores messages_pending, messages_processing, etc., para entender o fluxo.

Saúde do Sistema: Monitore CPU, memória e disco do /stats para garantir que o servidor tem recursos suficientes.

Monitoramento de Erros: Use requests_by_status (códigos 4xx, 5xx) e last_error do /stats para alertas rápidos. Para análise profunda de erros, use os logs (via /logs e ferramentas externas).

GraphQL: Use se precisar de buscas mais flexíveis ou se seu dashboard já usa GraphQL. Ele replica muitas das informações REST.

Latência: Capture e agregue o header X-Process-Time para monitorar a performance das requisições.

Essencialmente, o servidor fornece contadores, gauges (medidores instantâneos), timestamps e informações descritivas, que são a base para a maioria dos dashboards de monitoramento de aplicações e sistemas.