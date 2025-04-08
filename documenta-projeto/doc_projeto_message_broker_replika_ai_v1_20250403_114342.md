# 📄 Documentação do Projeto: projeto message broker replika ai v1

**Gerado em:** 2025-04-03 11:43:42
**Plataforma:** Windows 10
**Modelo IA:** gemini-1.5-flash
**Arquivos Analisados:**
- `projeto message broker replika ai v1\message-broker-v2-clean.py`
- `projeto message broker replika ai v1\webdashv2-clean.py`
- `projeto message broker replika ai v1\webdocv1.py`

---

# Documentação Técnica: Message Broker API v3.1.4

**Propriedade Intelectual:** Elias Andrade - Maringá, Paraná - 03/04/2025 - Replika AI Solutions

Este documento descreve a arquitetura e funcionalidades da Message Broker API v3.1.4, um serviço assíncrono de gerenciamento de filas de mensagens construído com FastAPI, Tortoise ORM e SQLite.  A API oferece endpoints RESTful e GraphQL para publicação, consumo e gerenciamento de mensagens, além de recursos de monitoramento e logging.

## 1. Visão Geral e Propósito

O Message Broker API v3.1.4 visa fornecer uma solução robusta e escalável para o gerenciamento de filas de mensagens. Ele permite que aplicações publiquem mensagens assincronamente em filas nomeadas e que outras aplicações consumam essas mensagens de forma ordenada e confiável.  A solução simplifica o desenvolvimento de sistemas distribuídos, permitindo a comunicação desacoplada entre componentes.  A API inclui recursos de monitoramento para acompanhar o desempenho e o status do sistema, além de um sistema de logging detalhado para facilitar a depuração e auditoria.

## 2. Funcionalidades Chave

* **Gerenciamento de Filas:** Criação, listagem e deleção de filas de mensagens.
* **Publicação de Mensagens:** Envio assíncrono de mensagens para filas específicas.
* **Consumo de Mensagens:** Consumo atômico da mensagem mais antiga em uma fila, com mecanismo de *lock* para garantir a integridade.
* **ACK/NACK:** Mecanismo de confirmação (ACK) e rejeição (NACK) de mensagens consumidas.
* **Autenticação JWT:** Uso de JSON Web Tokens (JWT) para autenticação segura dos clientes.
* **Monitoramento:** Endpoints para obter estatísticas detalhadas do sistema, incluindo métricas de desempenho e contagem de mensagens.
* **Logging:** Geração de logs estruturados em formato JSON, com gravação em arquivo e console.
* **Interface GraphQL:** Exposição da funcionalidade principal através de uma API GraphQL, oferecendo flexibilidade na consulta de dados.
* **Tratamento de Erros:** Implementação de tratamento de erros robusto, com respostas padronizadas e logging detalhado.
* **Geração de Certificado SSL:** Geração automática de certificado auto-assinado para uso em ambiente de desenvolvimento.


## 3. Estrutura do Projeto

O projeto é composto por dois arquivos principais: `message-broker-v2-clean.py` e `webdashv2-clean.py`.  Existe também o arquivo `webdocv1.py` que gera a documentação HTML estática.

* **`message-broker-v2-clean.py`:** Este arquivo contém a implementação principal da API, incluindo a definição dos endpoints RESTful e GraphQL, o gerenciamento do banco de dados (SQLite via Tortoise ORM), a lógica de tratamento de mensagens e os mecanismos de autenticação (JWT).  Ele também inclui a configuração de logging, middleware para CORS e rate limiting, e o servidor Uvicorn.

* **`webdashv2-clean.py`:**  Este arquivo implementa um painel de controle baseado em Flask que monitora a API. Ele periodicamente coleta dados de estatísticas da API principal através de requisições HTTP e os exibe em gráficos e indicadores.  Utiliza Chart.js para a renderização dos gráficos.

* **`webdocv1.py`:** Este arquivo gera uma página HTML estática contendo a documentação da API, incluindo exemplos de requisições e respostas, além de detalhes sobre autenticação, rate limiting e tratamento de erros.

O fluxo principal de dados e controle é o seguinte:

1. **Clientes** enviam requisições HTTP (REST ou GraphQL) para `message-broker-v2-clean.py`.
2. A API (`message-broker-v2-clean.py`) processa as requisições, interage com o banco de dados (SQLite) via Tortoise ORM e retorna as respostas.
3. O painel de controle (`webdashv2-clean.py`) periodicamente faz requisições para obter dados de monitoramento da API.
4. A documentação (`webdocv1.py`) é uma página HTML estática, independente do funcionamento da API.


## 4. Componentes Importantes

### 4.1 `message-broker-v2-clean.py`

**4.1.1 Configurações (`settings`):** Define parâmetros importantes como porta do servidor, chave secreta JWT, URL do banco de dados, diretórios de logs e certificados, origens permitidas para CORS, e limites de rate limiting.  A chave secreta JWT deve ser gerada aleatoriamente e armazenada em uma variável de ambiente em produção para segurança.

**4.1.2 Logging:** Implementa um sistema de logging robusto, com handlers para console (com cores via Colorama) e arquivo (formato JSON).  Utiliza um `JsonFormatter` personalizado para logs estruturados.

**4.1.3 Geração de Certificado SSL:** Inclui uma função `generate_self_signed_cert` para gerar um certificado auto-assinado para uso em desenvolvimento, utilizando a biblioteca `cryptography`.

**4.1.4 Modelos Pydantic:** Define modelos Pydantic para validação e serialização de dados de entrada e saída, garantindo a consistência dos dados.

**4.1.5 Modelos Tortoise ORM:** Define modelos Tortoise ORM (`Queue` e `Message`) para a representação de filas e mensagens no banco de dados SQLite.  Define relações entre os modelos, incluindo uma ForeignKey de `Message` para `Queue` e uma ReverseRelation para acesso conveniente às mensagens de uma fila.

**4.1.6 Autenticação JWT:** Implementa autenticação com JWT, incluindo funções para geração de tokens (access e refresh), decodificação e validação. Dependencias para autenticação são criadas utilizando `Depends` no FastAPI.

**4.1.7 Middleware:** Utiliza middleware para atualizar estatísticas de requisições, aplicar CORS e rate limiting.

**4.1.8 Endpoints FastAPI:** Define os endpoints RESTful da API para gerenciamento de filas e mensagens, incluindo handlers de exceções personalizados.

**4.1.9 GraphQL:** Define o esquema e resolvers GraphQL usando Strawberry, fornecendo uma interface alternativa à API REST.

**4.1.10 Tratamento de Exceções:** Implementa handlers de exceções globais para lidar com erros comuns, como `DoesNotExist`, `IntegrityError` e `ValidationError`, retornando respostas JSON padronizadas.


### 4.2 `webdashv2-clean.py`

**4.2.1 Configurações:** Define a porta do servidor do painel, URL base da API principal, credenciais para acesso à API e intervalo de coleta de dados. **IMPORTANTE:** Em produção, as credenciais devem ser configuradas via variáveis de ambiente.

**4.2.2 Estado da Aplicação:** Mantém o estado da aplicação, incluindo as estatísticas mais recentes, histórico para gráficos, status de login e um mecanismo de *lock* para acesso concorrente seguro.

**4.2.3 Funções de Coleta de Dados:** `login_to_api` e `fetch_api_data` são responsáveis pela autenticação na API principal e pela coleta periódica de dados.

**4.2.4 Servidor Flask:** Implementa um servidor Flask para servir a interface web do painel e um endpoint `/api/dashboard_data` para fornecer dados ao cliente JavaScript.

**4.2.5 Interface Web:** Utiliza uma template HTML com CSS embutido e Chart.js para a visualização de dados.

### 4.3 `webdocv1.py`

Este arquivo é um servidor Flask simples que serve uma página HTML estática contendo a documentação da API.  O conteúdo HTML é gerado diretamente no código Python e inclui CSS embutido para estilização.


## 5. Como Usar/Executar

### 5.1 `message-broker-v2-clean.py`

1. **Instalação de Dependências:** Execute `pip install -r requirements.txt` (crie um `requirements.txt` com as dependências listadas no código fonte).
2. **Configuração:** Configure as variáveis de ambiente necessárias, principalmente `JWT_SECRET_KEY`.  Considere configurar outras variáveis para produção.
3. **Execução:** Execute o script `message-broker-v2-clean.py` usando `python message-broker-v2-clean.py`.  O servidor Uvicorn iniciará e a API estará disponível em `https://localhost:8777` (ou a porta definida em `settings.API_PORT`).


### 5.2 `webdashv2-clean.py`

1. **Instalação de Dependências:** Execute `pip install flask requests schedule flask-cors`
2. **Configuração:** Configure as variáveis de ambiente `API_BASE_URL`, `API_USER`, e `API_PASS` apontando para a sua API principal.
3. **Execução:** Execute o script `webdashv2-clean.py` usando `python webdashv2-clean.py`. O servidor Flask iniciará e o painel estará disponível em `http://localhost:8333` (ou a porta definida em `DASHBOARD_PORT`).

### 5.3 `webdocv1.py`

1. **Instalação de Dependências:** Execute `pip install flask`
2. **Configuração:** Configure `API_BASE_URL` no código para apontar para a sua API principal.
3. **Execução:** Execute o script `webdocv1.py` usando `python webdocv1.py`.  A documentação estará acessível em `http://localhost:8112`.


## 6. Dependências Externas

* `asyncio`
* `json`
* `logging`
* `os`
* `platform`
* `secrets`
* `sys`
* `time`
* `traceback`
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
* `requests`
* `schedule`
* `flask`
* `flask_cors`
* `urllib3` (opcional, para desabilitar warnings de SSL)


## 7. Considerações Adicionais

* **Segurança:** A chave secreta JWT (`JWT_SECRET_KEY`) **deve** ser gerada aleatoriamente e armazenada em uma variável de ambiente em produção.  A configuração `ALLOWED_ORIGINS` para CORS deve listar apenas as origens permitidas em produção, evitando o uso de `"*"`.  As credenciais padrão (`admin`/`admin`) para login devem ser substituídas por um sistema de autenticação seguro em produção (por exemplo, usando `passlib` para hash de senhas).

* **Escalabilidade:** O uso de SQLite é adequado para desenvolvimento e testes, mas para produção, considere um banco de dados relacional mais robusto e escalável, como PostgreSQL ou MySQL.

* **Monitoramento:** O painel de controle fornece um monitoramento básico. Para produção, considere ferramentas de monitoramento mais avançadas, como Prometheus e Grafana.

* **Tratamento de Erros:** Os handlers de exceções globais garantem uma resposta consistente em caso de erros, mas é importante adicionar tratamento de erros específico em cada endpoint para lidar com casos mais específicos.

* **Documentação:** A documentação HTML gerada pelo `webdocv1.py` é estática.  Considere usar ferramentas de geração de documentação automática, como Swagger/OpenAPI, para facilitar a manutenção da documentação.


Esta documentação fornece uma visão geral completa do projeto.  Para detalhes mais específicos, consulte o código fonte.  Lembrando que este código foi concebido para demonstração e desenvolvimento, e precisa de ajustes para implementação em produção.
