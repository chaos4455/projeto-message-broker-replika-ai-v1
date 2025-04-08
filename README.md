# 🚀 Replika Message Broker - Replika AI Solutions 🚀

[![Status do Workflow (main)](https://img.shields.io/github/actions/workflow/status/chaos4455/message-broker-replika/docker-build.yml?branch=main&style=for-the-badge&logo=githubactions&label=CI%2FCD%20Pipeline)](https://github.com/chaos4455/message-broker-replika/actions/workflows/docker-build.yml)
[![Docker Pulls](https://img.shields.io/docker/pulls/chaos4455/message-broker-replika?style=for-the-badge&logo=docker&label=Pulls%20DockerHub)](https://hub.docker.com/r/chaos4455/message-broker-replika)
[![Tamanho da Imagem Docker (latest)](https://img.shields.io/docker/image-size/chaos4455/message-broker-replika/latest?style=for-the-badge&logo=docker&label=Tamanho%20da%20Imagem)](https://hub.docker.com/r/chaos4455/message-broker-replika)
[![Licença](https://img.shields.io/github/license/chaos4455/message-broker-replika?style=for-the-badge&label=Licen%C3%A7a)](LICENSE) <!-- Certifique-se de ter um arquivo LICENSE -->
[![Python Version](https://img.shields.io/badge/Python-3.x-blue?style=for-the-badge&logo=python)](https://www.python.org/)
[![Framework Principal](https://img.shields.io/badge/Framework-FastAPI-green?style=for-the-badge&logo=fastapi)](https://fastapi.tiangolo.com/)
[![Estabilidade](https://img.shields.io/badge/Estabilidade-Beta-yellow?style=for-the-badge&label=Estabilidade)](./CONTRIBUTING.md)
[![Revisão de Segurança](https://img.shields.io/badge/Seguran%C3%A7a-Revis%C3%A3o%20Necess%C3%A1ria-red?style=for-the-badge)](#%EF%B8%8F-considera%C3%A7%C3%B5es-cr%C3%ADticas-de-seguran%C3%A7a)

---

**Olá! Eu sou Elias Andrade (chaos4455)** 👋

Como **Arquiteto de Sistemas de IA**, **Desenvolvedor Python Full-Cycle** e um entusiasta apaixonado por **DevOps e práticas de CI/CD**, percebi em muitos projetos, especialmente aqueles envolvendo microsserviços e fluxos de dados assíncronos para treinamento ou inferência de IA, a necessidade de uma ferramenta de mensageria que fosse ao mesmo tempo **poderosa e descomplicada**. Muitas soluções existentes, embora robustas, traziam uma complexidade e um consumo de recursos que nem sempre se justificavam.

<img width="1920" alt="chrome_snnH7HC5f1" src="https://github.com/user-attachments/assets/2b9d7454-8a45-4586-8c69-cceb68cd7a37" />


![screencapture-file-C-projeto-message-broker-replika-ai-v1-doc-web-diagram-20250408-004137-c1fa35d6-html-2025-04-08-00_42_31](https://github.com/user-attachments/assets/ce8c8ea2-7262-4c52-a352-e7d94c54df48)


Foi nesse contexto que **eu criei o Replika Message Broker**. Meu objetivo? Oferecer uma alternativa **leve, performática, escrita puramente em Python moderno**, e totalmente alinhada com as práticas de desenvolvimento e operações que prezo: containerização eficiente, automação ponta a ponta e foco na simplicidade operacional.

Este projeto é um reflexo da minha visão sobre como construir software resiliente e escalável, aproveitando o melhor do ecossistema Python e das ferramentas de DevOps atuais.

<img width="481" alt="chrome_w1U9g6CbZu" src="https://github.com/user-attachments/assets/07371eed-9471-4784-b543-9b8e8fe120b2" />

<img width="289" alt="chrome_Ns2I6PanRQ" src="https://github.com/user-attachments/assets/1d405056-9f81-4a92-b5e3-3b8524680e92" />

<img width="389" alt="chrome_yutc4iwJAw" src="https://github.com/user-attachments/assets/4b2e6a77-f32c-4f8f-b668-635460ceefae" />

<img width="354" alt="chrome_zt7hfDQlq3" src="https://github.com/user-attachments/assets/097586c6-a219-4764-a605-500a7b9f5c3c" />

<img width="856" alt="chrome_mIb7XWqwWe" src="https://github.com/user-attachments/assets/a4859cf6-04a6-4632-b9f8-ca38c02ebc81" />

<img width="486" alt="chrome_7f4tYiuEK4" src="https://github.com/user-attachments/assets/8129e6ac-a525-4369-85b3-8366c6b88f50" />

<img width="823" alt="chrome_JJ0z3Fka1x" src="https://github.com/user-attachments/assets/5aa6fdcb-8f46-44bc-80e6-c8671c80771e" />

<img width="223" alt="chrome_LB5juHWHuP" src="https://github.com/user-attachments/assets/7a986ce0-3f07-4b3f-aaf5-4804f4d877a3" />

<img width="486" alt="chrome_WQTcxbuNh8" src="https://github.com/user-attachments/assets/840b939e-f1e5-4e72-8926-0c8985cecc15" />

<img width="805" alt="chrome_PjOlztb8og" src="https://github.com/user-attachments/assets/6d60ee5f-f9de-4860-af34-1f79e77e960f" />

---

## 📖 Replika Message Broker: Uma Visão Geral

O Replika é, em essência, um **message broker open-source** projetado para ser um intermediário confiável na comunicação assíncrona. Eu o construí utilizando o que há de mais moderno em Python assíncrono, como **FastAPI** para a API RESTful/GraphQL e **Tortoise ORM** para persistência (inicialmente com **Aiosqlite**, mas extensível).

Ele é ideal para cenários como:

*   Comunicação entre microsserviços.
*   Filas de tarefas (Task Queues).
*   Arquiteturas Orientadas a Eventos (Event-Driven Architectures).
*   Distribuição de dados para processamento paralelo (cenário comum em IA/ML).

A filosofia por trás do Replika é **simplicidade e performance**. Ele não tenta competir em features com gigantes como RabbitMQ ou Kafka, mas sim oferecer o essencial de forma extremamente eficiente e fácil de usar, especialmente para quem já vive no ecossistema Python.

---

## 🤔 Por Que Eu Criei o Replika? (Diferenciais)

*   🐍 **Ecossistema Python Nativo:** Minha escolha por Python não foi acidental. Como desenvolvedor Python, queria uma solução que se integrasse perfeitamente, sem a necessidade de gerenciar runtimes ou dependências externas complexas (como a JVM). Isso simplifica o desenvolvimento, o deploy e a manutenção.
*   ⚡ **Performance Assíncrona:** Construído sobre `asyncio`, FastAPI e Uvicorn, o Replika é projetado para alta concorrência e I/O não bloqueante, resultando em baixa latência e excelente throughput para muitos casos de uso.
*   🪶 **Leveza:** Comparado a brokers tradicionais, o Replika tem um *footprint* de recursos significativamente menor, ideal para ambientes com restrições de memória ou CPU, ou simplesmente para reduzir custos operacionais.
*   🐳 **Containerização Pronta:** Desde o início, eu pensei o Replika para rodar em containers. A imagem Docker oficial (`chaos4455/message-broker-replika`) está otimizada e pronta para uso.
*   ⚙️ **Automação Total (CI/CD):** Como especialista em DevOps, a automação é crucial para mim. O pipeline de CI/CD no GitHub Actions garante que cada mudança seja buildada, testada e publicada de forma confiável e rápida. Falaremos muito sobre isso!
*   🌐 **APIs Modernas:** Oferece tanto uma API RESTful intuitiva (com documentação automática Swagger/ReDoc) quanto um endpoint GraphQL (via Strawberry) para flexibilidade na consulta.
*   📊 **Dashboard Simples:** Inclui um painel web básico (em Flask) para monitoramento e gerenciamento inicial.

---

## ✨ Funcionalidades Principais

*   ✅ **Criação/Gestão de Filas:** API para criar, listar e deletar filas dinamicamente.
*   ✅ **Publicação de Mensagens:** Envio de mensagens para filas específicas (persistentes ou não).
*   ✅ **Consumo de Mensagens:** Obtenção de mensagens de filas (com suporte básico a confirmação/ACK implícito ou explícito a ser aprimorado).
*   ✅ **Persistência Configurável:** Uso de Tortoise ORM com Aiosqlite por padrão, fácil de adaptar para outros bancos suportados (PostgreSQL AsyncPG, etc.).
*   ✅ **API RESTful:** Endpoint principal na porta `8777`.
*   ✅ **Documentação Automática:** Swagger UI (`/docs`) e ReDoc (`/redoc`) gerados automaticamente pelo FastAPI.
*   ✅ **Endpoint GraphQL:** Interface GraphQL na porta `8777/graphql` via Strawberry.
*   ✅ **Dashboard Web:** Painel de visualização e gestão básica na porta `8333`.
*   ✅ **Gerenciamento de Processos:** Uso de `supervisord` dentro do container para garantir que a API e o dashboard estejam sempre rodando.
*   ✅ **Rate Limiting:** Proteção básica contra abuso da API (configurável).
*   ✅ **CORS:** Configuração flexível de Cross-Origin Resource Sharing.


<img width="1091" alt="chrome_7Iw6F4DGjQ" src="https://github.com/user-attachments/assets/9ab69f40-4bb8-4605-aa68-750ef00f1e45" />


<img width="1087" alt="chrome_OfCQUHyUY3" src="https://github.com/user-attachments/assets/3063ea80-956d-4e66-9d4d-de9b7278152c" />



---

## 🛠️ Stack Tecnológico Utilizado

Para construir o Replika, eu selecionei um conjunto de tecnologias que considero eficientes e modernas dentro do ecossistema Python:

*   **Linguagem:** Python 3.x
*   **Framework API Principal:** FastAPI
*   **Servidor ASGI:** Uvicorn (com `standard` extras para performance)
*   **ORM Assíncrono:** Tortoise ORM
*   **Driver DB Padrão:** Aiosqlite
*   **Validação de Dados:** Pydantic
*   **GraphQL:** Strawberry-graphql[fastapi]
*   **Framework Dashboard:** Flask
*   **Template Engine (Dashboard):** Jinja2
*   **Autenticação/JWT (Básico):** python-jose[cryptography], passlib
*   **Rate Limiting:** slowapi
*   **Gerenciador de Processos (Container):** Supervisord
*   **Containerização:** Docker
*   **CI/CD:** GitHub Actions

---

## 🚀 Começando Rápido: Rodando o Replika com Docker

A maneira mais simples e recomendada por mim para você experimentar o Replika é utilizando a imagem Docker que eu disponibilizo publicamente no Docker Hub.

1.  **Baixe a Imagem:**
    ```bash
    docker pull chaos4455/message-broker-replika:latest
    ```

2.  **Execute o Container:**
    ```bash
    docker run -d --name replika_broker \
      -p 8777:8777 \
      -p 8333:8333 \
      chaos4455/message-broker-replika:latest
    ```
    *   `-d`: Roda o container em background (detached).
    *   `--name replika_broker`: Dá um nome fácil de lembrar para o container.
    *   `-p 8777:8777`: Mapeia a porta 8777 da sua máquina para a porta 8777 do container (onde roda a API FastAPI).
    *   `-p 8333:8333`: Mapeia a porta 8333 da sua máquina para a porta 8333 do container (onde roda o Dashboard Flask).

3.  **Acesse os Serviços:**
    *   **API Principal (FastAPI):** `http://localhost:8777`
    *   **Documentação Swagger UI:** `http://localhost:8777/docs`
    *   **Documentação ReDoc:** `http://localhost:8777/redoc`
    *   **Endpoint GraphQL:** `http://localhost:8777/graphql` (Use um cliente GraphQL como Apollo Sandbox ou Postman)
    *   **Dashboard Web (Flask):** `http://localhost:8333`

4.  **Credenciais Padrão (Atenção!):**
    *   **Usuário:** `admin`
    *   **Senha:** `admin`

    ⚠️ **ALERTA DE SEGURANÇA CRÍTICO!** ⚠️
    Estas credenciais (`admin`/`admin`) são **EXTREMAMENTE INSEGURAS** e servem **APENAS** para um primeiro teste rápido local. **JAMAIS, EM HIPÓTESE ALGUMA**, utilize estas credenciais em qualquer ambiente que não seja o seu próprio computador para testes iniciais. Em ambientes de desenvolvimento compartilhado, staging ou produção, é **OBRIGATÓRIO** configurar mecanismos de autenticação seguros e gerenciar segredos adequadamente (via variáveis de ambiente, secret managers, etc.). Eu abordo isso mais adiante nas considerações de segurança.

---

## 🏗️ Arquitetura Interna: Como o Replika Roda no Container

Dentro do container Docker, eu optei por usar o `supervisord`. Por quê? Porque o Replika, por padrão, executa dois processos Python principais:

1.  **O Servidor da API (FastAPI/Uvicorn):** Responsável por todas as operações do broker (`message-broker-v3-clean.py`).
2.  **O Servidor do Dashboard (Flask):** Responsável pela interface web (`webdashv2-clean.py`).

Um container Docker normalmente executa apenas um processo principal (CMD/ENTRYPOINT). O `supervisord` atua como um "gerente" de processos dentro do container. Ele é o processo principal iniciado pelo Docker (veja o `CMD` no Dockerfile gerado) e, por sua vez, ele inicia, monitora e reinicia automaticamente (se necessário) os processos da API e do dashboard.

Isso garante que ambos os serviços estejam sempre disponíveis e simplifica a imagem Docker, evitando a necessidade de scripts de inicialização complexos ou múltiplos containers para tarefas simples (embora para cenários mais complexos, múltiplos containers seja a abordagem preferida). Os logs de cada processo são gerenciados pelo `supervisord` e podem ser facilmente acessados (como veremos na seção de CI/CD).

---

##  automating 🔄 CI/CD - O Coração Pulsante da Automação: Mergulho Profundo no Workflow (`docker-build.yml`)

Para mim, um projeto moderno não vive sem automação robusta. O pipeline definido em `.github/workflows/docker-build.yml` é a espinha dorsal que garante a qualidade e a agilidade na entrega de novas versões do Replika. Vamos dissecar cada etapa, como eu a projetei:

** Gatilho (Trigger): `on: push: branches: - main` **
*   **O quê:** O workflow é acionado automaticamente toda vez que um `push` (envio de código) é feito para a branch `main`.
*   **Por quê:** A `main` representa o código estável e pronto para release. Automatizar o build e teste aqui garante que apenas código funcional chegue à imagem `latest`. Para Pull Requests, eu poderia (e provavelmente irei) criar um workflow separado com mais verificações.

** Ambiente de Execução: `runs-on: ubuntu-latest` **
*   **O quê:** Define que os jobs rodarão em uma máquina virtual Ubuntu Linux gerenciada pelo GitHub Actions, sempre na versão estável mais recente.
*   **Por quê:** Garante um ambiente limpo, padronizado e atualizado para cada execução, evitando problemas de "funciona na minha máquina".

** Variáveis de Ambiente (`env:`): **
*   `IMAGE_NAME: chaos4455/message-broker-replika`: Centraliza o nome da imagem Docker. Facilita a manutenção.
*   `VERSION: latest`: Define a tag padrão. Para releases futuras, eu posso parametrizar isso ou usar tags Git.
*   `DOCKERHUB_USERNAME: chaos4455`: Meu usuário no Docker Hub.

---

### Detalhamento das Etapas (Steps):

1.  **🧱 Checkout do Repositório (`actions/checkout@v3`)**
    *   **O quê faz:** Baixa o código-fonte da branch `main` para o ambiente do runner do GitHub Actions.
    *   **Minha visão:** Passo fundamental. Sem o código, nada acontece. Usar a action oficial `@v3` garante compatibilidade e segurança.

2.  **🧾 Criação Dinâmica do Dockerfile (`run: cat <<'EOF' > Dockerfile`)**
    *   **O quê faz:** Em vez de ter um arquivo `Dockerfile` versionado no repositório, este passo *gera* o conteúdo do Dockerfile "on-the-fly" durante a execução do workflow usando um *here document* (`cat <<'EOF' ... EOF`).
    *   **Por que eu fiz assim? (Minha Racionalização):**
        *   **Flexibilidade Extrema:** Permite injetar variáveis de ambiente do workflow (ex: versões de dependências específicas, configurações de build) diretamente nas camadas do Dockerfile, se necessário.
        *   **Contexto Único:** Mantém a definição exata do ambiente de build junto com a lógica do workflow que o utiliza. Para este projeto, onde o Dockerfile é relativamente estável mas intrinsecamente ligado ao processo de CI, achei essa abordagem interessante.
        *   **Experimentação:** Permite testar variações do Dockerfile (ex: base images diferentes, otimizações de camadas) diretamente no workflow sem poluir o histórico do Git com múltiplos arquivos Dockerfile.
        *   **IaC (Infrastructure as Code) na Prática:** Leva o conceito de IaC até a definição do ambiente de execução da aplicação.
    *   **Conteúdo Gerado (Resumido):** O Dockerfile gerado instala Python, `pip`, `supervisor`, as dependências Python do `requirements.txt` (ou listadas diretamente como no exemplo), cria um usuário não-root `replika`, copia o código da aplicação, copia a configuração do `supervisord` (que também será gerada dinamicamente) e define o `CMD` para iniciar o `supervisord`.

3.  **⚙️ Criação Dinâmica do supervisord.conf (`run: cat <<'EOF' > supervisord.conf`)**
    *   **O quê faz:** Similar ao Dockerfile, gera o arquivo de configuração do `supervisord` dinamicamente.
    *   **Por que eu fiz assim?:** Pelos mesmos motivos de flexibilidade do Dockerfile. Poderia, por exemplo, habilitar/desabilitar serviços (programas no `supervisord`) com base em variáveis do workflow ou definir caminhos de log dinamicamente.
    *   **Conteúdo Gerado (Resumido):** Define a configuração global do `supervisord` (rodar em foreground, arquivos de log/pid) e as seções `[program:...]` para o broker (`message-broker-v3-clean.py`) e o dashboard (`webdashv2-clean.py`), especificando o comando de execução, diretório, auto-start, auto-restart e arquivos de log para stdout/stderr de cada processo.

4.  **🐳 Login no Docker Hub (`docker/login-action@v2`)**
    *   **O quê faz:** Autentica o runner do GitHub Actions no Docker Hub para permitir o push da imagem.
    *   **Minha visão:** Passo de segurança crucial. Utiliza a action oficial `docker/login-action`, que é a forma recomendada. O nome de usuário vem da variável `env`, e a senha/token **DEVE** ser armazenada de forma segura como um **GitHub Secret** (chamado `DOCKERHUB_TOKEN` neste workflow). **Nunca, jamais, coloque senhas ou tokens diretamente no código do workflow!**

5.  **🛠️ Build da Imagem Docker (`run: docker build ...`)**
    *   **O quê faz:** Executa o comando `docker build` usando o `Dockerfile` gerado na etapa anterior.
    *   **Comando:** `docker build -t $IMAGE_NAME:$VERSION .`
    *   **Minha visão:** O coração do processo de empacotamento. O `-t` aplica a tag (ex: `chaos4455/message-broker-replika:latest`) à imagem construída. O `.` indica que o contexto do build é o diretório atual (onde o código foi checado e os arquivos dinâmicos foram criados).

6.  **📤 Push da Imagem Docker (`run: docker push ...`)**
    *   **O quê faz:** Envia a imagem recém-construída e taggeada para o registry do Docker Hub.
    *   **Comando:** `docker push $IMAGE_NAME:$VERSION`
    *   **Minha visão:** Torna a nova versão do Replika disponível publicamente (ou privadamente, dependendo da configuração do repositório Docker Hub). Só funciona se o login na etapa anterior foi bem-sucedido.

7.  **🚀 Deploy & Teste de Portas (`run: ...`)**
    *   **O quê faz:** Esta é uma etapa crítica de **Smoke Test** ou **Teste de Sanidade** que eu implementei. Ela valida se a imagem que *acabou de ser enviada* para o Docker Hub pode ser baixada, executada e se os serviços essenciais dentro dela estão respondendo nas portas corretas.
    *   **Mecanismo Detalhado:**
        1.  `docker run -d --name replika_test_container -p 8333:8333 -p 8777:8777 $IMAGE_NAME:$VERSION`: Baixa (se não estiver em cache) e inicia um container a partir da imagem recém-publicada. Mapeia as portas para `localhost` no runner.
        2.  `sleep 15`: **Pausa Essencial!** Eu adicionei este `sleep` porque o `supervisord`, o Uvicorn e o Flask precisam de alguns segundos para inicializar completamente dentro do container e começar a "ouvir" (`listen`) nas portas 8777 e 8333. Sem essa pausa, os testes de porta provavelmente falhariam prematuramente. 15 segundos é um valor conservador; pode ser ajustado.
        3.  `nc -zv localhost 8333 || echo '⚠️ Porta 8333...'`: Aqui eu uso o `netcat` (`nc`), uma ferramenta de rede poderosa. `-z` faz um scan sem enviar dados, `-v` dá output verboso. Ele tenta estabelecer uma conexão TCP com `localhost` na porta 8333. Se o serviço (Dashboard) estiver rodando e ouvindo, `nc` retorna sucesso (código 0). Se falhar (porta fechada, serviço não iniciou), o comando após `||` (OR lógico do shell) é executado, imprimindo um aviso.
        4.  `nc -zv localhost 8777 || echo '⚠️ Porta 8777...'`: Mesma lógica para a porta 8777 (API do Broker).
        5.  `docker exec replika_test_container tail -n 50 ... || echo '⚠️ ...'` : Se os testes de porta passarem (ou mesmo se falharem), eu uso `docker exec` para executar comandos *dentro* do container `replika_test_container` que ainda está rodando. O comando `tail -n 50` busca as últimas 50 linhas dos arquivos de log do `supervisord`, do stdout do broker e do stdout do dashboard. Isso é **crucial para depuração**. Se uma porta não respondeu, os logs podem me dizer *por quê* (ex: erro de inicialização do Python, falha ao bindar a porta, etc.). O `|| echo ...` captura falhas no próprio `docker exec` (ex: se o container já tiver morrido).
    *   **Minha visão de Arquiteto/DevOps:** Para mim, um build que passa não significa nada se o artefato gerado (a imagem Docker) não funciona minimamente. Esta etapa fornece uma **confiança básica fundamental** de que a imagem não está quebrada. É o primeiro portão de qualidade após o build.

8.  **🏷️ Opcional: Criar e Pushar Tag Git (Comentado)**
    *   **O quê faria:** Configuraria o Git dentro do runner, criaria uma tag Git (ex: `RC1-beta-v0001`) associada ao commit que disparou o workflow e a enviaria para o repositório no GitHub.
    *   **Minha visão:** É uma prática comum para marcar releases. Eu deixei comentado como um exemplo de como eu poderia evoluir o workflow para um processo de release mais formalizado, talvez acionado manualmente ou por tags Git.

---

## ⚙️ Configuração Detalhada

Embora eu busque a simplicidade, alguns pontos de configuração são importantes:

*   **Portas Padrão:**
    *   `8777/tcp`: API RESTful/GraphQL (FastAPI)
    *   `8333/tcp`: Web Dashboard (Flask)
*   **Credenciais Padrão:** `admin`/`admin` (⚠️ **Reforçando: APENAS PARA TESTES LOCAIS!**)
*   **Banco de Dados:**
    *   Padrão: SQLite, arquivo localizado em `/home/replika/app/databases/message_broker_v3.db` *dentro do container*.
    *   **Customização (Recomendado para Produção):** Eu projetei usando Tortoise ORM, então é relativamente simples modificar o `DATABASE_URL` (provavelmente via variável de ambiente) em `message-broker-v3-clean.py` para usar um banco de dados mais robusto como PostgreSQL (com `asyncpg`). Ex: `postgresql://user:pass@host:port/dbname`.
*   **Logging:**
    *   Os processos gerenciados pelo `supervisord` têm seus `stdout` e `stderr` redirecionados para arquivos em `/var/log/supervisor/` dentro do container (ex: `broker.out.log`, `webdash.err.log`).
    *   Para produção, eu recomendaria configurar o Docker daemon com um driver de log apropriado (como `json-file`, `journald`, `syslog`, ou drivers para agregadores como Fluentd, Splunk, Datadog) para coletar e gerenciar esses logs de forma centralizada. A observabilidade é chave!

---

## ⚠️ Considerações Críticas de Segurança

Como arquiteto responsável, a segurança é uma preocupação central. O Replika, no estado atual (Beta), requer atenção especial antes de ir para produção:

1.  🔐 **Credenciais:** **NÃO USE `admin`/`admin`!** A primeira e mais crítica mudança é implementar um sistema de autenticação/autorização robusto.
    *   **Sugestões:** Usar JWT com chaves secretas fortes carregadas via variáveis de ambiente ou um sistema de gerenciamento de segredos (como HashiCorp Vault, AWS Secrets Manager, GCP Secret Manager). Implementar gerenciamento de usuários/tokens via API.
2.  🔒 **HTTPS/TLS:** O setup padrão expõe as portas em HTTP. **Inaceitável para produção.** A abordagem padrão e recomendada por mim é usar um **Reverse Proxy** (como Nginx, Traefik, Caddy, ou Ingress Controllers no Kubernetes) na frente do container Replika. O proxy lidaria com a terminação TLS (certificados SSL/TLS), encaminhando o tráfego para o container Replika via HTTP internamente na rede privada.
3.  🛡️ **Validação de Entrada:** Embora FastAPI/Pydantic ofereçam boa validação, sempre trate dados externos (nomes de filas, conteúdo de mensagens) com cuidado. Sanitize entradas para prevenir ataques de injeção ou exploração de vulnerabilidades.
4.  🚦 **Rate Limiting:** A biblioteca `slowapi` está incluída, mas os limites padrão podem não ser adequados. Configure limites realistas para proteger a API contra abuso ou ataques de DoS (Denial of Service) básicos. Considere limites mais avançados no nível do reverse proxy/API Gateway.
5.  📦 **Limites de Recursos:** Em ambientes orquestrados (Kubernetes, Docker Swarm), **SEMPRE** defina limites de CPU e memória para o container Replika. Isso previne que ele consuma todos os recursos do nó em caso de bug ou sobrecarga.
6.  🌐 **Políticas de Rede:** Restrinja o acesso às portas 8777 e 8333. Use firewalls, security groups (AWS/GCP/Azure) ou Network Policies (Kubernetes) para permitir conexões apenas de fontes confiáveis (ex: outros microsserviços da sua aplicação, IPs específicos de administradores).
7.  🔄 **Auditoria e Monitoramento:** Integre logs e métricas (ex: usando Prometheus/Grafana via um exporter, ou soluções APM) para monitorar o comportamento do broker e detectar anomalias.

---

## 📈 Próximos Passos & Roadmap (Minhas Ideias)

O Replika é um projeto vivo e minha intenção é continuar evoluindo-o. Algumas ideias que tenho para o futuro:

*   Melhorar o sistema de confirmação de mensagens (ACK/NACK explícito).
*   Implementar retentativas automáticas (retries) com backoff exponencial.
*   Adicionar suporte a Dead Letter Queues (DLQ).
*   Explorar mecanismos de Pub/Sub mais avançados (exchanges/topics).
*   Aprimorar o Dashboard com mais métricas e funcionalidades.
*   Oficializar o suporte a outros backends de banco de dados (PostgreSQL).
*   Refatorar a segurança para um modelo mais robusto e configurável.
*   Criar Helm Charts para deploy fácil em Kubernetes.
*   Adicionar mais testes unitários e de integração no pipeline de CI/CD.

---

## 🤝 Como Contribuir

Eu acredito fortemente no poder da comunidade open-source! Se você gostou do Replika, encontrou um bug, tem uma ideia para uma nova feature ou quer ajudar a melhorar a documentação, sua contribuição é **muito bem-vinda**!

1.  Faça um **Fork** do repositório.
2.  Crie uma nova **Branch** para sua feature ou correção (`git checkout -b feature/minha-feature` ou `fix/corrige-bug-x`).
3.  Faça suas alterações e **Commits**. Escreva mensagens de commit claras!
4.  Faça **Push** da sua branch para o seu fork (`git push origin feature/minha-feature`).
5.  Abra um **Pull Request** no repositório original, detalhando suas mudanças.

Sinta-se à vontade também para abrir **Issues** para reportar problemas ou discutir ideias.

---

## 📜 Licença

Este projeto é distribuído sob a Licença [Nome da Sua Licença - Ex: MIT]. Veja o arquivo `LICENSE` para mais detalhes.

---

Espero que o Replika Message Broker seja útil para seus projetos, assim como tem sido para os meus estudos e desenvolvimentos. Ele representa minha paixão por criar ferramentas eficientes e elegantes usando Python e as melhores práticas de DevOps.

Qualquer dúvida ou feedback, pode me encontrar aqui no GitHub!

**Elias Andrade (chaos4455)**

