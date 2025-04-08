FROM ubuntu:22.04

ARG GITHUB_PAT
ENV DEBIAN_FRONTEND=noninteractive

# Dependências básicas
RUN apt-get update && \
    apt-get upgrade -y && \
    apt-get install -y python3 python3-pip git net-tools curl iputils-ping nano openssh-server && \
    useradd -m -s /bin/bash replika && \
    echo 'replika:replika' | chpasswd && \
    mkdir -p /home/replika/app

WORKDIR /home/replika/app

# Clona o repo privado usando o token
RUN git clone https://x-access-token:${GITHUB_PAT}@github.com/chaos4455/projeto-message-broker-replika-ai-v1.git temp && \
    cp temp/*.py ./ && \
    rm -rf temp

# Instala dependências Python se necessário
RUN if [ -f requirements.txt ]; then pip3 install -r requirements.txt; fi

# Scripts principais rodando em background
CMD bash -c "python3 message-broker-v3-clean.py & \
             sleep 5 && python3 webdash3-clean.py & \
             sleep 5 && python3 geramensagem-v3-massive-loop.py & \
             sleep 5 && python3 coleta-mensagem-v3-batch-lote.py && \
             tail -f /dev/null"
