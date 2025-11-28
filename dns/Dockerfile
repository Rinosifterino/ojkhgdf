# Use uma imagem base Debian ou Ubuntu para instalar o Bind9
FROM ubuntu:latest

# Instala o Bind9 e ferramentas de rede
RUN apt-get update && apt-get install -y bind9 dnsutils net-tools

# Cria o diretório de configuração do Bind9
RUN mkdir -p /etc/bind/zones

# Copia os arquivos de configuração
COPY named.conf.options /etc/bind/
COPY named.conf.local /etc/bind/
COPY db.meutrabalho.com.br /etc/bind/zones/

# Define a porta padrão do DNS
EXPOSE 53/udp
EXPOSE 53/tcp

# Comando para iniciar o Bind9 em foreground
CMD ["/usr/sbin/named", "-g", "-c", "/etc/bind/named.conf"]
