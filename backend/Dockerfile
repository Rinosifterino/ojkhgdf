# Use uma imagem base Node.js
FROM node:20-alpine

# Defina o diretório de trabalho dentro do container
WORKDIR /usr/src/app

# Copie o package.json e instale as dependências
COPY package*.json ./
RUN npm install

# Copie o restante do código da aplicação
COPY . .

# Exponha a porta que o servidor irá rodar
EXPOSE 3000

# Comando para iniciar a aplicação
CMD [ "npm", "start" ]
