FROM node:17.9

WORKDIR /app

COPY package*.json ./

RUN npm install

RUN groupadd appgroup && useradd -g appgroup appuser 

COPY . ./

EXPOSE 3001

USER appuser

CMD node server.js 