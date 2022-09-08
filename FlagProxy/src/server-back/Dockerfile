FROM node:17

WORKDIR /usr/src/app

COPY ./package.json ./
COPY ./package-lock.json ./
RUN npm install

COPY . .
CMD npm start
