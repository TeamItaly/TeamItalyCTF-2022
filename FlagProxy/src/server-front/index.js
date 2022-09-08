import 'dotenv/config';
import express from 'express';
import { request } from './http-client.js';
const app = express();

app.use((req, res, next) => {
  let data = '';
  req.setEncoding('utf8');
  req.on('data', (chunk) => {
    data += chunk;
  });

  req.on('end', () => {
    req.body = data;
    next();
  });
});

app.get('/flag', (req, res) => {
  if (!req.query.token) {
    res.status(500).send('Missing token');
    return;
  }

  request(`http://${process.env.BACK}:8080/flag`, {
    method: 'GET',
    headers: {
      Authorization: `Bearer ${req.query.token}`
    }
  })
    .then((response) => {
      res.send(response);
    })
    .catch((e) => {
      res.status(500).send('There has been an error with the request');
    });
});

app.get('/add-token', (req, res) => {
  if (!req.query.token) {
    res.status(500).send('Missing token');
    return;
  }

  if (!req.query.auth || req.query.auth !== process.env.AUTH) {
    res.status(500).send('Wrong auth');
    return;
  }

  request(`http://${process.env.BACK}:8080/add-token?token=${req.query.token}`, {
    method: 'GET'
  })
    .then((response) => {
      res.send(response);
    })
    .catch((e) => {
      res.status(500).send('There has been an error with the request');
    });
});

app.listen(1337, () => {
  console.log('Listening on port 1337!');
});
