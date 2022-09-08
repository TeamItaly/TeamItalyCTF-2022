import 'dotenv/config';
import express from 'express';
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

const tokens = [];

app.get('/flag', (req, res) => {
  const token = req.headers['authorization'].split(' ')[1];
  if (tokens.includes(token)) {
    res.send(process.env.FLAG);
  } else {
    res.status(500).send('Invalid token');
  }
});

app.get('/add-token', (req, res) => {
  if (req.query.token === undefined || req.query.token?.length < 10) {
    res.send('Token too short');
  } else {
    tokens.push(req.query.token);
    res.send('OK');
  }
});

app.listen(8080, () => {
  console.log('Listening on port 8080!');
});
