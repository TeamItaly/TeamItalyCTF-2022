import express from 'express';
import fs from 'fs';
import { port, convTo, coinName } from './config.js';
import { getPrice } from './cache.js';

const app = express();
app
  .get('/prices', async (req, res) => {
    let data = await getPrice();
    res.send({
      price: data.currentPrice,
      change: data.upOrDown,
      currency: convTo,
      name: coinName,
      lastSync: data.lastSync,
      nextSync: data.nextSync
    });
  })
  .listen(port, () => {
    console.log(`Server started on port ${port}`);
  });
