import express from 'express';
import { port } from './config.js';

import { pricesAPI } from './modules/prices-api.js';
import { adminAPI } from './modules/admin-api.js';

import * as serialize from './utils/serialize.js';
import * as jwtAuth from './utils/jwt-auth.js';
import * as visits from './utils/visits.js';

import { checkConfig } from './configChecker.js';

checkConfig();

const app = express();
app.use(express.json());

let deps = {
  flag: process.env.FLAG,
  adminPassword: process.env.ADMIN_PASSWORD,
  db: serialize,
  jwtAuth: jwtAuth,
  visits: visits
};

console.log('Flag: ' + deps.flag);
console.log('Admin password: ' + deps.adminPassword);

jwtAuth.setPassword(deps.adminPassword);

//Webserver

//Admin API
let admin = express.Router();
adminAPI(admin, deps);
app.use('/adminAPI', admin);

//Prices API
let prices = express.Router();
pricesAPI(prices, deps);
app.use('/pricesAPI', prices);

//HTML
app.get('/', visits.middleware(deps));
app.use('/', express.static('./html'));

app.listen(port, () => {
  console.log(`Server started on port ${port}`);
});
