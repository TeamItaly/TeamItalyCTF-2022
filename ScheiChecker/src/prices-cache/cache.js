import { getCoinPrice } from './CoinMarketCap.js';
import { pollingInterval } from './config.js';

let currentPrice = null;
let upOrDown = 'stable';
let lastSync = 0;
let nextSync = Date.now() + 10 * 1000;

async function cachePrice() {
  try {
    let cOld = currentPrice;
    currentPrice = await getCoinPrice();
    lastSync = Date.now();
    nextSync = Date.now() + pollingInterval;

    if (cOld === null) cOld = currentPrice;
    if (currentPrice > cOld) upOrDown = 'up';
    else if (currentPrice < cOld) upOrDown = 'down';
    else upOrDown = 'stable';

    console.log(`Price updated: ${currentPrice}, going ${upOrDown}`);
  } catch (ex) {
    console.error(ex);
    return;
  }
}

export function getPrice() {
  return {
    currentPrice,
    upOrDown,
    lastSync,
    nextSync
  };
}

cachePrice();
setInterval(() => cachePrice(), pollingInterval);
