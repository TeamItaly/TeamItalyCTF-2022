import axios from 'axios';
import { CoinMarketCapApiKey, coinID, convTo } from './config.js';

let token_warned = false;
let response = null;

async function requestor(endpoint, data) {
  // https://coinmarketcap.com/api/documentation/v1/
  let apiKey, hostname;
  if (CoinMarketCapApiKey === '') {
    if (!token_warned) {
      console.warn(
        'No CoinMarketCap API key specified inside the config.js. Using mock data API instead.'
      );
      console.warn(
        'Real data will not be returned. Please add a CoinMarketCap API key to the config.js file if this is a production environment.'
      );
      token_warned = true;
    }
    // Use public mock data API
    apiKey = 'b54bcf4d-1bca-4e8e-9a24-22ff2c3d462c';
    hostname = 'sandbox-api.coinmarketcap.com';
  } else {
    if (!token_warned) {
      let obscured = CoinMarketCapApiKey.substring(0, 4) + '****';
      console.log(`Using CoinMarketCap API key ${obscured} from the config.js file.`);
      token_warned = true;
    }
    apiKey = CoinMarketCapApiKey;
    hostname = 'pro-api.coinmarketcap.com';
  }
  let qdata = '';
  if (data) qdata = new URLSearchParams(data).toString();
  try {
    response = await axios.get(`https://${hostname}/${endpoint}?${qdata}`, {
      headers: {
        'X-CMC_PRO_API_KEY': apiKey
      }
    });
  } catch (ex) {
    if (!ex.response) {
      console.error('There was a network error. Please check your internet connection.');
      throw ex;
    }
    if (ex.response.status === 401) {
      console.error('CoinMarketCap API key is invalid. Please check the config.js file.');
      process.exit(1);
    }
    if (ex.response.status === 429) {
      console.error('CoinMarketCap API rate limit exceeded');
      throw ex;
    }
    console.error(ex);
    throw ex;
  }
  if (response) {
    const json = response.data;
    return json;
  }
}

export async function getCoinPrice() {
  let data = {
    id: coinID,
    convert: convTo
  };
  let json = await requestor('v1/cryptocurrency/quotes/latest', data);
  return json.data[coinID].quote[convTo].price;
}
