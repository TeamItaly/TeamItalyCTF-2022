import undici from 'undici';
import { serviceURL } from '../config.js';
export default (path) => new Promise((resolve, reject) => {
  let url = new URL(serviceURL + path);
  let client = new undici.Client(`http://${url.hostname}:${url.port ?? 80}`, {
    timeout: 1000,
    headersTimeout: 2000,
    bodyTimeout: 5000,
    connectTimeout: 1000,
    pipelining: 0
  });
  (async () => {
    try {
      let { statusCode, body } = await client.request({
        method: 'GET',
        path: '/' + path.replace(/\/+/, '')
      });

      body.on("error", (err) => {
        reject(err);
      });
      if (statusCode !== 200) return reject(closeClient(client, `Service returned status code ${statusCode}`));
      let respb = '';
      let size = 0;
      for await (let chunk of body) {
        if (chunk.length + size > 100000) {
          return reject(closeClient(client, 'Response too large'));
        }
        respb += chunk;
        size += chunk.length;
      }
      closeClient(client);
      resolve(JSON.parse(respb.toString()));
    } catch (e) { reject(e) }
  })();
});

function closeClient(client, err) {
  if (client && !client.destroyed) client.destroy('');
  if (err) return (err);
  return "";
}
