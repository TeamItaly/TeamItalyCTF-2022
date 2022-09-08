import reql from '../utils/prices-request.js';
export function pricesAPI(route, deps) {
  route.get('/getPrice', (req, res) => {
    if (!req.query.url || typeof req.query.url !== 'string')
      return res.status(400).send('Missing url');
    reql(req.query.url)
      .then((data) => {
        res.send(data);
      })
      .catch((err) => {
        res.status(502).send('There was an error processing your request: ' + err);
      });
  });
}
