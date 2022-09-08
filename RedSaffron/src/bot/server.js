const express = require('express')
require('express-async-errors')

const bot = require('./bot')

const PORT = 9999

const app = express()

app.use(express.json());


app.post('/visit', async function (req, res) {

    const url = req.body.url;

    if (!url || typeof url !== 'string') {
        console.log('Visit requested with missing parameters');
        res.status(400).json({ msg: 'Missing parameters' });
        return;
    }


    if (url.startsWith('http')) {
        try {
            const result = await bot.visit(url);

            if (result === 'ok') {
                return res.json({ msg: 'Url visited' });
            } else {
                return res.status(500, { msg: result });
            }

        } catch (e) {
            console.log(e);
            res.status(500).json({ msg: 'failed' });
            return;
        }
    }
    res.status(400).json({ msg: 'bad url' });
})


app.listen(PORT, '0.0.0.0');
console.log('Listening on port %d ...', PORT);