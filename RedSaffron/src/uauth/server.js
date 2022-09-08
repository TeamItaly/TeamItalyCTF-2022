const express = require('express')
require('express-async-errors')
const val = require('express-validator')
const crypto = require('crypto')


const validate_redirect = /^http:\/\/saffron\.challs\.teamitaly\.eu\/cb/


const ADMIN_PASSWORD = process.env['ADMIN_PASSWORD'] || 'password'

const app = express()
const port = 3000

app.set('view engine', 'ejs');

const db = require('better-sqlite3')(':memory:', {})
db.prepare('CREATE TABLE IF NOT EXISTS users (username VARCHAR(50) PRIMARY KEY, role VARCHAR(20), password TEXT NOT NULL);').run()
db.prepare('CREATE TABLE IF NOT EXISTS tokens (username VARCHAR(50), token VARCHAR(40) NOT NULL, exp INTEGER NOT NULL);').run()

db.prepare('CREATE TABLE IF NOT EXISTS money (username VARCHAR(50) PRIMARY KEY, balance INTEGER NOT NULL);').run()
db.prepare('CREATE TABLE IF NOT EXISTS transactions (from_user VARCHAR(50), to_user VARCHAR(50), amount INTEGER NOT NULL);').run()

// db.prepare("INSERT INTO users(username, role, password) VALUES ('xato','author','password');").run()
// db.prepare("INSERT INTO money(username, balance) VALUES ('xato', 100);").run()
// db.prepare("INSERT INTO users(username, role, password) VALUES ('xato2','advertiser','password');").run()
// db.prepare("INSERT INTO money(username, balance) VALUES ('xato2', 0);").run()
// db.prepare("INSERT INTO users(username, role, password) VALUES ('xato3','author','password');").run()
// db.prepare("INSERT INTO money(username, balance) VALUES ('xato3', 100);").run()

db.prepare("INSERT INTO users(username, role, password) VALUES ('admin','admin',?);").run([ADMIN_PASSWORD])
db.prepare("INSERT INTO money(username, balance) VALUES ('admin', 1000);").run()


const clear_tokens_stmt = db.prepare('DELETE FROM tokens WHERE exp < ?')
setInterval(() => {
    const now = Math.floor(Date.now() / 1000)
    clear_tokens_stmt.run([now])
}, 10000)


app.use(express.urlencoded({ extended: false }))


app.get('/auth',
    val.query('redirect_uri').isString(),
    val.query('response_type').isIn(['token']),
    (req, res) => {

        const errors = val.validationResult(req);
        if (!errors.isEmpty()) {
            return res.status(400).send('bad parameters');
        }

        const { redirect_uri, response_type } = req.query


        if (!validate_redirect.test(redirect_uri)) {
            return res.status(400).send('invalid redirect uri')
        }

        res.render('login')
    })

app.post('/auth',
    val.query('redirect_uri').isString(),
    val.query('response_type').isIn(['token']),
    val.body('username').isString().isLength({ min: 4, max: 50 }),
    val.body('password').isString().isLength({ min: 8, max: 50 }),
    (req, res) => {

        const errors = val.validationResult(req);
        if (!errors.isEmpty()) {
            return res.status(400).send('bad parameters');
        }

        const { redirect_uri, response_type } = req.query
        const { username, password } = req.body

        if (!validate_redirect.test(redirect_uri)) {
            return res.status(400).send('invalid redirect uri')
        }

        const u = db.prepare('SELECT username, password FROM users WHERE username = ?').get(username)

        if (u && u.password === password) {

            const token = crypto.randomUUID()
            const exp = Math.floor(Date.now() / 1000) + 60 * 30

            console.log(username, token, exp)

            db.prepare('INSERT INTO tokens (username, token, exp) VALUES (?,?,?)').run([username, token, exp])

            return res.redirect(redirect_uri + `#token=${token}&exp=${exp}`)
        }

        return res.redirect(redirect_uri + '#error=bad credentials')
    })

app.get('/register',
    (req, res) => {
        res.render('register')
    })

app.post('/register',
    val.body('username').isString().isLength({ min: 4, max: 50 }),
    val.body('password').isString().isLength({ min: 8, max: 50 }),
    val.body('role').isString().isIn(['author', 'advertiser']),
    (req, res) => {

        const errors = val.validationResult(req);
        if (!errors.isEmpty()) {
            return res.status(400).send('bad parameters');
        }

        let { username, password, role } = req.body

        try {
            db.prepare("INSERT INTO users(username, role, password) VALUES (?,?,?);").run([username, role, password])
            db.prepare("INSERT INTO money(username, balance) VALUES (?, 0);").run([username])
        } catch (e) {
            if (e.code && e.code === 'SQLITE_CONSTRAINT_PRIMARYKEY') {
                return res.status(400).send('user already exists')
            }
            return res.status(500).send(e)
        }

        if (req.query.redirect_uri /*&& validate_redirect.test(req.query.redirect_uri)*/) {
            return res.redirect(req.query.redirect_uri)
        }

        res.send('registered')
    })

app.get('/me',
    val.query('token').isString(),
    (req, res) => {

        const errors = val.validationResult(req);
        if (!errors.isEmpty()) {
            return res.status(400).send('bad parameters');
        }

        const token = req.query.token
        const u = db.prepare('SELECT u.username, role FROM tokens AS t, users AS u WHERE u.username=t.username AND token = ?').get(token)

        if (u) {
            return res.json(u)
        }

        return res.status(400).json({ error: 'invalid token' })
    }
)


app.get('/money',
    val.query('token').isString().isUUID(),
    (req, res) => {

        const errors = val.validationResult(req);
        if (!errors.isEmpty()) {
            return res.status(400).send('bad parameters');
        }


        const u = db.prepare('SELECT username FROM tokens WHERE token = ?').get(req.query.token)

        if (u) {
            const r = db.prepare('SELECT balance FROM money WHERE username = ?').get(u.username)
            return res.json(r)
        }

        return res.status(400).json({ error: 'invalid token' })
    }
)

app.post('/transaction',
    val.body('token').isString().isUUID(),
    val.body('to').isString(),
    val.body('amount').isString().toInt().isInt({ min: 1 }),
    (req, res) => {

        let errors = val.validationResult(req);
        if (!errors.isEmpty()) {
            return res.status(400).send('bad parameters');
        }


        let from_user = db.prepare('SELECT u.username AS username, role FROM tokens AS t, users AS u WHERE u.username = t.username AND token = ?').get(req.body.token)
        let to_user = db.prepare('SELECT username, role FROM users WHERE username = ?').get(req.body.to)


        console.log(from_user, to_user, req.body.amount)

        if (from_user && to_user) {

            const get_balance = db.prepare('SELECT balance FROM money WHERE username = ?')
            const update_balance = db.prepare('UPDATE money SET balance=balance+? WHERE username = ?')
            const add_transaction = db.prepare('INSERT INTO transactions(from_user, to_user, amount) VALUES(?,?,?)')

            const transaction = db.transaction((from_user, to_user, amount) => {
                const b = get_balance.get(from_user.username)
                if (b.balance >= amount) {
                    if (from_user.role !== 'admin') {
                        update_balance.run([-amount, from_user.username])
                    }
                    update_balance.run([amount, to_user.username])
                    add_transaction.run([from_user.username, to_user.username, amount])
                    return true
                }
                return false
            })

            const x = transaction(from_user, to_user, req.body.amount)

            if (x) {
                return res.json({ msg: 'succeeded' })
            } else {
                return res.status(500).json({ error: 'failed' })
            }
        }

        return res.status(400).json({ error: 'bad request' })
    }
)




app.listen(port, () => {
    console.log(`App listening on port ${port}`)
})