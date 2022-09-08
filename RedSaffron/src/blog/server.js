const express = require('express')
require('express-async-errors')
const val = require('express-validator')
const crypto = require('crypto')
require('isomorphic-fetch')
const cookieParser = require("cookie-parser")
const ejs = require("ejs")
const createDOMPurify = require('dompurify')
const { JSDOM } = require('jsdom')
const helmet = require("helmet")

const default_ad = `<h2 style="color: red">You can buy this ad</h2>`

const BOT_URL = process.env['BOT_URL'] || 'http://bot:9999/visit'
const BLOG_HOST = process.env['BLOG_HOST'] || 'http://localhost:3001'
const AUTH_HOST_INT = process.env['AUTH_HOST_INT'] || 'http://localhost:3000'
const AUTH_HOST_EXT = process.env['AUTH_HOST_EXT'] || 'http://localhost:3000'
const FLAG = process.env['FLAG'] || 'flag{REDACTED}'

const window = new JSDOM('').window
const DOMPurify = createDOMPurify(window)

const app = express()

app.set('view engine', 'ejs')

const port = 3001

const db = require('better-sqlite3')(':memory:', {})
db.prepare('CREATE TABLE IF NOT EXISTS recipes (id VARCHAR(40) PRIMARY KEY, author VARCHAR(50) NOT NULL, title TEXT NOT NULL, content TEXT NOT NULL, public BOOLEAN NOT NULL);').run()
db.prepare('CREATE TABLE IF NOT EXISTS ads (recipeid VARCHAR(40) PRIMARY KEY, owner VARCHAR(50) NOT NULL, content TEXT NOT NULL);').run()
db.prepare("INSERT INTO recipes(id, author, title, content, public) VALUES (?,'admin','Pineapple pizza',?,TRUE);").run('7e2f4cf7-f03b-45dc-9382-05ab49449c8d',
    `The real italian&reg; pizza. </br></br><img src="/pizza.jpeg">`) //crypto.randomUUID())
db.prepare("INSERT INTO recipes(id, author, title, content, public) VALUES (?,'admin','Flag',?,FALSE);").run([crypto.randomUUID(), FLAG])


app.use(express.urlencoded({ extended: false }))
app.use(cookieParser())
app.use(express.static('static'))

app.use(
    helmet({
        contentSecurityPolicy: false,
    })
)


app.use((req, res, next) => {
    if (req.cookies.token) {
        res.locals.islogged = true
    } else {
        res.locals.islogged = false
    }
    next()
})

app.get('/', (req, res) => {
    res.render('home')
})

app.get('/public',
    (req, res) => {
        recipes = db.prepare('SELECT id, title FROM recipes WHERE public = TRUE').all()
        res.render('recipe_list', { recipes })
    })

app.get('/private',
    val.cookie('token').isString().isUUID(),
    async (req, res) => {

        if (!req.cookies.token) {
            return res.status(403).render('error', { error: 'you need to login' })
        }

        let errors = val.validationResult(req);
        if (!errors.isEmpty()) {
            return res.status(400).render('error', { error: 'bad parameters' });
        }


        let user_info = await fetch(AUTH_HOST_INT + '/me?token=' + req.cookies.token).then(r => r.json())

        if (!user_info.username) {
            res.clearCookie('token')
            return res.status(403).render('error', { error: 'you need to login' })
        }
        let recipes = db.prepare('SELECT id, title FROM recipes WHERE public = FALSE and author = ? ').all([user_info.username])
        res.render('recipe_list', { recipes })
    })


app.get('/:recipeid([a-f0-9\-]{36})',
    val.param('recipeid').notEmpty(),
    (req, res) => {

        errors = val.validationResult(req);
        if (!errors.isEmpty()) {
            return res.status(400).render('error', { error: 'bad parameters' });
        }

        let { recipeid } = req.params

        let recipe = db.prepare('SELECT * FROM recipes WHERE id = ?').get(recipeid)
        let ad = db.prepare('SELECT content FROM ads WHERE recipeid = ?').get(recipeid)

        if (recipe) {
            return res.render('recipe', { title: recipe.title, recipe: recipe.content, ad: ad?.content ?? default_ad, recipeid, can_buy_ad: ad?.content ? false : true })
        } else {
            return res.status(404).render('error', { error: 'not found' })
        }

    })


app.get('/cb',
    (req, res) => {
        res.render('cb')
    }
)

app.get('/login',
    (req, res) => {
        sp = new URLSearchParams({
            redirect_uri: 'http://' + req.headers.host + '/cb',
            response_type: 'token'
        })
        res.redirect(AUTH_HOST_EXT + '/auth?' + sp.toString())
    }
)

app.get('/register',
    (req, res) => {
        sp = new URLSearchParams({
            redirect_uri: 'http://' + req.headers.host + '/registered'
        })
        res.redirect(AUTH_HOST_EXT + '/register?' + sp)
    }
)

app.get('/registered',
    (req, res) => {
        res.render('registered')
    }
)

app.get('/logout',
    (req, res) => {
        res.clearCookie('token')
        res.redirect('/')
    }
)

app.get('/me',
    val.cookie('token').isString().isUUID(),
    async (req, res) => {

        errors = val.validationResult(req);
        if (!errors.isEmpty()) {
            return res.status(400).render('error', { error: 'bad parameters' })
        }

        let me = await fetch(AUTH_HOST_INT + '/me?token=' + req.cookies.token).then(r => r.json())
        let money = await fetch(AUTH_HOST_INT + '/money?token=' + req.cookies.token).then(r => r.json())

        if (me.error || money.error) {
            res.clearCookie('token')
            return res.redirect('/error?msg=please, login again')
        }
        return res.render('me', { username: me.username, role: me.role, balance: money.balance })
    }
)



app.get('/new',
    (req, res) => {
        res.render('new_recipe')
    })

app.post('/new',
    val.cookie('token').isString().isUUID(),
    val.body('content').isString(),
    val.body('title').isString(),
    async (req, res) => {

        if (!req.cookies.token) {
            return res.status(403).render('error', { error: 'you need to login' })
        }

        let errors = val.validationResult(req)
        if (!errors.isEmpty()) {
            return res.status(400).render('error', { error: 'bad parameters' })
        }

        let public = req.body.public ? 1 : 0
        let { username, role } = await fetch(AUTH_HOST_INT + '/me?token=' + req.cookies.token).then(r => r.json())

        if (!username || !role) {
            res.clearCookie('token')
            return res.redirect('/error?msg=please, login again')
        }

        if (role !== 'author' && role !== 'admin') {
            return res.status(403).render('error', { error: 'only an author can create a new recipe' })
        }

        clean = DOMPurify.sanitize(req.body.content)
        id = crypto.randomUUID()

        db.prepare('INSERT INTO recipes(id, title, content, author, public) VALUES(?,?,?,?,?)').run([id, req.body.title, clean, username, public])
        res.redirect('/' + id)
    })

app.get('/buyad',
    val.query('recipeid').isString().isUUID(),
    async (req, res) => {

        let errors = val.validationResult(req)
        if (!errors.isEmpty()) {
            return res.status(400).render('error', { error: 'bad parameters' })
        }

        return res.render('buyad', { recipeid: req.query.recipeid })
    }
)

app.post('/buyad',
    val.body('recipeid').isString().isUUID(),
    val.body('ad').isString(),
    val.cookie('token').isString().isUUID(),
    async (req, res) => {

        if (!req.cookies.token) {
            return res.render('error', { error: 'you need to login' })
        }

        let errors = val.validationResult(req)
        if (!errors.isEmpty()) {
            return res.status(400).render('error', { error: 'bad parameters' })
        }

        let to_user = db.prepare('SELECT author FROM recipes WHERE id = ?').get(req.body.recipeid)

        if (!to_user) {
            return res.status(404).render('error', { error: 'recipe not found' })
        }

        if (db.prepare('SELECT owner FROM ads WHERE recipeid = ?').get(req.body.recipeid)) {
            return res.status(400).render('error', { error: 'ad already taken' })
        }

        user_info = await fetch(AUTH_HOST_INT + '/me?token=' + req.cookies.token).then(r => r.json())
        user_money = await fetch(AUTH_HOST_INT + '/money?token=' + req.cookies.token).then(r => r.json())

        if (user_info.error) {
            res.clearCookie('token')
            return res.redirect('/error?msg=please, login again')
        }

        if (!user_money.balance || user_money.balance < 100) {
            return res.render('error', { error: 'not enough money' })
        }

        if (user_info.role !== 'advertiser' && user_info.role !== 'admin') {
            return res.render('error', { error: 'you need to be an advertiser to buy an ad' })
        }


        r = await fetch(AUTH_HOST_INT + '/transaction', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/x-www-form-urlencoded'
            },
            body: new URLSearchParams({
                'token': req.cookies.token,
                'to': to_user.author,
                'amount': '100'
            })
        })


        if (r.status === 200) {
            let ad_text = req.body.ad
            if (user_info.role === 'admin') {
                // automatic personalized ads for the admin!
                ad_text = '<h4 style="color: red;">A special message from the admin:</h4><p>' + ejs.escapeXML(ad_text) + '</p>'
            }
            db.prepare('INSERT INTO ads (recipeid,owner,content) VALUES (?,?,?)').run([req.body.recipeid, user_info.username, ad_text])
            return res.redirect('/' + req.body.recipeid)
        }

        return res.status(r.status).render('error', { error: 'transaction failed' })
    }
)

app.get('/report',
    val.query('recipeid').isString().isUUID(),
    async (req, res) => {

        let errors = val.validationResult(req)
        if (!errors.isEmpty()) {
            return res.status(400).render('error', { error: 'bad parameters' })
        }

        return res.render('report', { recipeid: req.query.recipeid })
    }
)

app.post('/report',
    val.body('recipeid').isString().isUUID(),
    async (req, res) => {

        let errors = val.validationResult(req)
        if (!errors.isEmpty()) {
            return res.status(400).render('error', { error: 'bad parameters' })
        }

        try {

            let result = await fetch(BOT_URL, {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json'
                },
                body: JSON.stringify({ url: BLOG_HOST + '/' + req.body.recipeid })
            })
            let { msg } = await result.json()

            if (result.status === 200) {
                return res.render('reported', { msg, success: true })
            }

            return res.render('reported', { msg, success: false })

        } catch (error) {

            console.error(error)

            return res.render('reported', { msg: 'Failed to report the recipe, please contact the admin', success: false })

        }

    }
)

app.get('/error',
    (req, res) => {
        if (!req.query.msg) {
            return res.redirect('/')
        }
        res.render('error', { error: req.query.msg })
    }
)


app.listen(port, () => {
    console.log(`App listening on port ${port}`)
})