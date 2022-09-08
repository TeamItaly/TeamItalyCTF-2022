const puppeteer = require('puppeteer')

const USERNAME = process.env['USERNAME'] || 'admin'
const PASSWORD = process.env['PASSWORD'] || 'password'

const TIMEOUT = 1000 * 5 // 5s

const AUTH_URL = process.env['AUTH_URL'] || 'http://localhost:3000/auth'

async function visit(url) {

    console.log('Running browser to visit "%s"', url);

    const browser = await puppeteer.launch({
        headless: true,
        args: [
            '--disable-default-apps',
            '--disable-extensions',
            '--disable-gpu',
            '--disable-sync',
            '--disable-translate',
            '--hide-scrollbars',
            '--metrics-recording-only',
            '--mute-audio',
            '--no-first-run',
            '--no-sandbox',
            '--safebrowsing-disable-auto-update'
        ],
        executablePath: '/usr/bin/google-chrome'
    })

    // Authenticate
    let page = await browser.newPage()
    page.setDefaultNavigationTimeout(TIMEOUT)

    try {
        await page.goto(url)

        console.log(page.url())

        await page.waitForSelector('#login')
        await page.click('#login')


        console.log(page.url())

        await page.waitForSelector('#inputUsername', { timeout: TIMEOUT })

        const login_url = page.url()

        console.log(login_url)

        if (! typeof login_url === 'string' || !login_url.startsWith(AUTH_URL)) {
            console.log(`Bad auth url "${login_url}"`)
            return 'Bad auth url'
        }

        //await page.waitForNavigation({ waitUntil: 'networkidle2' })


        await page.focus('#inputUsername')
        await page.keyboard.type(USERNAME)


        // if (login_url !== page.url()) {
        //     console.log('???')
        //     return 'Bad auth url'
        // }

        await page.focus('#inputPassword')
        await page.keyboard.type(PASSWORD)
        await page.click('#submit')

        await page.waitForNavigation();


        // wait in the page
        await new Promise(resolve => setTimeout(resolve, TIMEOUT));
        await page.close()
        await browser.close()
        return 'ok'
    } catch (e) {
        await browser.close()
        console.log(e)
        throw (e)
    }

}

module.exports = { visit }