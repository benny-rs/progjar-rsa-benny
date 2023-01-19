import socket as sock
from datetime import datetime as dt
import requests as req
import rsa, pickle, os

reply = ''
def clear_scr():
    if os.name == 'nt':
        os.system('cls')
    elif os.name == 'posix':
        os.system('clear')
def limit_length(func_name):
    global reply
    if len(reply) >= 351:
        func_name()
def rep_time():
    global reply
    reply = 'Waktu sekarang: ' + dt.now().strftime('%A, %d %B %Y | %H:%M')
def rep_quote():
    global reply
    result = req.get('https://api.quotable.io/random')
    data = result.json()
    reply = 'Quote hari ini: ' + data['content']
    limit_length(rep_quote)
def rep_jokes():
    global reply
    result = req.get('https://api.chucknorris.io/jokes/random')
    data = result.json()
    reply = 'Jokes receh: ' + data['value']
    limit_length(rep_jokes)
def rep_fact():
    global reply
    result = req.get('https://uselessfacts.jsph.pl/random.json')
    data = result.json()
    reply = "Fakta menarik: " + data['text']
    if data['language'] != 'en':
        rep_fact()
    limit_length(rep_fact)
def rep_riddle():
    global reply
    result = req.get('https://api.api-ninjas.com/v1/riddles')
    data = result.json()
    reply = "Question: " + data[0]['question'] + "\nAnswer: " + data[0]['answer']
    limit_length(rep_riddle)
def send_msg(client_conn, reply):
    reply += '\r\n'
    client_conn.send(reply.encode())
def recv_msg(client_conn, addr):
    msg = ''
    while True:
        msg_part = str((client_conn.recv(16)).decode())
        msg += msg_part
        if '\r\n' in msg_part:
            break
    return msg
def sendpubkey(server_pubkey, client_conn):
    key_bytes = pickle.dumps(server_pubkey)
    key_hex_str = key_bytes.hex()
    send_msg(client_conn, key_hex_str)
def recvpubkey(client_conn, addr):
    received = recv_msg(client_conn, addr)
    rm_end = received.replace('\r\n', '')
    rev_key_hex_str = bytes.fromhex(rm_end)
    rev_key_bytes = pickle.loads(rev_key_hex_str)
    return rev_key_bytes
def encrypt_reply(reply, client_pubkey, server_privkey):
    plain = reply.encode('utf8')
    reply_encrypt = rsa.encrypt(plain, client_pubkey)
    reply_signed = rsa.sign(plain, server_privkey, 'SHA-1')
    pack_raw = {'cipher':reply_encrypt, 'signature':reply_signed}
    pack_med = pickle.dumps(pack_raw)
    pack_ready = pack_med.hex()
    return pack_ready

print('Membangkitkan pasangan kunci RSA...')
(server_pubkey, server_privkey) = rsa.newkeys(3072)
clear_scr()
print('Pasangan kunci RSA berhasil dibuat!')

server = sock.socket(sock.AF_INET, sock.SOCK_STREAM)
host = '0.0.0.0'
port = 10000
server.bind((host, port))
print(f'Server berjalan pada port {port}')

while True:
    server.listen()
    client_conn, addr = server.accept()

    client_pubkey = recvpubkey(client_conn, addr)
    sendpubkey(server_pubkey, client_conn)
    
    msg = recv_msg(client_conn, addr)
    print('Diterima pesan: ' + msg.replace('\r\n', ''))
    msg2 = msg.replace('\r\n', '')
    if msg2.upper() == 'TIME':
        rep_time()
    elif msg2.upper() == 'QUOTE':
        rep_quote()
    elif msg2.upper() == 'JOKES':
        rep_jokes()
    elif msg2.upper() == 'FACT':
        rep_fact()
    elif msg2.upper() == 'RIDDLE':
        rep_riddle()
    else:
        reply = 'QUERY TIDAK ADA!!!'

    encrypted = encrypt_reply(reply, client_pubkey, server_privkey)
        
    send_msg(client_conn, encrypted)