import socket as sock
import rsa, os, pickle

def menu():
    print('''
    +-----------------------------+
    |    Benny Ridwan Susanto     |
    |      NIM 202410102015       |
    |   Tugas Akhir Kriptografi   |
    +-----------------------------+
    |         MENU PROGRAM        |
    |- TIME (Waktu saat ini)      |
    |- QUOTE (Quote Random)       |
    |- JOKES (Jokes Receh)        |
    |- FACT (Fakta Menarik)       |
    |- RIDDLE (Teka-teki menarik) |
    +-----------------------------+
    *Masukkan menu sebagai query dibawah
    ''')
def clear_scr():
    if os.name == 'nt':
        os.system('cls')
    elif os.name == 'posix':
        os.system('clear')
def end_program():
    confirm = input('Tekan Enter untuk mengulang, masukkan 0 untuk berhenti\n')
    clear_scr()
    decision = True
    if confirm == '0':
        decision = False
    elif confirm == '':
        decision = True
    else:
        print('PERINTAH TIDAK DIKETAHUI!!!')
        end_program()
    return decision
def send_msg(client, msg):
    msg += '\r\n'
    client.send(msg.encode())
def server_reply(client):
    reply_msg = ''
    while True:
        reply = (client.recv(16)).decode()
        reply_msg += reply
        if '\r\n' in reply:
            break
    return reply_msg
def sendpubkey(client_pubkey, client):
    key_bytes = pickle.dumps(client_pubkey)
    key_hex_str = key_bytes.hex()
    send_msg(client, key_hex_str)
def recvpubkey(client):
    received = server_reply(client)
    rm_end = received.replace('\r\n', '')
    rev_key_hex_str = bytes.fromhex(rm_end)
    rev_key_bytes = pickle.loads(rev_key_hex_str)
    return rev_key_bytes
def decrypt_reply(encrypted, client_privkey, server_pubkey):
    rm_end = encrypted.replace('\r\n', '')
    pack_med = bytes.fromhex(rm_end)
    pack_raw = pickle.loads(pack_med)
    rep_cipher = pack_raw['cipher']
    rep_signature = pack_raw['signature']
    plaintext = rsa.decrypt(rep_cipher, client_privkey)
    # plaintext += b'1' #Untuk test verifikasi signature gagal
    plain_decoded = plaintext.decode('utf8')
    try:
        verify = rsa.verify(plaintext, rep_signature, server_pubkey)
        if verify == 'SHA-1':
            return plain_decoded
    except:
        return False

print('Membangkitkan pasangan kunci RSA...')
(client_pubkey, client_privkey) = rsa.newkeys(3072)
clear_scr()
input('Pasangan kunci RSA berhasil dibuat!\nTekan Enter untuk melanjutkan...')
ip_addr = input('Masukkan Alamat IP Server: ')
port = int(input('Masukkan Port Server: '))

while True:
    client = sock.socket(sock.AF_INET, sock.SOCK_STREAM)
    
    client.connect((ip_addr, port))
    print(f'Terhubung dengan {ip_addr} pada port {port}')

    sendpubkey(client_pubkey, client)
    server_pubkey = recvpubkey(client)

    menu()
    msg = str(input('Masukkan query: '))
    send_msg(client, msg)
    clear_scr()
    print('Pesan terkirim: ' + msg.replace('\r\n', ''))

    rep = server_reply(client)
    decrypted = decrypt_reply(rep, client_privkey, server_pubkey)
    if decrypted == False:
        print('Proses Verifikasi Signature RSA Gagal!')
    else:
        print('Balasan dari server:\n' + str(decrypted))

    client.close()
    print('Koneksi telah ditutup')
    if end_program() == True:
        continue
    else:
        break