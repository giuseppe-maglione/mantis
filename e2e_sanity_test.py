import sys, socket, threading, time
sys.path.insert(0, '.')

from Mantis.Decoys.FTP.fake_ftp_tarpit_goal import GoalSeekingTarpitFTP
from Mantis.InjectionManager.default import DefaultInjectionManager

hparams = {
    'EXPECTED_NUMBER_OF_DIRECTORIES': 6,
    'GOAL_FILE_BASE_PROB': 0.9,   # alziamo la prob per forzare la comparsa nel test
    'GOAL_FILE_PROB_SLOPE': 0.0,
    'GOAL_FILE_PROB_CAP': 0.95,
    'GOAL_FILE_MIN_SIZE': 5000,
    'GOAL_FILE_MAX_SIZE': 6000,   # piccolo cosi' il test finisce in fretta
    'RETR_DRIP_BYTES': 500,
    'RETR_DRIP_INTERVAL': 0.05,
    'RETR_MAX_DURATION': 5,
}

from confs.ftp_filesystem_tarpit_goal import TRIGGER_EVENTS

im = DefaultInjectionManager(TRIGGER_EVENTS, '127.0.0.1', '127.0.0.1')
decoy = GoalSeekingTarpitFTP(port=2121, name='into_tarpit', hparams=hparams)

th = threading.Thread(target=decoy.serve, args=(im,), daemon=True)
th.start()
time.sleep(0.5)

# --- client raw FTP (control channel) ---
ctrl = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
ctrl.connect(('127.0.0.1', 2121))
print("BANNER:", ctrl.recv(1024))

def send(cmd):
    ctrl.sendall((cmd + '\r\n').encode())
    time.sleep(0.2)
    return ctrl.recv(4096)

print("USER:", send("USER anonymous"))
print("PASS:", send("PASS x"))

# apriamo un listener locale per il canale dati (PORT attivo)
data_srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
data_srv.bind(('127.0.0.1', 0))
data_srv.listen(1)
dport = data_srv.getsockname()[1]
p1, p2 = dport // 256, dport % 256
print("PORT:", send(f"PORT 127,0,0,1,{p1},{p2}"))

ctrl.sendall(b"LIST\r\n")
conn, _ = data_srv.accept()
listing = b""
while True:
    chunk = conn.recv(4096)
    if not chunk: break
    listing += chunk
conn.close()
print("LIST DATA:\n", listing.decode())
print("LIST CTRL TAIL:", ctrl.recv(4096))

# individuiamo il nome del file esca dal listing
fname = None
for line in listing.decode().splitlines():
    if line.startswith('-rw'):
        fname = line.split()[-1]
        break
print("Target file trovato:", fname)

if fname:
    data_srv2 = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    data_srv2.bind(('127.0.0.1', 0))
    data_srv2.listen(1)
    dport2 = data_srv2.getsockname()[1]
    p1, p2 = dport2 // 256, dport2 % 256
    print("PORT2:", send(f"PORT 127,0,0,1,{p1},{p2}"))

    ctrl.sendall(f"RETR {fname}\r\n".encode())
    conn2, _ = data_srv2.accept()
    t0 = time.time()
    total = 0
    while True:
        chunk = conn2.recv(4096)
        if not chunk: break
        total += len(chunk)
    conn2.close()
    print(f"RETR: {total} bytes ricevuti in drip-feed in {time.time()-t0:.2f}s (mai completato)")
    print("RETR CTRL TAIL:", ctrl.recv(4096))

ctrl.sendall(b"QUIT\r\n")
print("QUIT:", ctrl.recv(1024))
ctrl.close()
