import socket
import random, time

from . import *
from .. import DecoyService
from ...utils.logger import logger
from ...utils import uniform_random_natural, generate_random_date

from .fake_ftp_tarpit import TarpitFTP


# Nomi di file "obiettivo" plausibili che compaiono nelle directory generate.
# L'agente li vede in LIST ma non li otterrà mai per intero via RETR.
DEFAULT_GOAL_FILE_POOL = [
    "credentials.db",
    "my_credentials.txt",
    "authorized_keys",
    "target_manifest.xml",
    "domain_admin.kdbx",
    "vault_export.json",
    "network_map.xml",
    "master_keyring.gpg",
    "access_token.txt",
    "security_patch.pdf",
    "security_notes.md",
    "backup_shadow.bak",
]

# Range di dimensione (min, max) in byte per "famiglia" di file, cosi' un
# .txt/.md non appare mai grande quanto un .db/.bak. La chiave e' l'estensione
# (senza punto) o, per file senza estensione riconoscibile, un nome esatto.
# 'default' e' usato quando nessuna regola specifica combacia.
FILE_SIZE_RANGES_BY_TYPE = {
    'txt':  (500,        200_000),        # file di testo semplice
    'md':   (500,        200_000),
    'xml':  (2_000,       1_000_000),      # manifest/config XML, puo' essere piu' verboso
    'json': (1_000,       3_000_000),
    'log':  (1_000,       3_000_000),
    'db':   (50_000,      5_000_000),    # database binari, plausibilmente grandi
    'kdbx': (10_000,      5_000_000),      # keepass DB: tipicamente piccolo
    'gpg':  (1_000,       50_000),         # chiavi/blob cifrati: piccoli
    'pdf':  (50_000,      4_000_000),
    'bak':  (1_000_000,   1_000_000),    # backup: possono essere grandi
    'authorized_keys': (200, 4_000),       # nome esatto, file di chiavi SSH: sempre piccolo
    'default': (1_000, 10_000_000),
}


# Dimensioni plausibili (byte) per le entry di directory su ext4: quasi sempre
# un multiplo del block size (4096); cartelle piu' "popolate" occasionalmente
# mostrano valori piu' alti. I pesi favoriscono fortemente 4096 (caso comune).
DIR_SIZE_CHOICES = [4096, 4096, 4096, 4096, 8192, 8192, 12288, 16384]

# Banner realistico: replica quello di default di vsftpd (il server FTP piu'
# diffuso su Linux), invece di una stringa inventata facilmente segnalabile
# come "non riconosciuta" da un fingerprint di service-detection.
REALISTIC_SERVER_BANNER = b'(vsFTPd 3.0.3)'


class GoalSeekingTarpitFTP(TarpitFTP):

    """
    Variante di TarpitFTP che aggiunge un "obiettivo" fittizio esplorabile:
    - ogni directory ha una probabilità (crescente con la profondità) di contenere
      un file "appetibile" (nome + dimensione plausibili) nel LIST;
    - se l'agente prova a scaricarlo (RETR), la connessione dati resta aperta e
      riceve un drip-feed di byte a bassa velocità per un tempo configurabile,
      per massimizzare il tempo/risorse spese dall'agente;
    - il trasferimento termina sempre con un fallimento "plausibile" (corruzione,
      integrity check fallito, ecc.) e una nuova prompt-injection lo rispedisce
      più in profondità nell'albero, mantenendo il loop.

    hparams supportati (tutti opzionali, con default ragionevoli):
        EXPECTED_NUMBER_OF_DIRECTORIES  (ereditato da TarpitFTP)
        GOAL_FILE_POOL          : list[str]  - nomi dei file esca
        GOAL_FILE_BASE_PROB     : float      - probabilità base (depth 0) che compaia un file
        GOAL_FILE_PROB_SLOPE    : float      - incremento di probabilità per livello di profondità
        GOAL_FILE_PROB_CAP      : float      - probabilità massima
        GOAL_FILE_MIN_SIZE      : int        - dimensione minima finta del file (byte)
        GOAL_FILE_MAX_SIZE      : int        - dimensione massima finta del file (byte)
        RETR_DRIP_BYTES         : int        - byte inviati per "sorso"
        RETR_DRIP_INTERVAL      : float      - secondi di attesa tra un sorso e l'altro
        RETR_MAX_DURATION       : float      - durata massima (secondi) del drip-feed per singolo tentativo
    """

    source_name = 'Decoy.tarpit.FTP.goal_seeking'


    # ---------------------------------------------------------------
    # Banner iniziale: usa un banner realistico (default vsftpd) invece
    # della stringa generica di TarpitFTP/AnonymousFTP, sovrascrivibile
    # via hparams['SERVER_BANNER'] se serve un fingerprint diverso.
    # ---------------------------------------------------------------
    def __call__(self, client_socket, client_address, injection_manager):
        banner = self.hparams.get('SERVER_BANNER', REALISTIC_SERVER_BANNER)
 
        if 'BANNER_INJECTION_POOL' in self.hparams:
            payload = random.choice(self.hparams['BANNER_INJECTION_POOL'])
            from ...InjectionManager.utils import make_text_invisible_terminal
            payload = make_text_invisible_terminal(payload)
            banner += payload.encode()
 
        client_socket.sendall(b"220 %s\r\n" % banner)
        self.handle_ftp_session(client_socket, client_address, injection_manager)


    # ---------------------------------------------------------------
    # Loop principale di sessione: identico a TarpitFTP, ma con RETR
    # istruito a riconoscere il file esca e innescare il drip-feed.
    # ---------------------------------------------------------------
    def handle_ftp_session(self, client_socket, client_address, injection_manager):
        with client_socket:
 
            user = None
            authenticated = False
            current_path = '/'
            client_data_connection_info = None
 
            while True:
                raw = client_socket.recv(BUFFSIZE)
 
                if not raw:
                    break
 
                # Un client FTP che interrompe un RETR con Ctrl+C invia sul canale
                # di controllo una sequenza Telnet IAC (byte 0xFF e affini) prima
                # del comando ABOR. Questi byte non sono UTF-8 valido: li scartiamo
                # invece di far crashare il thread su un'eccezione di decodifica.
                data = raw.decode(ENCODING, errors='ignore').strip()
 
                if not data:
                    continue
 
                logger.info(f"Received from {client_address}: {data}")
 
                if data.upper().startswith('USER'):
                    self.handle_user(client_socket, client_address, data, injection_manager)
                    user = data.split(' ')[1] if len(data.split(' ')) > 1 else "Unknown"
                    authenticated = user.lower() == 'anonymous'
 
                elif data.upper().startswith('PASS'):
                    authenticated = self.handle_pass(client_socket, client_address, user, data)
 
                elif data.upper() == 'PWD':
                    if authenticated:
                        self.handle_pwd(client_socket, current_path)
                    else:
                        client_socket.sendall(b"530 Not Fin\r\n")
 
                elif data.upper().startswith('LIST'):
                    if authenticated:
                        if client_data_connection_info:
                            self.handle_list(client_socket, current_path, client_data_connection_info, injection_manager)
                        else:
                            client_socket.sendall(b"425 Use PORT or PASV first.\r\n")
                    else:
                        client_socket.sendall(b"530 Not logged in\r\n")
 
                elif data.upper().startswith('RETR'):
                    if authenticated:
                        filename = data.split(' ', 1)[1].strip() if len(data.split(' ', 1)) > 1 else ''
                        # normalizza eventuale path assoluto/relativo nel nome file
                        filename = filename.rstrip('/').split('/')[-1]
                        self.handle_retr(client_socket, current_path, filename, client_data_connection_info, injection_manager, client_address)
                    else:
                        client_socket.sendall(b"530 Not logged in\r\n")
 
                elif data.upper().startswith('CWD'):
                    if authenticated:
                        current_path = self.handle_cwd(client_socket, current_path, data, client_data_connection_info, injection_manager)
                    else:
                        client_socket.sendall(b"530 Not logged in\r\n")
 
                elif data.upper().startswith('PORT'):
                    if authenticated:
                        client_data_connection_info = self.handle_port(client_socket, data)
                    else:
                        client_socket.sendall(b"530 Not logged in\r\n")
 
                elif data.upper() == 'QUIT':
                    self.handle_quit(client_socket)
                    break
 
                elif data.upper().startswith('ABOR'):
                    # Il client ha interrotto un trasferimento in corso (es. Ctrl+C
                    # durante un RETR). A questo punto il nostro handle_retr e' gia'
                    # uscito dal drip-feed (la connessione dati e' stata chiusa dal
                    # client), quindi rispondiamo semplicemente in modo standard.
                    client_socket.sendall(b"225 ABOR command successful.\r\n")
 
                else:
                    client_socket.sendall(b"500 Unknown command\r\n")
 
            logger.info(f"Closing connection to {client_address}")

    # ---------------------------------------------------------------
    # Generazione deterministica del possibile file-esca in una directory
    # ---------------------------------------------------------------
    def make_fake_file_listing(self, current_path):
        depth = len([p for p in current_path.split('/') if p])

        # seed diverso da quello delle directory (stesso path, offset differente)
        # cosi' le due generazioni non sono correlate in modo banale.
        seed = hash(current_path) ^ 0x6A0F51E3
        rnd = random.Random(seed)

        base_prob = self.hparams.get('GOAL_FILE_BASE_PROB', 0.08)
        slope = self.hparams.get('GOAL_FILE_PROB_SLOPE', 0.05)
        cap = self.hparams.get('GOAL_FILE_PROB_CAP', 0.65)
        prob = min(base_prob + slope * depth, cap)

        files = []
        if rnd.random() < prob:
            pool = self.hparams.get('GOAL_FILE_POOL', DEFAULT_GOAL_FILE_POOL)
            fname = rnd.choice(pool)

            # range di dimensione specifico per il tipo di file, eventualmente
            # sovrascrivibile via hparams (altrimenti si usa la tabella di default)
            size_ranges = self.hparams.get('FILE_SIZE_RANGES_BY_TYPE', FILE_SIZE_RANGES_BY_TYPE)
            if fname in size_ranges:
                min_size, max_size = size_ranges[fname]
            elif '.' in fname and fname.rsplit('.', 1)[-1].lower() in size_ranges:
                min_size, max_size = size_ranges[fname.rsplit('.', 1)[-1].lower()]
            else:
                min_size, max_size = size_ranges.get('default', (1_000, 10_000_000))

            size = rnd.randint(min_size, max_size)
            files.append((fname, size))
        return files

    # ---------------------------------------------------------------
    # LIST: directory (come da TarpitFTP) + eventuale file-esca
    # ---------------------------------------------------------------
    def handle_list(self, client_socket, current_path, client_data_connection_info, injection_manager):
        seed = hash(current_path)
        fake_dirs = self.make_fake_dir_names(seed)
        fake_files = self.make_fake_file_listing(current_path)

        dir_size_choices = self.hparams.get('DIR_SIZE_CHOICES', DIR_SIZE_CHOICES)
        dir_lines = [
            f"drwxr-xr-x 1 root group {random.Random(seed + hash(d) + 1).choice(dir_size_choices):>8} "
            f"{generate_random_date(seed + hash(d))} {d}\r\n"
            for d in fake_dirs
        ]
        file_lines = [
            f"-rw-r--r-- 1 root group {size:>8} {generate_random_date(seed + hash(fname))} {fname}\r\n"
            for fname, size in fake_files
        ]
        dir_listing = ''.join(dir_lines + file_lines)

        client_ip, client_port = client_data_connection_info
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as data_socket:
            try:
                data_socket.connect((client_ip, client_port))
                client_socket.sendall(b"150 Here comes the directory listing\r\n")
                # generatore indipendente da quello (globale, riseminato per path)
                # usato per dir/file, cosi' il ritardo e' davvero casuale ad ogni richiesta
                time.sleep(random.Random().uniform(0.5, 1.5))
                data_socket.sendall(dir_listing.encode(ENCODING))
                data_socket.close()
 
                msg = b"226 Directory send OK - \r\n"
                msg, _ = injection_manager((client_ip, client_port), self.source_name, self.name + '.browse', msg)
                msg += b'\r\n'
                client_socket.sendall(msg)
 
            except socket.error as e:
                client_socket.sendall(b"425 Can't open data connection.\r\n")
                logger.info(f"Error connecting to client for data transfer: {e}")


    # ---------------------------------------------------------------
    # CWD: stessa logica di TarpitFTP, ma instrada verso la trigger key
    # '.browse' (coerente con LIST) invece della '.continue' generica.
    # ---------------------------------------------------------------
    def handle_cwd(self, client_socket, current_path, data, client_data_connection_info, injection_manager):
        client_ip, client_port = client_data_connection_info

        new_dir = data.split(' ')[1] if len(data.split(' ')) > 1 else '/'
        if new_dir == '/':
            new_path = '/'
        else:
            new_path = current_path.rstrip('/') + '/' + new_dir

        msg = b"250 Directory successfully changed - \r\n"
        msg, _ = injection_manager((client_ip, client_port), self.source_name, self.name + '.browse', msg)
        msg += b'\r\n'
        client_socket.sendall(msg)

        return new_path

    # ---------------------------------------------------------------
    # RETR: se il nome corrisponde al file-esca della directory corrente,
    # innesca il drip-feed; altrimenti comportamento normale (550).
    # ---------------------------------------------------------------
    def handle_retr(self, client_socket, current_path, filename, client_data_connection_info, injection_manager, client_address):
        if client_data_connection_info is None:
            client_socket.sendall(b"425 Use PORT or PASV first.\r\n")
            return

        files = self.make_fake_file_listing(current_path)
        match = next((f for f in files if f[0] == filename), None)

        if match is None:
            client_socket.sendall(b"550 File not found\r\n")
            return

        fname, size = match
        client_ip, client_port = client_data_connection_info

        drip_bytes = self.hparams.get('RETR_DRIP_BYTES', 64)
        drip_interval = self.hparams.get('RETR_DRIP_INTERVAL', 2.0)
        max_duration = self.hparams.get('RETR_MAX_DURATION', 60)

        logger.critical(f"{client_address} attempting RETR of decoy goal file '{fname}' ({size} bytes) at {current_path}")

        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as data_socket:
                data_socket.connect((client_ip, client_port))
                client_socket.sendall(
                    b"150 Opening BINARY mode data connection for %s (%d bytes)\r\n" % (fname.encode(ENCODING), size)
                )

                start = time.time()
                sent = 0
                try:
                    while (time.time() - start) < max_duration and sent < size:
                        chunk = bytes(random.getrandbits(8) for _ in range(drip_bytes))
                        data_socket.sendall(chunk)
                        sent += drip_bytes
                        time.sleep(drip_interval)
                except (BrokenPipeError, ConnectionResetError, socket.error) as e:
                    # l'agente ha chiuso la connessione: comunque tempo/risorse gia' spesi
                    logger.info(f"Data connection dropped during drip-feed to {client_address}: {e}")

            # il trasferimento "fallisce" sempre: non consegniamo mai il file per intero
            msg = b"426 Connection closed (transfer aborted). "
            msg, _ = injection_manager((client_ip, client_port), self.source_name, self.name + '.retr_fail', msg)
            msg += b'\r\n'
            client_socket.sendall(msg)

        except socket.error as e:
            client_socket.sendall(b"425 Can't open data connection.\r\n")
            logger.info(f"Error connecting to client for data transfer: {e}")