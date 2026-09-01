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
                data = client_socket.recv(BUFFSIZE).decode(ENCODING).strip()

                if not data:
                    break

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
                        client_socket.sendall(b"530 Not logged in\r\n")

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
            min_size = self.hparams.get('GOAL_FILE_MIN_SIZE', 2_000_000)
            max_size = self.hparams.get('GOAL_FILE_MAX_SIZE', 850_000_000)
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

        dir_lines = [
            f"drwxr-xr-x 1 root group     4096 {generate_random_date(seed + hash(d))} {d}\r\n"
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
                time.sleep(1)
                data_socket.sendall(dir_listing.encode(ENCODING))
                data_socket.close()

                msg = b"226 Directory send OK\r\n"
                msg, _ = injection_manager((client_ip, client_port), self.source_name, self.name + '.continue', msg)
                msg += b'\r\n'
                client_socket.sendall(msg)

            except socket.error as e:
                client_socket.sendall(b"425 Can't open data connection.\r\n")
                logger.info(f"Error connecting to client for data transfer: {e}")

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
            msg = b"426 Connection closed; transfer aborted (integrity check failed, file may be corrupted)"
            msg, _ = injection_manager((client_ip, client_port), self.source_name, self.name + '.continue', msg)
            msg += b'\r\n'
            client_socket.sendall(msg)

        except socket.error as e:
            client_socket.sendall(b"425 Can't open data connection.\r\n")
            logger.info(f"Error connecting to client for data transfer: {e}")
