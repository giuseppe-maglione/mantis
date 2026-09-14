import socket
import random, time
import select

from . import *
from .. import DecoyService
from ...utils.logger import logger
from ...utils import uniform_random_natural, generate_random_date

from .fake_ftp_tarpit import TarpitFTP


DEFAULT_GOAL_FILE_POOL = [
    "credentials.db", "my_credentials.txt", "authorized_keys", "target_manifest.xml",
    "domain_admin.kdbx", "vault_export.json", "network_map.xml", "master_keyring.gpg",
    "access_token.txt", "security_patch.pdf", "security_notes.md", "backup_shadow.bak",
]

DEFAULT_MUNDANE_FILE_POOL = [
    "readme.txt", "license.md", "index.html", ".DS_Store", "thumbs.db",
    "setup.log", "cache.bin", "temp_01.dat", "config.default.ini",
    "favicon.ico", "app.js", "style.css", "npm-debug.log", "error_log"
]

FILE_SIZE_RANGES_BY_TYPE = {
    'txt':  (500,        200_000),        
    'md':   (500,        200_000),
    'xml':  (2_000,       1_000_000),      
    'json': (1_000,       3_000_000),
    'log':  (1_000,       3_000_000),
    'db':   (50_000,      5_000_000),    
    'kdbx': (10_000,      5_000_000),      
    'gpg':  (1_000,       50_000),         
    'pdf':  (50_000,      4_000_000),
    'bak':  (1_000_000,   1_000_000),    
    'authorized_keys': (200, 4_000),       
    'default': (1_000, 10_000_000),
}

DIR_SIZE_CHOICES = [4096, 4096, 4096, 4096, 8192, 8192, 12288, 16384]

REALISTIC_SERVER_BANNER = b'(vsFTPd 3.0.3)'


class GoalSeekingTarpitFTP(TarpitFTP):

    source_name = 'Decoy.tarpit.FTP.goal_seeking'

    def __call__(self, client_socket, client_address, injection_manager):
        banner = self.hparams.get('SERVER_BANNER', REALISTIC_SERVER_BANNER)
 
        if 'BANNER_INJECTION_POOL' in self.hparams:
            payload = random.choice(self.hparams['BANNER_INJECTION_POOL'])
            from ...InjectionManager.utils import make_text_invisible_terminal
            payload = make_text_invisible_terminal(payload)
            banner += payload.encode()
 
        client_socket.sendall(b"220 %s\r\n" % banner)
        self.handle_ftp_session(client_socket, client_address, injection_manager)

    def handle_ftp_session(self, client_socket, client_address, injection_manager):
        with client_socket:
            user = None
            authenticated = False
            current_path = '/'
            client_data_connection_info = None
            pasv_socket = None

            buffer = "" 

            while True:
                raw = client_socket.recv(BUFFSIZE)
                if not raw:
                    break

                buffer += raw.decode(ENCODING, errors='ignore')

                while '\n' in buffer:
                    line, buffer = buffer.split('\n', 1)
                    
                    data = line.strip()
                    if not data:
                        continue

                    # --- logging logic ---
                    cmd_base = data.split(' ')[0].upper() if data else ""
                    ip = client_address[0]
                    
                    if cmd_base in ['USER', 'PASS', 'CWD', 'LIST', 'RETR', 'PWD']:
                        logger.info(f"[{ip}] ➜ {data}")
                    else:
                        logger.debug(f"[{ip}] ⚙️ {data}")

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

                    elif data.upper() == 'PASV':
                        if authenticated:
                            pasv_socket = self.handle_pasv(client_socket)
                            client_data_connection_info = None
                        else:
                            client_socket.sendall(b"530 Not logged in\r\n")

                    elif data.upper() == 'SYST':
                        client_socket.sendall(b"215 UNIX Type: L8\r\n")

                    elif data.upper() == 'FEAT':
                        client_socket.sendall(b"211-Features:\r\n PASV\r\n211 End\r\n")

                    elif data.upper().startswith('TYPE'):
                        client_socket.sendall(b"200 Type set to I\r\n")

                    elif data.upper().startswith('LIST'):
                        if authenticated:
                            if pasv_socket or client_data_connection_info:
                                # --- extract path from LIST command ---
                                target_path = current_path
                                parts = data.split()
                                
                                for part in parts[1:]:
                                    if not part.startswith('-'):
                                        if part.startswith('/'):
                                            target_path = part  
                                        else:
                                            target_path = current_path.rstrip('/') + '/' + part
                                        break
                                
                                self.handle_list(client_socket, target_path, client_data_connection_info, pasv_socket, injection_manager)
                                
                                if pasv_socket:
                                    pasv_socket.close()
                                    pasv_socket = None
                            else:
                                client_socket.sendall(b"425 Use PORT or PASV first.\r\n")
                        else:
                            client_socket.sendall(b"530 Not logged in\r\n")

                    elif data.upper().startswith('RETR'):
                        if authenticated:
                            filename = data.split(' ', 1)[1].strip() if len(data.split(' ', 1)) > 1 else ''
                            filename = filename.rstrip('/').split('/')[-1]
                            self.handle_retr(client_socket, current_path, filename, client_data_connection_info, pasv_socket, injection_manager, client_address)
                            if pasv_socket:
                                pasv_socket.close()
                                pasv_socket = None
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
                            pasv_socket = None
                        else:
                            client_socket.sendall(b"530 Not logged in\r\n")

                    elif data.upper() == 'QUIT':
                        self.handle_quit(client_socket)
                        buffer = ""
                        break

                    elif data.upper().startswith('ABOR'):
                        client_socket.sendall(b"225 ABOR command successful.\r\n")

                    else:
                        client_socket.sendall(b"500 Unknown command\r\n")
                
                if data.upper() == 'QUIT':
                    break

            logger.info(f"Closing connection to {client_address}")

    def make_fake_file_listing(self, current_path):
        depth = len([p for p in current_path.split('/') if p])
        seed = hash(current_path) ^ 0x6A0F51E3
        rnd = random.Random(seed)
        files = []
        
        num_mundane = rnd.randint(1, 6)
        mundane_pool = self.hparams.get('MUNDANE_FILE_POOL', DEFAULT_MUNDANE_FILE_POOL)
        
        chosen_mundane = rnd.sample(mundane_pool, min(num_mundane, len(mundane_pool)))
        for fname in chosen_mundane:
            size = rnd.randint(100, 500_000) 
            files.append((fname, size))

        base_prob = self.hparams.get('GOAL_FILE_BASE_PROB', 0.08)
        slope = self.hparams.get('GOAL_FILE_PROB_SLOPE', 0.05)
        cap = self.hparams.get('GOAL_FILE_PROB_CAP', 0.65)
        prob = min(base_prob + slope * depth, cap)

        if rnd.random() < prob:
            pool = self.hparams.get('GOAL_FILE_POOL', DEFAULT_GOAL_FILE_POOL)
            fname = rnd.choice(pool)

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

    def handle_list(self, client_socket, current_path, client_data_connection_info, pasv_socket, injection_manager):
        seed = hash(current_path)
        fake_dirs = self.make_fake_dir_names(seed, current_path)
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

        data_socket = None
        try:
            if pasv_socket:
                client_socket.sendall(b"150 Here comes the directory listing\r\n")
                data_socket, _ = pasv_socket.accept()
                injection_ip = client_socket.getpeername()[0]
                injection_port = client_socket.getpeername()[1]
            else:
                client_ip, client_port = client_data_connection_info
                data_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                data_socket.connect((client_ip, client_port))
                client_socket.sendall(b"150 Here comes the directory listing\r\n")
                injection_ip, injection_port = client_ip, client_port

            time.sleep(random.Random().uniform(0.5, 1.5))
            
            empty_msg = b""
            payload, _ = injection_manager((injection_ip, injection_port), self.source_name, self.name + '.browse', empty_msg)
            
            # --- new injection logic: append payload to directory listing ---
            dir_listing_with_payload = dir_listing.encode(ENCODING) + payload + b"\r\n"
            
            data_socket.sendall(dir_listing_with_payload)
            data_socket.close()
            
            client_socket.sendall(b"226 Directory send OK\r\n")
            
        except socket.error as e:
            client_socket.sendall(b"425 Can't open data connection.\r\n")
            logger.info(f"Error transferring data: {e}")
            if data_socket:
                data_socket.close()

    def handle_cwd(self, client_socket, current_path, data, client_data_connection_info, injection_manager):
        client_ip, client_port = client_socket.getpeername()
        
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

    def handle_retr(self, client_socket, current_path, filename, client_data_connection_info, pasv_socket, injection_manager, client_address):
        if client_data_connection_info is None and pasv_socket is None:
            client_socket.sendall(b"425 Use PORT or PASV first.\r\n")
            return

        files = self.make_fake_file_listing(current_path)
        match = next((f for f in files if f[0] == filename), None)

        if match is None:
            client_socket.sendall(b"550 File not found\r\n")
            return

        fname, size = match
        drip_bytes = self.hparams.get('RETR_DRIP_BYTES', 64)
        drip_interval = self.hparams.get('RETR_DRIP_INTERVAL', 2.0)
        max_duration = self.hparams.get('RETR_MAX_DURATION', 60)

        logger.critical(f"{client_address} attempting RETR of decoy goal file '{fname}' ({size} bytes) at {current_path}")

        data_socket = None
        try:
            if pasv_socket:
                client_socket.sendall(b"150 Opening BINARY mode data connection for %s (%d bytes)\r\n" % (fname.encode(ENCODING), size))
                data_socket, _ = pasv_socket.accept()
                injection_ip, injection_port = client_socket.getpeername()
            else:
                client_ip, client_port = client_data_connection_info
                data_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                data_socket.connect((client_ip, client_port))
                client_socket.sendall(b"150 Opening BINARY mode data connection for %s (%d bytes)\r\n" % (fname.encode(ENCODING), size))
                injection_ip, injection_port = client_ip, client_port

            start = time.time()
            sent = 0
            
            if fname.endswith('.db') or fname.endswith('.sqlite'):
                magic = b"SQLite format 3\000"
            elif fname.endswith('.pdf'):
                magic = b"%PDF-1.4\n"
            elif fname.endswith('.txt') or fname.endswith('.md'):
                magic = b"CONFIDENTIAL AND PROPRIETARY\n\n"
            else:
                magic = b""
            
            if magic:
                data_socket.sendall(magic)
                sent += len(magic)

            try:
                while (time.time() - start) < max_duration and sent < size:
                    r, _, _ = select.select([client_socket], [], [], 0.0)
                    if r:
                        peek_data = client_socket.recv(1024, socket.MSG_PEEK)
                        if not peek_data:
                            logger.info(f"Control connection closed by client during RETR: {client_address}")
                            break
                        if b"ABOR" in peek_data.upper():
                            logger.info(f"ABOR command detected during RETR: {client_address}")
                            break

                    current_drip = int(drip_bytes * random.uniform(0.8, 1.2))
                    chunk = bytes(random.getrandbits(8) for _ in range(current_drip))
                    data_socket.sendall(chunk)
                    sent += current_drip
                    jitter = random.uniform(0.5, 1.5)
                    time.sleep(drip_interval * jitter)
            except (BrokenPipeError, ConnectionResetError, socket.error) as e:
                logger.info(f"Data connection dropped during drip-feed to {client_address}: {e}")

            data_socket.close()

            msg = b"426 Connection closed (transfer aborted). "
            msg, _ = injection_manager((injection_ip, injection_port), self.source_name, self.name + '.retr_fail', msg)
            msg += b'\r\n'
            client_socket.sendall(msg)

        except socket.error as e:
            client_socket.sendall(b"425 Can't open data connection.\r\n")
            logger.info(f"Error transferring data: {e}")
            if data_socket:
                data_socket.close()