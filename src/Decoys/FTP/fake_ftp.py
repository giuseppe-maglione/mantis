import socket
import random

from . import *
from .. import DecoyService
from ...utils.logger import logger
from ...InjectionManager.utils import make_text_invisible_terminal

class AnonymousFTP(DecoyService):

    """Decoy FTP with Anonymous credentials enabled"""

    source_name = 'Decoy.FTP'

    def __call__(self, client_socket, client_address, injection_manager):

        banner = SERVER_BANNER
        # Send FTP banner message
        if 'BANNER_INJECTION_POOL' in self.hparams:
            payload = random.choice(self.hparams['BANNER_INJECTION_POOL'])
            payload = make_text_invisible_terminal(payload)
            banner += payload.encode()
        
        client_socket.sendall(b"220 %s\r\n" % banner)

        self.handle_ftp_session(client_socket, client_address, injection_manager)
    
    def handle_ftp_session(self, client_socket, client_address, injection_manager):
        with client_socket:
            user = None
            password = None

            while True:
                data = client_socket.recv(BUFFSIZE).decode(ENCODING).strip()
                
                if not data:
                    break

                logger.info(f"Received from {client_address}: {data}")
                
                if data.upper().startswith('USER'):                    
                    user = data.split(' ')[1] if len(data.split(' ')) > 1 else "Unknown"

                    logger.info(f"{user}@{client_address} into the decoy")
                    
                    if user.lower() == 'anonymous':
                        msg = b"230 Login Successful"
                        msg, to_kill = injection_manager(client_address, self.source_name, self.name, msg)
                        msg += b'\r\n'
                        client_socket.sendall(msg)

                        if to_kill:
                            logger.info("Self-kill")
                            client_socket.close()
                            break
                    else:
                        client_socket.sendall(b"331 Username OK, need password\r\n")
                        
                elif data.upper().startswith('PASS'):
                    password = data.split(' ')[1] if len(data.split(' ')) > 1 else "Unknown"
                    
                    if user.lower() == 'anonymous':
                        # No password needed for anonymous login
                        client_socket.sendall(b"230 Anonymous login successful\r\n")
                    else:
                        client_socket.sendall(b"530 Login incorrect\r\n")
                    
                    logger.info(f"Login attempt - USER: {user}, PASS: {password}")
                    
                    if user.lower() != 'anonymous':
                        break

                elif data.upper() == 'QUIT':
                    client_socket.sendall(b"221 Goodbye\r\n")
                    break

                elif data.upper() == 'SYST':
                    # Risposta standard che tranquillizza i client
                    client_socket.sendall(b"215 UNIX Type: L8\r\n")

                elif data.upper() == 'FEAT':
                    # Dichiariamo esplicitamente di supportare la modalità passiva
                    client_socket.sendall(b"211-Features:\r\n PASV\r\n211 End\r\n")

                elif data.upper().startswith('TYPE'):
                    # Rispondiamo 200 (Successo) a prescindere che chieda A (Ascii) o I (Image/Binary)
                    client_socket.sendall(b"200 Type set successfully\r\n")

                else:
                    client_socket.sendall(b"500 Unknown command\r\n")
            
            logger.info(f"Closing connection to {client_address}")

    # --- METODI DI UTILITA' EREDITATI DALLE CLASSI FIGLIE ---

    def handle_pasv(self, client_socket):
        """
        Apre una porta temporanea e restituisce il socket passivo.
        Verrà richiamata dalle classi figlie (TarpitFTP e GoalSeekingTarpitFTP)
        per gestire LIST e RETR.
        """
        local_ip = client_socket.getsockname()[0]
        if local_ip == '0.0.0.0':
            local_ip = '127.0.0.1' # Fallback sicuro

        # Crea un socket temporaneo in ascolto su una porta casuale (0)
        pasv_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        pasv_sock.bind((local_ip, 0))
        pasv_sock.listen(1)
        
        # Estrai la porta assegnata dal sistema operativo
        port = pasv_sock.getsockname()[1]
        
        # Calcola la stringa FTP per l'IP e la porta (h1,h2,h3,h4,p1,p2)
        p1 = port // 256
        p2 = port % 256
        h1, h2, h3, h4 = local_ip.split('.')
        
        msg = f"227 Entering Passive Mode ({h1},{h2},{h3},{h4},{p1},{p2}).\r\n"
        client_socket.sendall(msg.encode(ENCODING))
        
        logger.info(f"Entered Passive Mode on {local_ip}:{port}")
        return pasv_sock