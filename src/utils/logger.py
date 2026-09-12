import logging
import logging.config
import coloredlogs

# Definiamo un formato pulito con larghezze fisse per un allineamento perfetto a colonna
# Es: 2026-09-12 15:30:00 | INFO     | fake_ftp_tarpit | Received from...
FORMAT_STRING = '%(asctime)s | %(levelname)-8s | %(module)-20s | %(message)s'

LOGGING_CONFIG = {
    'version': 1,
    'disable_existing_loggers': False,
    'formatters': {
        'file_format': {
            'format': FORMAT_STRING,
            'datefmt': '%Y-%m-%d %H:%M:%S',
        },
    },
    'handlers': {
        'file': {
            # Utilizziamo la rotazione: evita che un attacco DoS saturi il disco con i log
            'class': 'logging.handlers.RotatingFileHandler', 
            'filename': './app.log',
            'maxBytes': 10485760, # 10 MB per file
            'backupCount': 5,     # Conserva gli ultimi 5 file (totale 50 MB)
            'formatter': 'file_format',
            'level': 'INFO',
        },
    },
    'loggers': {
        'Mantis': {
            'handlers': ['file'], # Il gestore console è delegato a coloredlogs
            'level': 'INFO',
            'propagate': False,
        }
    }
}

# Applica la configurazione per il file
logging.config.dictConfig(LOGGING_CONFIG)
logger = logging.getLogger("Mantis")

# Configura coloredlogs esclusivamente per un output su console elegante e leggibile
coloredlogs.install(
    level='INFO',
    logger=logger,
    fmt=FORMAT_STRING,
    datefmt='%Y-%m-%d %H:%M:%S',
    field_styles={
        'asctime': {'color': 'green'},
        'levelname': {'bold': True, 'color': 'black'},
        'module': {'color': 'cyan'}
    },
    level_styles={
        'debug': {'color': 'black', 'bright': True},
        'info': {'color': 'white'},
        'warning': {'color': 'yellow'},
        'error': {'color': 'red'},
        'critical': {'bold': True, 'color': 'red'}
    }
)