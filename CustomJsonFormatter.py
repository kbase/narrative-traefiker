from pythonjsonlogger import jsonlogger
import os

class CustomJsonFormatter(jsonlogger.JsonFormatter):
    def add_fields(self, log_record, record, message_dict):
        super(CustomJsonFormatter, self).add_fields(log_record, record, message_dict)
        if not log_record.get('timestamp'):
            # this doesn't use record.created, so it is slightly off
            log_record['timestamp'] = log_record['asctime']
        if log_record.get('level'):
            log_record['level'] = log_record['level'].upper()
        else:
            log_record['level'] = record.levelname
        log_record['container'] = os.environ['HOSTNAME']
        log_record['type'] = os.environ.get('es_type',"gunicorn_log")
        del log_record['asctime']
