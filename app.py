import flask
import requests
import os
import random
import logging
from pythonjsonlogger import jsonlogger
import sys
from datetime import datetime
import manage_docker
import manage_rancher
from werkzeug.debug import DebuggedApplication


# Setup default configuration values, overriden by values from os.environ later
cfg = {"docker_url": u"unix://var/run/docker.sock",
       "hostname": u"localhost",
       "auth2": u"https://ci.kbase.us/services/auth/api/V2/token",
       "image": u"kbase/narrative:latest",
       "es_type": "narrative-traefiker",
       "session_cookie": u"narrative_session",
       "kbase_cookie": u"kbase_session",
       "container_name": u"narrative-{}",
       "dock_net": u"narrative-traefiker_default",
       "reload_secs": 10,
       "log_level": logging.DEBUG,
       "log_dest": None,
       "log_name": u"traefiker",
       "rancher_user": None,
       "rancher_password": None,
       "rancher_url": None,
       "rancher_meta": "http://rancher-metadata/",
       "rancher_env_url": None,
       "rancher_stack_id": None,
       "mode": None}

# Put all error strings in 1 place for ease of maintenance and to do comparisons for
# error handling
errors = None

# Set a global logger instance
logger = logging.getLogger()

app = flask.Flask(__name__)


def setup_app(app):
    global errors
    errors = {'no_cookie': "No {} cookie in request".format(cfg['kbase_cookie']),
              'auth_error': "Session cookie failed validation at {}: ".format(cfg['auth2']),
              'request_error': "Error querying {}: ".format(cfg['auth2'])}

    #  ToDo: Comment this out before going to prod
    if app.debug:
        app.wsgi_app = DebuggedApplication(app.wsgi_app, evalex=True)

    # Seed the random number generator based on default (time)
    random.seed()

    for cfg_item in cfg.keys():
        if cfg_item in os.environ:
            cfg[cfg_item] = os.environ[cfg_item]

    # Configure logging
    class CustomJsonFormatter(jsonlogger.JsonFormatter):
        def add_fields(self, log_record, record, message_dict):
            super(CustomJsonFormatter, self).add_fields(log_record, record, message_dict)
            if not log_record.get('timestamp'):
                # this doesn't use record.created, so it is slightly off
                now = datetime.utcnow().strftime('%Y-%m-%dT%H:%M:%S.%fZ')
                log_record['timestamp'] = now
            if log_record.get('level'):
                log_record['level'] = log_record['level'].upper()
            else:
                log_record['level'] = record.levelname
            log_record['container'] = os.environ['HOSTNAME']
            log_record['type'] = cfg['es_type']

    logging.basicConfig(stream=sys.stdout, level=int(cfg['log_level']))
    logHandler = logging.StreamHandler()
    formatter = CustomJsonFormatter('(timestamp) (level) (name) (message) (container) (type)')
    logHandler.setFormatter(formatter)
    logger.addHandler(logHandler)

    # Remove the default flask logger in favor of the one we just configured
    logger.removeHandler(flask.logging.default_handler)

    logging.getLogger("urllib3").setLevel(logging.CRITICAL)

    # Verify that either docker or rancher configs are viable before continuing. It is a fatal error if the
    # configs aren't good, so bail out entirely and don't start the app
    try:
        if (cfg["rancher_url"] is not None):
            cfg['mode'] = "rancher"
            manage_rancher.setup(cfg, logger)
            manage_rancher.verify_config(cfg)
        else:
            cfg['mode'] = "docker"
            manage_docker.setup(cfg, logger)
            manage_docker.verify_config(cfg)
    except Exception as ex:
        logger.critical("Failed validation of docker or rancher configuration")
        raise(ex)
    logger.info({'message': "container management mode set to: {}".format(cfg['mode'])})


def reload_msg(narrative, wait=0):
    msg = """
<html>
<head>
<META HTTP-EQUIV="refresh" CONTENT="{};URL='/narrative/{}'">
</head>
<body>
Starting narrative - will reload shortly
</body>
</html>
"""
    return msg.format(wait, narrative)


def container_err_msg(message):
    msg = """
<html>
<head>
</head>
<body>
There was an error starting your narrative: {}
please contact KBase support staff.
</body>
</html>
"""
    return msg.format(message)


def valid_request(request):
    """
    Validate request has a legit auth token and return a dictionary that has a userid field if
    it is legit, otherwise return the error type in the error field
    """
    auth_status = dict()
    if cfg['kbase_cookie'] not in request.cookies:
        auth_status['error'] = 'no_cookie'
    else:
        token = request.cookies[cfg['kbase_cookie']]
        try:
            r = requests.get(cfg['auth2'], headers={'Authorization': token})
            authresponse = r.json()
            if r.status_code == 200:
                auth_status['userid'] = authresponse['user']
            else:
                auth_status['error'] = 'auth_error'
                auth_status['message'] = authresponse['error']['message']
        except Exception as err:
            auth_status['error'] = "request_error"
            auth_status['message'] = repr(err)
    return(auth_status)


def get_container(userid, request, narrative):
    """
    Given the request object and the username from validating the token, either find or spin up
    the narrative container that should handle this user's narrative session. Return a flask response
    object that contains the necessary cookie for traefik to use for routing, as well as a brief
    message that reloads the page so that traefik reroutes to the right place
    """
    # Set the check_session() and start() methods to point to the versions appropriate for
    # the mode we're in
    if cfg['mode'] == "rancher":
        check_session = manage_rancher.check_session
        start = manage_rancher.start
    else:
        check_session = manage_docker.check_session
        start = manage_docker.start

    # See if there is an existing session for this user, if so, reuse it
    session = check_session(userid)
    resp = flask.Response(status=200)
    if session is None:
        logger.debug({"message": "new_session", "userid": userid, "client_ip": request.remote_addr})
        resp.set_data(reload_msg(narrative, cfg['reload_secs']))
        session = random.getrandbits(128).to_bytes(16, "big").hex()
        try:
            session = start(session, userid, request)
        except Exception as err:
            logger.critical({"message": "start_container_exception", "userid": userid, "client_ip": request.remote_addr,
                            "exception": repr(err)})
            resp.set_data(container_err_msg(repr(err)))
            resp.status = 500
            session = None
    else:
        # Session already exists, don't pause before reloading
        resp.set_data(reload_msg(narrative, 0))
    if session is not None:
        cookie = "{}={}".format(cfg['session_cookie'], session)
        logger.debug({"message": "session_cookie", "userid": userid, "client_ip": request.remote_addr, "cookie": cookie})
        resp.set_cookie(cfg['session_cookie'], session)
    return(resp)


def error_response(auth_status, request):
    """
    Return an flask response that is appropriate for the message in the auth_status dict.
    """
    resp = flask.Response(errors[auth_status["error"]])
    if auth_status['error'] == 'no_cookie':
        resp = flask.Response(errors['no_cookie'])
        resp.status_code = 401
    if auth_status['error'] == 'auth_error':
        resp = flask.Response(errors['auth_error']+auth_status['message'])
        resp.status_code = 403
    if auth_status['error'] == 'request_error':
        resp = flask.Response(errors['request_error']+auth_status['message'])
        resp.status_code = 403
    logger.info({"message": "auth_error", "client_ip": request.remote_addr, "error": auth_status['error'],
                "detail": auth_status.get('message', "")})
    return(resp)


@app.route("/narrative/" + '<path:narrative>')
def hello(narrative):
    """
    Main handler for the auth service. Validate the request, get the container is should be routed
    to and return a response that will result in traefik routing to the right place for subsequent
    requests. Returns an error in the flask response if requirements are not met or if an error
    occurs
    """
    request = flask.request
    auth_status = valid_request(request)
    # raise
    if 'userid' in auth_status:
        resp = get_container(auth_status['userid'], request, narrative)
    else:
        resp = error_response(auth_status, request)
    return resp


setup_app(app)

if __name__ == '__main__':

    if cfg['mode'] is not None:
        app.run()
    else:
        logger.critical({"message": "No container management configuration. Please set docker_url or rancher_* environment variable appropriately"})
        raise RuntimeError("Cannot start/check containers.")
