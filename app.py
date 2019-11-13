import flask
import requests
import docker
import base64
import os
import random
# import json
import logging
import structlog
from structlog import wrap_logger
from structlog.processors import JSONRenderer
from structlog.stdlib import filter_by_level, add_logger_name, add_log_level
import sys


# Setup default configuration values, overriden by values from os.environ later
cfg = {"docker_url": u"unix://var/run/docker.sock",
       "hostname": u"localhost",
       "auth2": u"https://ci.kbase.us/services/auth/api/V2/token",
       "image": u"kbase/narrative:latest",
       "session_cookie": u"narrative_session",
       "kbase_cookie": u"kbase_session",
       "base_url": u"/narrative/",
       "container_name": u"narrative-{}",
       "dock_net": u"narrative-traefiker_default",
       "reload_secs": 5,
       "log_level": logging.DEBUG,
       "log_dest": None,
       "log_name": u"traefiker"}

for cfg_item in cfg.keys():
    if cfg_item in os.environ:
        cfg[cfg_item] = os.environ[cfg_item]

client = docker.DockerClient(base_url=cfg['docker_url'])
app = flask.Flask(__name__)

logging.basicConfig(stream=sys.stdout, format="%(message)s", level=cfg['log_level'])
structlog.configure(
    processors=[
        structlog.stdlib.filter_by_level,
        structlog.stdlib.add_logger_name,
        structlog.stdlib.add_log_level,
        structlog.stdlib.PositionalArgumentsFormatter(),
        structlog.processors.StackInfoRenderer(),
        structlog.processors.format_exc_info,
        structlog.processors.UnicodeDecoder(),
        structlog.stdlib.render_to_log_kwargs,
    ],
    context_class=dict,
    logger_factory=structlog.stdlib.LoggerFactory(),
    wrapper_class=structlog.stdlib.BoundLogger,
    cache_logger_on_first_use=True,
)
log = wrap_logger(logging.getLogger(cfg['log_name']),
                  processors=[filter_by_level, add_logger_name, add_log_level, JSONRenderer(indent=1, sort_keys=True)])

# Put all error strings in 1 place for ease of maintenance and to do comparisons for
# error handling
errors = {'no_cookie': "No {} cookie in request".format(cfg['kbase_cookie']),
          'auth_error': "Session cookie failed validation at {}: ".format(cfg['auth2']),
          'request_error': "Error querying {}: ".format(cfg['auth2'])}


# Seed the random number generator based on default (time)
random.seed()


def reload_msg(narrative, wait=0):
    msg = """
<html>
<head>
<META HTTP-EQUIV="refresh" CONTENT="{};URL='/narrative/{}'">
</head>
<body>
Starting container - will reload shortly
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


def check_session(userid):
    """
    Check to see if we already have a container for this user by trying to pull the container object
    for the userid
    """
    try:
        container = client.containers.get(cfg['container_name'].format(userid))
    except docker.errors.NotFound:
        return(None)
    except docker.errors.APIErrors:
        return(None)  # This is stubbed out for now
    return(container.labels['session_id'])


def start_docker(session, userid, request):
    """
    Attempts to start a docker container. Takes the suggested session id and a username
    Returns the final session id ( in case there was a race condition and another session was already started).
    Will throw an exception if there was any issue starting the container other than the race condition we're
    already trying to handle
    """
    labels = dict()
    labels["traefik.enable"] = u"True"
    labels["session_id"] = session
    cookie = u"{}={}".format(cfg['session_cookie'], session)
    labels["traefik.http.routers." + userid + ".rule"] = u"Host(\"" + cfg['hostname'] + u"\") && PathPrefix(\""+cfg["base_url"]+u"\")"
    labels["traefik.http.routers." + userid + ".rule"] += u" && HeadersRegexp(\"Cookie\",\"" + cookie + u"\")"
    labels["traefik.http.routers." + userid + ".entrypoints"] = u"web"
    # Attempt to bring up a container, if there is an unrecoverable error, clear the session variable to flag
    # an error state, and overwrite the response with an error response
    try:
        name = cfg['container_name'].format(userid)
        container = client.containers.run(cfg['image'], detach=True, labels=labels, hostname=name,
                                          auto_remove=True, name=name, network=cfg["dock_net"])
        log.info(message="new_container", image=cfg['image'], userid=userid, name=name,
                 session_id=session, client_ip=request.remote_addr)
    except docker.errors.APIError as err:
        # If there is a race condition because a container has already started, then this should catch it.
        # Try to get the session for it, if that fails then bail with error message
        session = check_session(userid)
        if session is None:
            raise(err)
        else:
            log.info(message="previous_session", userid=userid, name=name, session_id=session, client_ip=request.remote_addr)
            container = client.get_container(name)
    if container.status != u"created":
        raise(Exception("Error starting container: container status {}".format(container.status)))
    return(session)


def get_container(userid, request, narrative):
    """
    Given the request object and the username from validating the token, either find or spin up
    the narrative container that should handle this user's narrative session. Return a flask response
    object that contains the necessary cookie for traefik to use for routing, as well as a brief
    message that reloads the page so that traefik reroutes to the right place
    """
    # See if there is an existing session for this user, if so, reuse it
    session = check_session(userid)
    resp = flask.Response(status=200)
    if session is None:
        log.debug(message="new_session", userid=userid, client_ip=request.remote_addr)
        resp.set_data(reload_msg(narrative, cfg['reload_secs']))
        session = base64.b64encode(random.getrandbits(128).to_bytes(16, "big")).decode()
        try:
            # Try to start the container, session may be updated due to circumstances
            session = start_docker(session, userid, request)
        except Exception as err:
            log.critical(message="start_container_exception", userid=userid, client_ip=request.remote_addr,
                         exception=repr(err))
            resp.set_data(container_err_msg(repr(err)))
            resp.status = 500
            session = None
    else:
        # Session already exists, don't pause before reloading
        resp.set_data(reload_msg(narrative, 0))
    if session is not None:
        cookie = "{}={}".format(cfg['session_cookie'], session)
        log.debug(message="session_cookie", userid=userid, client_ip=request.remote_addr, cookie=cookie)
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
    log.info(message="auth_error", client_ip=request.remote_addr, error=auth_status['error'],
             detail=auth_status.get('message', ""))
    return(resp)


def log_handler(dest):
    """
    Takes as input a string that is either a filename, or else socket specification of of the form
    "tcp:///host:port"
    An additional log handler will be created that directs log output to this destination
    """


@app.route(cfg['base_url'] + '<path:narrative>')
def hello(narrative):
    """
    Main handler for the auth service. Validate the request, get the container is should be routed
    to and return a response that will result in traefik routing to the right place for subsequent
    requests. Returns an error in the flask response if requirements are not met or if an error
    occurs
    """
    request = flask.request
    auth_status = valid_request(request)
    if 'userid' in auth_status:
        resp = get_container(auth_status['userid'], request, narrative)
    else:
        resp = error_response(auth_status, request)
    return resp


if __name__ == '__main__':

    app.run()
