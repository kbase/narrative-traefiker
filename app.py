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
       "log_name": u"traefiker",
       "rancher_user": None,
       "rancher_password": None,
       "rancher_url": None,
       "rancher_meta": "http://rancher-metadata/",
       "rancher_env_url": None,
       "rancher_stack_id": None,
       "mode": "docker"}


for cfg_item in cfg.keys():
    if cfg_item in os.environ:
        cfg[cfg_item] = os.environ[cfg_item]
client = docker.DockerClient(base_url=cfg['docker_url'])

app = flask.Flask(__name__)

logging.basicConfig(stream=sys.stdout, format="%(message)s", level=int(cfg['log_level']))
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
logger = wrap_logger(logging.getLogger(cfg['log_name']),
                     processors=[filter_by_level, add_logger_name, add_log_level, JSONRenderer(indent=1, sort_keys=True)])


# Put all error strings in 1 place for ease of maintenance and to do comparisons for
# error handling
errors = {'no_cookie': "No {} cookie in request".format(cfg['kbase_cookie']),
          'auth_error': "Session cookie failed validation at {}: ".format(cfg['auth2']),
          'request_error': "Error querying {}: ".format(cfg['auth2'])}


# Seed the random number generator based on default (time)
random.seed()


def setup_app(app):

    # Verify that either docker or rancher configs are viable before continuing. It is a fatal error if the
    # configs aren't good, so bail out entirely and don't start the app
    try:
        if (cfg["rancher_url"] is not None):
            cfg['mode'] = "rancher"
            verify_rancher_config()
        else:
            cfg['mode'] = "docker"  # That is the defaault, but somewhat safer to set it explicitly
            verify_docker_config()
    except Exception as ex:
        logger.critical("Failed validation of docker or rancher configuration")
        raise(ex)
    logger.info(message="container management mode set to: {}".format(cfg['mode']))


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


def check_session_docker(userid):
    """
    Check to see if we already have a container for this user by trying to pull the container object
    for the userid
    """
    try:
        name = cfg['container_name'].format(userid)
        container = client.containers.get(name)
        session_id = container.labels['session_id']
    except docker.errors.NotFound:
        session_id = None
    except docker.errors.APIErrors as err:
        msg = "Docker APIError thrown while searching for container name {} : {}".format(name, str(err))
        logger.error(message=msg, name=name, exception=str(err))
        session_id = None
    return(session_id)


def check_session_rancher(userid):
    """
    Check to see if we already have a container for this user by trying to pull the container object
    for the userid
    """
    try:
        name = cfg['container_name'].format(userid)
        url = "{}/service?name={}".format(cfg["rancher_env_url"], name)
        r = requests.get(url, auth=(cfg["rancher_user"], cfg["rancher_password"]))
        if not r.ok:
            msg = "Error response code from rancher API while searching for container name {} : {}".format(name, r.status_code)
            logger.error(message=msg, status_code=r.status_code, name=name, response_body=r.text)
            raise(Exception(msg))
        res = r.json()
        svcs = res['data']
        if len(svcs) == 0:
            logger.debug(message="No previous session found", name=name, userid=userid)
            session_id = None
        else:
            session_id = svcs[0]['launchConfig']['labels']['session_id']
            logger.debug(message="Found existing session", session_id=session_id, userid=userid)
            if len(svcs) > 1:
                uuids = [svc['uuid'] for svc in svcs]
                logger.warning(message="Found multiple session matches against container name", userid=userid,
                               name=name, rancher_uuids=uuids)
    except Exception as ex:
        logger.debug(message="Error trying to find existing session", exception=format(str(ex)), userid=userid)
        raise(ex)
    return(session_id)


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
        logger.info(message="new_container", image=cfg['image'], userid=userid, name=name,
                    session_id=session, client_ip=request.remote_addr)
    except docker.errors.APIError as err:
        # If there is a race condition because a container has already started, then this should catch it.
        # Try to get the session for it, if that fails then bail with error message
        session = check_session_docker(userid)
        if session is None:
            raise(err)
        else:
            logger.info(message="previous_session", userid=userid, name=name, session_id=session, client_ip=request.remote_addr)
            container = client.get_container(name)
    if container.status != u"created":
        raise(Exception("Error starting container: container status {}".format(container.status)))
    return(session)


def start_rancher(session, userid, request):
    """
    Attempts to start a new container using the rancher API. Signature is identical to the start_docker
    method, with the equivalent rancher exceptions.
    """
    # Crazy long config needed for rancher container startup. Based on observing the traffic from rancher
    # GUI to rancher REST APIs. Might be able to prune it down with some re
    container_config = {u'assignServiceIpAddress': False,
                        u'createIndex': None,
                        u'created': None,
                        u'description': None,
                        u'externalId': None,
                        u'fqdn': None,
                        u'healthState': None,
                        u'kind': None,
                        u'launchConfig':   {
                            u'blkioWeight': None,
                            u'capAdd': [],
                            u'capDrop': [],
                            u'cgroupParent': None,
                            u'count': None,
                            u'cpuCount': None,
                            u'cpuPercent': None,
                            u'cpuPeriod': None,
                            u'cpuQuota': None,
                            u'cpuRealtimePeriod': None,
                            u'cpuRealtimeRuntime': None,
                            u'cpuSet': None,
                            u'cpuSetMems': None,
                            u'cpuShares': None,
                            u'createIndex': None,
                            u'created': None,
                            u'dataVolumes': [],
                            u'dataVolumesFrom': [],
                            u'dataVolumesFromLaunchConfigs': [],
                            u'deploymentUnitUuid': None,
                            u'description': None,
                            u'devices': [],
                            u'diskQuota': None,
                            u'dns': [],
                            u'dnsSearch': [],
                            u'domainName': None,
                            u'drainTimeoutMs': 0,
                            u'environment': {
                                u'env1': u'val1',
                                u'env2': u'val2'},
                            u'externalId': None,
                            u'firstRunning': None,
                            u'healthInterval': None,
                            u'healthRetries': None,
                            u'healthState': None,
                            u'healthTimeout': None,
                            u'hostname': None,
                            u'imageUuid': u'docker:kbase/narrative:latest',
                            u'instanceTriggeredStop': u'stop',
                            u'ioMaximumBandwidth': None,
                            u'ioMaximumIOps': None,
                            u'ip': None,
                            u'ip6': None,
                            u'ipcMode': None,
                            u'isolation': None,
                            u'kernelMemory': None,
                            u'kind': u'container',
                            u'labels': {
                                u'io.rancher.container.pull_image': u'always',
                                u'session_id': None,
                                u'traefik.enable': u'True'},
                            u'logConfig': {u'config': {}, u'driver': u''},
                            u'memory': None,
                            u'memoryMb': None,
                            u'memoryReservation': None,
                            u'memorySwap': None,
                            u'memorySwappiness': None,
                            u'milliCpuReservation': None,
                            u'networkLaunchConfig': None,
                            u'networkMode': u'managed',
                            u'oomScoreAdj': None,
                            u'pidMode': None,
                            u'pidsLimit': None,
                            u'ports': [u'8888:8888/tcp'],
                            u'privileged': False,
                            u'publishAllPorts': False,
                            u'readOnly': False,
                            u'removed': None,
                            u'requestedIpAddress': None,
                            u'restartPolicy': {u'name': u'always'},
                            u'runInit': False,
                            u'secrets': [],
                            u'shmSize': None,
                            u'startCount': None,
                            u'startOnCreate': True,
                            u'stdinOpen': True,
                            u'stopSignal': None,
                            u'stopTimeout': None,
                            u'tty': True,
                            u'type': u'launchConfig',
                            u'user': None,
                            u'userdata': None,
                            u'usernsMode': None,
                            u'uts': None,
                            u'uuid': None,
                            u'vcpu': 1,
                            u'volumeDriver': None,
                            u'workingDir': None},
                        u'name': None,
                        u'removed': None,
                        u'scale': 1,
                        u'secondaryLaunchConfigs': [],
                        u'selectorContainer': None,
                        u'selectorLink': None,
                        u'stackId': None,
                        u'startOnCreate': True,
                        u'type': u'service',
                        u'uuid': None,
                        u'vip': None}
    name = cfg['container_name'].format(userid)
    cookie = u"{}={}".format(cfg['session_cookie'], session)
    labels = dict()
    labels["io.rancher.container.pull_image"] = u"always"
    labels["traefik.enable"] = u"True"
    labels["session_id"] = session
    rule = u"Host(\"{}\") && PathPrefix(\"{}\") && HeadersRegexp(\"Cookie\",\"{}\")"
    labels["traefik.http.routers." + userid + ".rule"] = rule.format(cfg['hostname'], cfg["base_url"], cookie)
    labels["traefik.http.routers." + userid + ".entrypoints"] = u"web"
    container_config['launchConfig']['labels'] = labels
    container_config['launchConfig']['name'] = name
    container_config['name'] = name
    container_config['stackId'] = cfg['rancher_stack_id']
    # Attempt to bring up a container, if there is an unrecoverable error, clear the session variable to flag
    # an error state, and overwrite the response with an error response
    try:
        r = requests.post(cfg["rancher_env_url"]+"/service", json=container_config, auth=(cfg["rancher_user"], cfg["rancher_password"]))
        logger.info(message="new_container", image=cfg['image'], userid=userid, name=name, session_id=session, client_ip="127.0.0.1")  # request.remote_addr)
        if not r.ok:
            msg = "Error - response code {} while creating new narrative rancher service: {}".format(r.status_code, r.text)
            logger.error(msg)
            raise(Exception(msg))
    except Exception as ex:
        # If there is a race condition because a container has already started, then this should catch it.
        # Try to get the session for it, if that fails then bail with error message
        # session = check_session(userid)
        # if session is None:
        #    raise(err)
        # else:
        #    logger.info(message="previous_session", userid=userid, name=name, session_id=session, client_ip=request.remote_addr)
        #    container = client.get_container(name)
        raise(ex)
    # if container.status != u"created":
    #    raise(Exception("Error starting container: container status {}".format(container.status)))
    return(session)


def find_stack():
    """
    Query the rancher-metadata service for the name of the stack we're running in, and then
    go to the rancher_url and walk down through the stacks in the rancher environments we
    have access to that find the the endpoint that matches the name
    """
    r = requests.get(cfg['rancher_meta']+"2016-07-29/self/stack/environment_name")
    env_name = r.text
    r = requests.get(cfg['rancher_meta']+"2016-07-29/self/stack/name")
    stack_name = r.text
    r = requests.get(cfg['rancher_url']+"projects", auth=(cfg['rancher_user'], cfg['rancher_password']))
    resp = r.json()
    x = [env['links']['self'] for env in resp['data'] if env['name'].lower() == env_name.lower()]
    env_endpoint = x[0]
    logger.info(message="Found environment endpoint: {}".format(env_endpoint))
    r = requests.get(env_endpoint+"/stacks", auth=(cfg['rancher_user'], cfg['rancher_password']))
    resp = r.json()
    x = [stack['id'] for stack in resp['data'] if stack['name'].lower() == stack_name.lower()]
    logger.info(message="Found stack id: {}".format(x[0]))
    return({"url": env_endpoint, "stack_id": x[0]})


def get_container(userid, request, narrative):
    """
    Given the request object and the username from validating the token, either find or spin up
    the narrative container that should handle this user's narrative session. Return a flask response
    object that contains the necessary cookie for traefik to use for routing, as well as a brief
    message that reloads the page so that traefik reroutes to the right place
    """
    # See if there is an existing session for this user, if so, reuse it
    session = check_session_rancher(userid)
    resp = flask.Response(status=200)
    if session is None:
        logger.debug(message="new_session", userid=userid, client_ip=request.remote_addr)
        resp.set_data(reload_msg(narrative, cfg['reload_secs']))
        session = base64.b64encode(random.getrandbits(128).to_bytes(16, "big")).decode()
        try:
            # Try to start the container, session may be updated due to circumstances
            session = start_rancher(session, userid, request)
        except Exception as err:
            logger.critical(message="start_container_exception", userid=userid, client_ip=request.remote_addr,
                            exception=repr(err))
            resp.set_data(container_err_msg(repr(err)))
            resp.status = 500
            session = None
    else:
        # Session already exists, don't pause before reloading
        resp.set_data(reload_msg(narrative, 0))
    if session is not None:
        cookie = "{}={}".format(cfg['session_cookie'], session)
        logger.debug(message="session_cookie", userid=userid, client_ip=request.remote_addr, cookie=cookie)
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
    logger.info(message="auth_error", client_ip=request.remote_addr, error=auth_status['error'],
                detail=auth_status.get('message', ""))
    return(resp)


def verify_rancher_config():
    """
    Check that we can access the rancher api, then make sure that the endpoints for the environment and the stack_id are good.
    If we have the rancher_url endpoint, but nothing else, try to figure it out using the rancher-metadata endpoint
    """
    if (cfg['rancher_url'] is None):
        logger.critical("rancher_url is not set, cannot operate in rancher mode")
        raise(ValueError("rancher_url configuration not set"))
    if (cfg['rancher_user'] is None) or (cfg['rancher_password'] is None):
        logger.warning("rancher_user and/or rancher_password not set")
    try:
        r = requests.get(cfg['rancher_url'], auth=(cfg['rancher_user'], cfg['rancher_password']))
        if (not r.ok):
            logger.critical("Error while contacting rancher_url with rancher_user and rancher_password: {}:{}".format(r.status_code, r.text))
            raise(ValueError("Cannot contact rancher service using provided configuration"))
    except Exception as ex:
        logger.critical("Error trying to connect to {}: {}".format(cfg['rancher_url'], str(ex)))
        raise(ex)
    if (cfg['rancher_stack_id'] is None or cfg['rancher_env_url'] is None):
        logger.info("rancher_stack_id or rancher_env_url not set - introspecting rancher-metadata service")
        try:
            info = find_stack()
            cfg['rancher_stack_id'] = info['stack_id']
            cfg['rancher_env_url'] = info['url']
            if cfg['rancher_stack_id'] is None or cfg['rancher_env_url'] is None:
                logger.critical("Failed to determine rancher_stack_id and/or rancher_env_url from metadata service")
                raise(ValueError("rancher_stack_id or rancher_env_url not set"))
        except Exception as ex:
            logger.critical("Could not query rancher_meta({}) service: {}".format(cfg['rancher_meta'], str(ex)))
            raise(ex)
    # Make sure we can query the rancher environment endpoint
    try:
        r = requests.get(cfg['rancher_env_url'], auth=(cfg['rancher_user'], cfg['rancher_password']))
        if (not r.ok):
            logger.critical("Error response from rancher_env_url {}:{}".format(r.status_code, r.text))
            raise(ValueError("Error from rancher environment endpoint"))
    except Exception as ex:
        logger.critical("Error trying to connect to {}: {}".format(cfg['rancher_env_url'], str(ex)))
        raise(ex)
    # Everything should be good at this point
    return


def verify_docker_config():
    """ Quickly test the docker socket, if it fails, rethrow the exception after some explanatory logging """
    try:
        client.containers.list()
    except Exception as ex:
        logger.critical("Error trying to list containers using {} as docker socket path.".format(cfg['docker_url']))
        raise(ex)


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


setup_app(app)

if __name__ == '__main__':

    app.run()
