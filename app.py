import flask
import requests
from urllib.parse import quote_plus
import os
import random
import logging
from pythonjsonlogger import jsonlogger
import sys
import time
import signal
import re
from datetime import datetime
import json
import manage_docker
import manage_rancher
from apscheduler.schedulers.background import BackgroundScheduler
from typing import Dict, List, Optional
from types import FrameType

# Setup default configuration values, overriden by values from os.environ later
cfg = {"docker_url": u"unix://var/run/docker.sock",    # path to docker socket
       "hostname": u"localhost",                       # hostname used for traefik router rules
       "auth2": u"https://ci.kbase.us/services/auth/api/V2/token",  # url for authenticating tokens
       "image": u"kbase/narrative:latest",             # image name used for spawning narratives
       "es_type": "narrative-traefiker",               # value for type field used in logstash json ingest
       "session_cookie": u"narrative_session",         # name of cookie used for storing session id
       "kbase_cookie": u"kbase_session",               # name of the cookie container kbase auth token
       "container_name": u"narrative-{}",              # python string template for narrative name, userid in param
       "container_name_prespawn": u"narrativepre-{}",  # python string template for pre-spawned narratives, userid in param
       "narrative_version_url": "https://ci.kbase.us/narrative_version",  # url to narrative_version endpoint
       "narr_img": "kbase/narrative",                  # string used to match images of services/containers for reaping
       "container_prefix": "narrative",                # string used to match names of services/containers for reaping
       "traefik_metrics": "http://traefik:8080/metrics",  # URL of traefik metrics endpoint, api + prometheus must be enabled
       "dock_net": u"narrative-traefiker_default",     # name of the docker network that docker containers should be bound to
       "reload_secs": 10,                              # how many seconds the client should wait before reloading when no prespawned available
       "log_level": logging.DEBUG,                     # loglevel
       "log_dest": None,                               # log destination - currently unused
       "log_name": u"traefiker",                       # python logger name
       "rancher_user": None,                           # username for rancher creds
       "rancher_password": None,                       # password for rancher creds
       "rancher_url": None,                            # URL for the rancher API endpoint, including version
       "rancher_meta": "http://rancher-metadata/",     # URL for the rancher-metadata service (unauthenticated)
       "rancher_env_url": None,                        # rancher enviroment URL (under rancher_url) - self-configured if not set
       "rancher_stack_id": None,                       # rancher stack ID value, used with rancher_env_url - self-configured if not set
       "mode": None,                                   # What orchestation type? "rancher" or "docker"
       "reaper_timeout_secs": 600,                     # How long should a container be idle before it gets reaped?
       "reaper_sleep_secs": 30,                        # How long should the reaper process sleep in between runs?
       "debug": 0,                                     # Set debug mode
       "narrenv": dict(),                              # Dictionary of env name/val to be passed to narratives at startup
       "num_prespawn": 5,                              # How many prespawned narratives should be maintained? Checked at startup and reapee runs
       "status_users": ["sychan", "kkeller", "jsfillman", "scanon", "bsadhkin"]}  # What users get full status from narrative_status?

# Put all error strings in 1 place for ease of maintenance and to do comparisons for
# error handling
errors: Optional[Dict[str, str]] = None

# Set a global logger instance
logger: logging.Logger = logging.getLogger()

app: flask.Flask = flask.Flask(__name__)

scheduler: BackgroundScheduler = BackgroundScheduler()

narr_activity: Dict[str, time.time] = dict()

narr_last_version = None


def narr_status(signalNumber: int, frame: FrameType) -> None:
    print("Current time: {}".format(time.asctime()))
    for container in narr_activity.keys():
        print("  {} last activity at {}".format(container, time.asctime(time.localtime(narr_activity[container]))))


def setup_app(app: flask.Flask) -> None:
    global errors
    errors = {'no_cookie': "No {} cookie in request".format(cfg['kbase_cookie']),
              'auth_error': "Session cookie failed validation at {}: ".format(cfg['auth2']),
              'request_error': "Error querying {}: ".format(cfg['auth2'])}

    # Seed the random number generator based on default (time)
    random.seed()

    for cfg_item in cfg.keys():
        if cfg_item in os.environ:
            logger.info({"message": "Setting config from environment",
                         "key": cfg_item, "value": os.environ[cfg_item]})
            if isinstance(cfg[cfg_item], int):
                cfg[cfg_item] = int(os.environ[cfg_item])
            elif isinstance(cfg[cfg_item], float):
                cfg[cfg_item] = float(os.environ[cfg_item])
            else:
                cfg[cfg_item] = os.environ[cfg_item]
    # To support injecting arbitrary environment variables into the narrative container, we
    # look for any environment variable with the prefix "NARRENV_" and add it into a narrenv
    # dictionary in the the config hash, using the env variable name stripped of "NARRENV_"
    # prefix as the key
    for k in os.environ.keys():
        match = re.match(r"^NARRENV_(\w+)", k)
        if match:
            cfg['narrenv'][match.group(1)] = os.environ[k]
            logger.info({"message": "Setting narrenv from environment",
                         "key": match.group(1), "value": os.environ[k]})

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
    logger.info({"message": "Starting scheduler", "reaper_timeout_sec": cfg['reaper_timeout_secs'],
                 "reaper_sleep_secs": cfg['reaper_sleep_secs']})
    scheduler.start()
    scheduler.add_job(reaper, 'interval', seconds=cfg['reaper_sleep_secs'], id='reaper')
    signal.signal(signal.SIGUSR1, narr_status)
    # the pre-spawning feature is only supported on rancher, if we prespawn is
    # set for a number higher than 0, prespawn that number of narratives
    if cfg.get("num_prespawn", 0) > 0 and cfg['mode'] == "rancher":
        prespawn_narrative(cfg['num_prespawn'])


def get_prespawned() -> List[str]:
    """ returns a list of the prespawned narratives waiting to be assigned """
    if cfg["mode"] != "rancher":
        raise(NotImplementedError("prespawning only supports rancher mode, current mode={}".format(cfg['mode'])))
    narratives = manage_rancher.find_narratives()
    idle_narr = [narr for narr in narratives if cfg['container_name_prespawn'].format("") in narr]
    return(idle_narr)


def prespawn_narrative(num: int) -> None:
    """ Prespawn num narratives that incoming users can be assigned to immediately """
    logger.info({"message": "prespawning containers", "number": num})
    if cfg['mode'] != "rancher":
        raise(NotImplementedError("prespawning only supports rancher mode, current mode={}".format(cfg['mode'])))
    prespawned = get_prespawned()
    num -= len(prespawned)
    logger.info({"message": "found {} already waiting narratives".format(len(prespawned))})
    if num > 0:
        for a in range(num):
            session = random.getrandbits(128).to_bytes(16, "big").hex()
            narr_id = session[0:6]
            try:
                manage_rancher.start(session, narr_id, True)
            except Exception as err:
                logger.critical({"message": "prespawn_narrative_exception", "session": session,
                                "container": "{} of {}".format(a, num), "exception": repr(err)})


def reload_msg(narrative: str, wait: int = 0) -> str:
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


def container_err_msg(message: str) -> str:
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


def valid_request(request: Dict[str, str]) -> str:
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


def get_container(userid: str, request: flask.Request, narrative: str) -> flask.Response:
    """
    Given the request object and the username from validating the token, either find or spin up
    the narrative container that should handle this user's narrative session. The narrative
    parameter is the path to the requested narrative from the original URL. Return a flask response
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
        logger.debug({"message": "new_session", "userid": userid, "client_ip": request.headers.get("X-Forwarded-For", None)})
        resp.set_data(reload_msg(narrative, cfg['reload_secs']))
        session = random.getrandbits(128).to_bytes(16, "big").hex()
        try:
            # Try to get a narrative session, the session value returned is the one that has been assigned to the
            # userid. The second value is whether or not the session is to a prespawned container, no wait is necessary
            response = start(session, userid)
            session = response['session']
            if "prespawned" in response:
                resp.set_data(reload_msg(narrative, 0))
        except Exception as err:
            logger.critical({"message": "start_container_exception", "userid": userid, "client_ip": request.headers.get("X-Forwarded-For", None),
                            "exception": repr(err)})
            resp.set_data(container_err_msg(repr(err)))
            resp.status = 500
            session = None
    else:
        # Session already exists, don't pause before reloading
        resp.set_data(reload_msg(narrative, 0))
    if session is not None:
        cookie = "{}={}".format(cfg['session_cookie'], session)
        logger.debug({"message": "session_cookie", "userid": userid, "client_ip": request.headers.get("X-Forwarded-For", None), "cookie": cookie})
        resp.set_cookie(cfg['session_cookie'], session)
    return(resp)


def error_response(auth_status: Dict[str, str], request: flask.request) -> flask.Response:
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
    logger.info({"message": "auth_error", "client_ip": request.headers.get("X-Forwarded-For", None), "error": auth_status['error'],
                "detail": auth_status.get('message', "")})
    return(resp)


def get_active_traefik_svcs() -> Dict[str, time.time]:
    """
    Looks through the traefik metrics endpoint results to find active websockets for narratives, and returns
    a dictionary identical in structure to the global narr_activity, which can be used to update() narr_activity
    """
    if cfg['mode'] == 'docker':
        find_image = manage_docker.find_image
    elif cfg['mode'] == 'rancher':
        find_image = manage_rancher.find_image
    else:
        raise RuntimeError('Unknown orchestration mode: {}'.format(cfg['mode']))
    try:
        r = requests.get(cfg['traefik_metrics'])
        if r.status_code == 200:
            body = r.text.split("\n")
            # Find all counters related to websockets - jupyter notebooks rely on websockets for communications
            service_conn = [line for line in body if "traefik_service_open_connections{" in line]
            service_websocket_open = [line for line in service_conn if "protocol=\"websocket\"" in line]
            # Containers is a dictionary keyed on container name with the value as the # of active web sockets
            containers = dict()
            for line in service_websocket_open:
                logger.debug({"message": "websocket line: {}".format(line)})
                matches = re.search(r"service=\"(\S+)@.+ (\d+)", line)
                containers[matches.group(1)] = int(matches.group(2))
            logger.debug({"message": "Looking for containers that with name prefix {} and image name {}".format(cfg['container_prefix'], cfg['narr_img'])})
            for name in containers.keys():
                logger.debug({"message": "Examing container: {}".format(name)})
                # Skip any containers that don't match the container prefix, to avoid wasting time on the wrong containers
                if name.startswith(cfg['container_prefix']):
                    logger.debug({"message": "Matches prefix"})
                    image_name = find_image(name)
                    # Filter out any container that isn't the image type we are reaping
                    if (cfg['narr_img'] in image_name):
                        logger.debug({"message": "Matches image name"})
                        # only update timestamp if the container has active websockets or this is the first
                        # time we've seen it.
                        if (containers[name] > 0) or (name not in narr_activity):
                            narr_activity[name] = time.time()
                            logger.debug({"message": "Updated timestamp for "+name})
                    else:
                        logger.debug({"message": "Skipping because {} not in {}".format(cfg['narr_img'], image_name)})
                else:
                    logger.debug({"message": "Skipped {} because it didn't match prefix {}".format(name, cfg['container_prefix'])})
            return(narr_activity)
        else:
            raise(Exception("Error querying {}:{} {}".format(cfg['traefik_metrics'], r.status_code, r.text)))
    except Exception as e:
        exc_type, exc_obj, tb = sys.exc_info()
        f = tb.tb_frame
        lineno = tb.tb_lineno
        filename = f.f_code.co_filename
        logger.critical({"message": "ERROR: {}".format(repr(e)), "file": filename, "line num": lineno})
        raise(e)


def versiontuple(v: str) -> tuple:
    """
    Function to converts a version string into a tuple that can be compared, copied from
    https://stackoverflow.com/questions/11887762/how-do-i-compare-version-numbers-in-python/21065570
    """
    return tuple(map(int, (v.split("."))))


def latest_narr_version() -> str:
    """
    Queries cfg['narrative_revsion'] and returns the version string. Throws exception if there is a problem.
    """
    try:
        r = requests.get(cfg['narrative_version_url'])
        resp = r.json()
        if r.status_code == 200:
            version = resp['version']
        else:
            raise(Exception("Error querying {} for version: {} {}".format(cfg['narrative_version_url'],
                            r.status_code, r.text)))
    except Exception as err:
        raise(err)
    return(version)


def reap_older_prespawn(version: str) -> None:
    """
    Reaps prespawned narratives that are older than the version string passed in
    """
    try:
        logger.info({"message": "Reaping narratives older than {}".format(version)})
        if cfg['mode'] == "rancher":
            find_narratives = manage_rancher.find_narratives
            find_narrative_labels = manage_rancher.find_narrative_labels
            reap_narrative = manage_rancher.reap_narrative
        else:
            find_narratives = manage_docker.find_narratives
            find_narrative_labels = manage_docker.find_narrative_labels
            reap_narrative = manage_docker.reap_narrative
        narr_names = find_narratives()
        narr_labels = find_narrative_labels(narr_names)
        ver = versiontuple(version)
        for narr in narr_labels.keys():
            narr_str = narr_labels[narr]['us.kbase.narrative-version']
            narr_ver = versiontuple(narr_str)
            if narr_ver != ver:
                logger.info({"message": "Reaping obsolete prespawned narrative", "narrative": narr,
                             "version": narr_str})
                reap_narrative(narr)
    except Exception as ex:
        raise(ex)


def reaper() -> None:
    """
    Reaper function, intended to be called at regular intervals specified by cfg['reaper_sleep_secs'].
    Updates last seen timestamps for narratives, reaps any that have been idle for longer than cfg['reaper_timeout_secs']
    """
    global narr_last_version
    global narr_activity
    logger.info({"message": "Reaper process running"})
    if cfg['mode'] == 'docker':
        reap_narrative = manage_docker.reap_narrative
    elif cfg['mode'] == 'rancher':
        reap_narrative = manage_rancher.reap_narrative
    else:
        raise RuntimeError('Unknown orchestration mode: {}'.format(cfg['mode']))
    try:
        newtimestamps = get_active_traefik_svcs()
        narr_activity.update(newtimestamps)
    except Exception as e:
        logger.critical({"message": "ERROR: {}".format(repr(e))})
        return
    now = time.time()
    reap_list = [name for name, timestamp in narr_activity.items() if (now - timestamp) > cfg['reaper_timeout_secs']]

    for name in reap_list:
        msg = "Container {} has been inactive longer than {}. Reaping.".format(name, cfg['reaper_timeout_secs'])
        logger.info({"message": msg})
        try:
            reap_narrative(name)
            del narr_activity[name]
        except Exception as e:
            logger.critical({"message": "Error: Unhandled exception while trying to reap container {}: {}".format(name, repr(e))})
    # Try the narrative_version endpoint to see if we need to update the prespawned
    # narratives
    latest_version = None
    try:
        latest_version = latest_narr_version()
    except Exception as ex:
        logger.info({"message": "Error while querying narrative_version_url {}".format(repr(ex))})
    if latest_version is not None:
        try:
            if narr_last_version is None:
                narr_last_version = latest_version
                logger.info({"message": "narr_last_version set", "version": narr_last_version})
            elif versiontuple(latest_version) > versiontuple(narr_last_version):
                narr_last_version = latest_version
                logger.info({"message": "narr_last_version set", "version": narr_last_version})
                reap_older_prespawn(latest_version)
        except Exception as ex:
            logger.critical({"message": "Error while checking prespawned narrative versions {}".format(repr(ex))})

    # Now make sure the narrative prespawn spool is at the desired level
    if cfg.get("num_prespawn", 0) > 0 and cfg['mode'] == "rancher":
        prespawn_narrative(cfg['num_prespawn'])


@app.route("/narrative_shutdown/", methods=['DELETE'])
@app.route("/narrative_shutdown/<path:username>", methods=['DELETE'])
def narrative_shutdown(username=None):
    """
    This handler takes request, and looks for an auth token, if both are present it
    looks for and sessions associated with that userid and calls the
    rancher API to delete that service. Returns a 401 error if there isn't an auth token, if
    there is an auth token then try to delete all of the sessions that are associated with that
    userid
    """
    request = flask.request
    auth_status = valid_request(request)
    logger.info({"message": "narrative_shutdown called", "auth_status": str(auth_status)})
    if 'userid' in auth_status:
        userid = auth_status['userid']
        if cfg['mode'] == "rancher":
            check_session = manage_rancher.check_session
            reap_narrative = manage_rancher.reap_narrative
            naming_regex = "^{}_"
        else:
            check_session = manage_docker.check_session
            reap_narrative = manage_docker.reap_narrative
            naming_regex = "^{}$"
        session_id = check_session(userid)
        logger.debug({"message": "narrative_shutdown session {}".format(session_id)})

        if session_id is None:
            resp = flask.Response('No sessions found for user', 404)
        else:
            try:
                name = cfg['container_name'].format(userid)
                logger.debug({"message": "narrative_shutdown reaping", "session_id": session_id})
                reap_narrative(name)
                # Try to clear the narrative out of the narr_activity dict, by matching the container
                # name as the priagainst what Traefik would call
                name_match = naming_regex.format(name)
                for narr_name in narr_activity.keys():
                    if re.match(name_match, narr_name):
                        del narr_activity[narr_name]
                        break
                resp = flask.Response("Service {} deleted".format(name), 200)
            except Exception as e:
                logger.critical({"message": "Error: Unhandled exception while trying to reap container {}: {}".format(name, repr(e))})
                resp = flask.Response("Error deleteing service {}: {}".format(name, repr(e)), 200)
    else:
        resp = flask.Response('Valid kbase authentication token required', 401)
    return resp


@app.route("/narrative_status/", methods=['GET'])
def narrative_status():
    """
    Simple status endpoint to re-assure us that the service is alive. Unauthenticated access just returns
    a 200 code with the current time in JSON string. If a kbase auth cookie is found, and the username is in the
    list of ID's in cfg['status_users'] then a dump of the current narratives running and their last
    active time from narr_activity is returned in JSON form, ready to be consumed by a metrics service
    """
    global narr_activity
    logger.info({"message": "Status query recieved"})
    resp_doc = {"timestamp": datetime.now().isoformat()}
    request = flask.request
    auth_status = valid_request(request)
    logger.debug({"message": "Status query recieved", "auth_status": auth_status})
    if 'userid' in auth_status:
        if auth_status['userid'] in cfg['status_users']:
            resp_doc['reaper_status'] = narr_activity
            if cfg['mode'] == "rancher":
                find_narratives = manage_rancher.find_narratives
                find_service = manage_rancher.find_service  # ToDo: This call doesn't exist yet!
            else:
                find_narratives = manage_docker.find_narratives
                find_service = manage_docker.find_service
            narr_names = find_narratives()
            narr_services = {name: find_service(name) for name in narr_names}
            resp_doc['narrative_services'] = narr_services
        else:
            logger.debug({"message": "User not in status_users", "status_users": cfg['status_users']})
    return(flask.Response(json.dumps(resp_doc), 200, mimetype='application/json'))


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
    if 'userid' in auth_status:
        resp = get_container(auth_status['userid'], request, narrative)
    else:
        if auth_status['error'] == "no_cookie":
            next_request = '{{"path":"{}","external":true}}'.format(request.full_path)
            logger.debug({"message": "Redirecting user for no_cookie", "nextrequest": request.url})
            resp = flask.redirect("/#login?nextrequest={}".format(quote_plus(next_request)))
        else:
            resp = error_response(auth_status, request)
    return resp


if __name__ == '__main__':

    setup_app(app)
    if cfg['mode'] is not None:
        app.run()
    else:
        logger.critical({"message": "No container management configuration. Please set docker_url or rancher_* environment variable appropriately"})
        raise RuntimeError("Cannot start/check containers.")
