import flask
import requests
from urllib.parse import quote_plus
import os
import random
import logging
import sys
import time
import re
from datetime import datetime
import json
import hashlib
import manage_docker
import manage_rancher
from typing import Dict, List, Optional
import ipaddress
import sqlite3

VERSION = "0.9.7"

# Setup default configuration values, overriden by values from os.environ later
cfg = {"docker_url": u"unix://var/run/docker.sock",    # path to docker socket
       "hostname": u"localhost",                       # hostname used for traefik router rules
       "auth2": u"https://ci.kbase.us/services/auth/api/V2/me",  # url for authenticating tokens
       "image": u"kbase/narrative:latest",             # image name used for spawning narratives
       "session_cookie": u"narrative_session",         # name of cookie used for storing session id
       "kbase_cookie": u"kbase_session",               # name of the cookie container kbase auth token
       "container_name": u"narrative-{}",              # python string template for narrative name, userid in param
       "container_name_prespawn": u"narrativepre-{}",  # python string template for pre-spawned narratives, userid in param
       "narrative_version_url": "https://ci.kbase.us/narrative_version",  # url to narrative_version endpoint
       "narr_img": "kbase/narrative",                  # string used to match images of services/containers for reaping
       "traefik_metrics": "http://traefik:8080/metrics",  # URL of traefik metrics endpoint, api + prometheus must be enabled
       "dock_net": u"narrative-traefiker_default",     # name of the docker network that docker containers should be bound to
       "log_level": logging.DEBUG,                     # loglevel - DEBUG=10, INFO=20, WARNING=30, ERROR=40, CRITICAL=50
       "log_dest": None,                               # log destination - currently unused
       "log_name": u"traefiker",                       # python logger name
       "rancher_user": None,                           # username for rancher creds
       "rancher_password": None,                       # password for rancher creds
       "rancher_url": None,                            # URL for the rancher API endpoint, including version
       "rancher_meta": "http://rancher-metadata/",     # URL for the rancher-metadata service (unauthenticated)
       "rancher_env_url": None,                        # rancher enviroment URL (under rancher_url) - self-configured if not set
       "rancher_stack_id": None,                       # rancher stack ID value, used with rancher_env_url - self-configured if not set
       "rancher_stack_name": None,                     # rancher stack name value, used with rancher_env_url - self-configured if not set, required if rancher_stack_id set
       "mode": None,                                   # What orchestation type? "rancher" or "docker"
       "reaper_timeout_secs": 600,                     # How long should a container be idle before it gets reaped?
       "reaper_ipnetwork": u"127.0.0.1/32",            # What IP address/network is allowed to access /reaper/ ?
       "debug": 0,                                     # Set debug mode
       "narrenv": dict(),                              # Dictionary of env name/val to be passed to narratives at startup
       "num_prespawn": 5,                              # How many prespawned narratives should be maintained? Checked at startup and reapee runs
       "status_role": "KBASE_ADMIN",                   # auth custom role for full narratve_status privs
       "sqlite_reaperdb_path": "/tmp/reaper.db",             # full path to SQLite3 database file
       "COMMIT_SHA": "not available"}                  # Git commit hash for this build, set via docker build env

# Put all error strings in 1 place for ease of maintenance and to do comparisons for
# error handling
errors: Optional[Dict[str, str]] = None

# Set a global logger instance
logger: logging.Logger = logging.getLogger()

app: flask.Flask = flask.Flask(__name__)

# The last version string seen for the narrative image
narr_last_version = None

# Dictionary with information about narratives currently running
narr_services: Dict[str, time.time] = dict()

# Consolidate method references to these globals until the class based rewrite is done
check_session = None
start = None
find_image = None
find_service = None
find_narratives = None
find_narrative_labels = None
reap_narrative = None
naming_regex = None
find_stopped_services = None
stack_suffix = None
 

def merge_env_cfg() -> None:
    """
    Go through the environment variables and and merge them into the global configuration.
    """
    for cfg_item in cfg.keys():
        if cfg_item in os.environ:
            logger.info({"message": "Setting config from environment"})
            if isinstance(cfg[cfg_item], int):
                cfg[cfg_item] = int(os.environ[cfg_item])
            elif isinstance(cfg[cfg_item], float):
                cfg[cfg_item] = float(os.environ[cfg_item])
            elif isinstance(cfg[cfg_item], list):
                cfg[cfg_item] = os.environ[cfg_item].split(',')
            else:
                cfg[cfg_item] = os.environ[cfg_item]
            logger.info({"message": "config set",
                         "key": cfg_item, "value": cfg[cfg_item]})

    # To support injecting arbitrary environment variables into the narrative container, we
    # look for any environment variable with the prefix "NARRENV_" and add it into a narrenv
    # dictionary in the the config hash, using the env variable name stripped of "NARRENV_"
    # prefix as the key
    for k in os.environ.keys():
        match = re.match(r"^NARRENV_(\w+)", k)
        if match:
            cfg['narrenv'][match.group(1)] = os.environ[k]
            logger.info({"message": "config set",
                         "key": "narrenv.{}".format(match.group(1)), "value": os.environ[k]})


def get_db() -> sqlite3.Connection:
    """
    Helper function for having flask get a database handle as needed
    """
    db = getattr(flask.g, '_database', None)
    if db is None:
        db = flask.g._database = sqlite3.connect(cfg['sqlite_reaperdb_path'])
    db.row_factory=sqlite3.Row
    return db


def get_narr_activity_from_db() -> Dict[ str, float ]:
    """
    Helper function to get the narrative activity from the database.
    """
    conn = get_db()
    cursor = conn.cursor()
    narr_activity = dict()
    for row in cursor.execute('SELECT * FROM narr_activity'):
        narr_activity[row['servicename']] = row['lastseen']
    return narr_activity


def save_narr_activity_to_db(narr_activity: Dict[ str, float ]) -> None:
    conn = get_db()
    cursor = conn.cursor()
    new_activity = list()
    for key in narr_activity:
        new_activity.append((key, narr_activity[key] ))
    logger.debug({"message": "Saving new narr_activity to database: {}".format(new_activity)})
    cursor.execute("DELETE FROM narr_activity")
    cursor.executemany('INSERT OR REPLACE INTO narr_activity VALUES (?,?)',new_activity)
    conn.commit()


def delete_from_narr_activity_db(servicename: str) -> int:
    """
    Helper function to delete one row of the narrative activity table in the database.
    """
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute("DELETE FROM narr_activity WHERE servicename = ?", [servicename])
    num_rows = cursor.rowcount
    conn.commit()
    return num_rows

@app.teardown_appcontext
def close_connection(exception) -> None:
    """
    Helper function for having flask close a database handle automatically
    """
    db = getattr(flask.g, '_database', None)
    if db is not None:
        db.close()


def setup_app(app: flask.Flask) -> None:
    global errors
    errors = {'no_cookie': "No {} cookie in request".format(cfg['kbase_cookie']),
              'auth_error': "Session cookie failed validation at {}: ".format(cfg['auth2']),
              'request_error': "Error querying {}: ".format(cfg['auth2']),
              'other': "Unexpected error: "}

    # Seed the random number generator based on default (time)
    random.seed()

    merge_env_cfg()

    # Configure logging
    logging.basicConfig(stream=sys.stdout, level=int(cfg['log_level']))

    # Remove the default flask logger in favor of the one we just configured
    logger.removeHandler(flask.logging.default_handler)

    logging.getLogger("urllib3").setLevel(logging.CRITICAL)

    # Verify that either docker or rancher configs are viable before continuing. It is a fatal error if the
    # configs aren't good, so bail out entirely and don't start the app. Set the global method pointers to
    # point at the right method - this will go away once the class based rewrite happens
    global check_session
    global start
    global find_image
    global find_service
    global find_narratives
    global find_narrative_labels
    global reap_narrative
    global naming_regex
    global find_stopped_services
    global stack_suffix

    try:
        if (cfg["rancher_url"] is not None):
            cfg['mode'] = "rancher"
            manage_rancher.setup(cfg, logger)
            manage_rancher.verify_config(cfg)
            check_session = manage_rancher.check_session
            start = manage_rancher.start
            find_image = manage_rancher.find_image
            find_service = manage_rancher.find_service
            find_narratives = manage_rancher.find_narratives
            find_narrative_labels = manage_rancher.find_narrative_labels
            reap_narrative = manage_rancher.reap_narrative
            naming_regex = "^{}_"
            find_stopped_services = manage_rancher.find_stopped_services
            stack_suffix = manage_rancher.stack_suffix
        else:
            cfg['mode'] = "docker"
            manage_docker.setup(cfg, logger)
            manage_docker.verify_config(cfg)
            start = manage_docker.start
            find_image = manage_docker.find_image
            find_service = manage_docker.find_service
            find_narratives = manage_docker.find_narratives
            find_narrative_labels = manage_docker.find_narrative_labels
            reap_narrative = manage_docker.reap_narrative
            naming_regex = "^{}$"
    except Exception as ex:
        logger.critical("Failed validation of docker or rancher configuration")
        raise(ex)
    logger.info({'message': "container management mode set to: {}".format(cfg['mode'])})
    if cfg.get("num_prespawn", 0) > 0 and cfg['mode'] == "rancher":
        prespawn_narrative(cfg['num_prespawn'])

    # Prepopulate the narr_activity dictionary with current narratives found
    narr_activity = dict()
    narrs = find_narratives()
    logger.debug({"message": "Found existing narrative containers at startup", "names": str(narrs)})
    prefix = cfg['container_name'].format('')
    if stack_suffix is not None:
        suffix = stack_suffix()
    else:
        suffix = ""
    narr_time = { narr+suffix: time.time() for narr in narrs if narr.startswith(prefix) }
    logger.debug({"message": "Adding containers matching {} to narr_activity".format(prefix), "names": str(list(narr_time.keys()))})
    narr_activity.update(narr_time)

    logger.info({'message': "using sqlite3 database in {}".format(cfg['sqlite_reaperdb_path'])})
    try:
        # need this because we are not in a flask request context here
        with app.app_context():
            db = get_db()
            cursor = db.cursor()
            cursor.execute('CREATE TABLE IF NOT EXISTS narr_activity (servicename TEXT PRIMARY KEY, lastseen FLOAT)')
            db.commit()
            save_narr_activity_to_db(narr_activity)
    except Exception as e:
        logger.critical({"message": "Could not save initial narr_activity data to database: {}".format(repr(e))})
 

def get_prespawned() -> List[str]:
    """
    Returns a list of the prespawned narratives waiting to be assigned
    """
    if cfg["mode"] != "rancher":
        raise(NotImplementedError("prespawning only supports rancher mode, current mode={}".format(cfg['mode'])))
    narratives = manage_rancher.find_narratives()
    idle_narr = [narr for narr in narratives if cfg['container_name_prespawn'].format("") in narr]
    return(idle_narr)


def prespawn_narrative(num: int) -> None:
    """
    Prespawn num narratives that incoming users can be assigned to immediately
    """
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


def reload_msg(narrative: str ) -> flask.Response:
    """
    Return a response object that redirects ultimately to the running narrative container,
    by way of the load-narrative page
    """
    msg = """
<html><head><META HTTP-EQUIV="refresh" CONTENT="0;URL='/load-narrative.html?n={}&check=true'">
</head>
<body>
</body>
</html>
"""
    resp = flask.Response(msg.format(narrative))
    resp.status_code = 201
    return(resp)


def error_response(auth_status: Dict[str, str], request: flask.request) -> flask.Response:
    """
    Return an flask response that is appropriate for the message in the auth_status dict.
    """
    resp = flask.Response(errors[auth_status["error"]])
    if auth_status['error'] == 'no_cookie':
        resp = flask.Response(errors['no_cookie'])
        resp.status_code = 401
    elif auth_status['error'] == 'auth_error':
        resp = flask.Response(errors['auth_error']+auth_status['message'])
        resp.status_code = 403
    elif auth_status['error'] == 'request_error':
        resp = flask.Response(errors['request_error']+auth_status['message'])
        resp.status_code = 403
    else:
        resp = flask.Response(errors['other']+auth_status['message'])
        resp.status_code = 400
    client_ip = request.headers.get("X-Real-Ip", request.headers.get("X-Forwarded-For", None))
    logger.info({"message": "auth_error", "client_ip": client_ip, "error": auth_status['error'],
                "detail": auth_status.get('message', "")})
    return(resp)


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
                auth_status['customroles'] = authresponse['customroles']
            else:
                auth_status['error'] = 'auth_error'
                auth_status['message'] = authresponse['error']['message']
        except Exception as err:
            auth_status['error'] = "request_error"
            auth_status['message'] = repr(err)
    return(auth_status)


def clean_userid( userid: str) -> str:
    """
    Takes a normal KBase userid and converts it into a userid that is okay to embed in a rancher servicename
    """
    hash = hashlib.sha1(userid.encode()).hexdigest()
    hash = hash[:6]
    clean1 = re.sub('[\._-]+', '-', userid)
    cleaned = re.sub('-$', '-0', clean1)
    max_len = 62 - len(cfg['container_name']) - len(hash)
    cleaned = "{}-{}".format(cleaned[:max_len], hash)
    return(cleaned)


def get_container(dirty_user: str, request: flask.Request, narrative: str) -> flask.Response:
    """
    Given the request object and the username from validating the token, either find or spin up
    the narrative container that should handle this user's narrative session. The narrative
    parameter is the path to the requested narrative from the original URL. Return a flask response
    object that contains the necessary cookie for traefik to use for routing, as well as a brief
    message that reloads the page so that traefik reroutes to the right place
    """
    # See if there is an existing session for this user, if so, reuse it
    userid = clean_userid(dirty_user)
    session = check_session(userid)
    client_ip = request.headers.get("X-Real-Ip", request.headers.get("X-Forwarded-For", None))
    if session is None:
        logger.debug({"message": "new_session", "userid": userid, "client_ip": client_ip})
        resp = reload_msg(narrative)
        session = random.getrandbits(128).to_bytes(16, "big").hex()
        try:
            # Try to get a narrative session, the session value returned is the one that has been assigned to the
            # userid. The second value is whether or not the session is to a prespawned container, no wait is necessary
            response = start(session, userid)
            session = response['session']
            if "prespawned" in response:
                resp = reload_msg(narrative)
        except Exception as err:
            logger.critical({"message": "start_container_exception", "userid": userid, "client_ip": client_ip,
                            "exception": repr(err)})
            resp = error_response({"error": "other", "message": repr(err)}, request)
            session = None
    else:
        # Session already exists, don't pause before reloading
        resp = reload_msg(narrative)
    if session is not None:
        cookie = "{}={}".format(cfg['session_cookie'], session)
        logger.debug({"message": "session_cookie", "userid": userid, "client_ip": client_ip, "cookie": cookie})
        resp.set_cookie(cfg['session_cookie'], session)
    return(resp)


def get_active_traefik_svcs(narr_activity) -> Dict[str, time.time]:
    """
    Looks through the traefik metrics endpoint results to find active websockets for narratives, and returns
    a dictionary identical in structure to the narr_activity structure used in reaper() .
    """

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
            prefix = cfg['container_name'].format('')
            logger.debug({"message": "Looking for containers that with name prefix {} and image name {}".format(prefix, cfg['narr_img'])})
            for name in containers.keys():
                logger.debug({"message": "Examining container: {}".format(name)})
                # Skip any containers that don't match the container prefix, to avoid wasting time on the wrong containers
                if name.startswith(prefix):
                    logger.debug({"message": "Matches prefix"})
                    image_name = find_image(name)
                    # Filter out any container that isn't the image type we are reaping
                    if (image_name is not None and cfg['narr_img'] in image_name):
                        logger.debug({"message": "Matches image name"})
                        # only update timestamp if the container has active websockets or this is the first
                        # time we've seen it.
                        if (containers[name] > 0) or (name not in narr_activity):
                            narr_activity[name] = time.time()
                            logger.debug({"message": "Updated timestamp for "+name})
                    else:
                        logger.debug({"message": "Skipping because {} not in {}".format(cfg['narr_img'], image_name)})
                else:
                    logger.debug({"message": "Skipped {} because it didn't match prefix {}".format(name, prefix)})
            return(narr_activity)
        else:
            raise(Exception("Error querying {}:{} {}".format(cfg['traefik_metrics'], r.status_code, r.text)))
    except Exception as e:
        _, _, tb = sys.exc_info()
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


def reaper() -> int:
    """
    Reaper function, originally intended to be called at regular intervals specified by cfg['reaper_sleep_secs']. Now being
    called by /reaper/ endpoint, returning number of narratives reaped
    Updates last seen timestamps for narratives, reaps any that have been idle for longer than cfg['reaper_timeout_secs']
    """
    global narr_last_version

    # Get narr_activity from the database
    try:
        narr_activity = get_narr_activity_from_db()
    except Exception as e:
        logger.critical({"message": "Could not get data from database: {}".format(repr(e))})
        return

    reaped = 0
    log_info = { k : datetime.utcfromtimestamp(narr_activity[k]).isoformat() for k in narr_activity.keys() }
    logger.info({"message": "Reaper function running", "narr_activity": str(log_info)})
    try:
        newtimestamps = get_active_traefik_svcs(narr_activity)
        narr_activity.update(newtimestamps)
    except Exception as e:
        logger.critical({"message": "ERROR: {}".format(repr(e))})
        return
    log_info = { k : datetime.utcfromtimestamp(narr_activity[k]).isoformat() for k in narr_activity.keys() }
    logger.debug({"message": "Activity after updated from traefik: ", "narr_activity": str(log_info)})

    now = time.time()
    reap_list = [name for name, timestamp in narr_activity.items() if (now - timestamp) > cfg['reaper_timeout_secs']]

    for name in reap_list:
        msg = "Container {} has been inactive longer than {}. Reaping.".format(name, cfg['reaper_timeout_secs'])
        logger.info({"message": msg})
        try:
            reap_narrative(name)
            # possible future work: use helper function to delete an entry from narr_activity in db
            del narr_activity[name]
            reaped += 1
        except Exception as e:
            logger.critical({"message": "Error: Unhandled exception while trying to reap container {}: {}".format(name, repr(e))})

    # Save narr_activity back to the database
    try:
        # trust that the narr_activity dict has the right info
        # if true then it should be safe to delete the table contents and repopulate from it
        save_narr_activity_to_db(narr_activity)
    except Exception as e:
        logger.critical({"message": "Could not save data to database: {}".format(repr(e))})

    # Look for any containers that may have died on startup and reap them as well
    try:
        zombies = find_stopped_services().keys()
        logger.debug({"message": "find_stopped_services() called", "num_returned": len(zombies)})
        for name in zombies:
            if ( cfg['container_name'].format("") in name or cfg['container_name_prespawn'].format("") in name ):
                msg = "Container {} identified as zombie container. Reaping.".format(name)
                logger.info({"message": msg})
                reap_narrative(name)
                reaped += 1
            else:
                msg = "Not reaping started-once container {} , does not match prefixes {} or {} ".format(name,cfg['container_name'],cfg['container_name_prespawn'])
                logger.info({"message": msg})
    except Exception as ex:
        logger.critical({"message": "Exception reaping zombie narratives", "Exception": repr(ex)})

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
            elif versiontuple(latest_version) != versiontuple(narr_last_version):
                narr_last_version = latest_version
                logger.info({"message": "narr_last_version set", "version": narr_last_version})
                reap_older_prespawn(latest_version)
                reaped += 1
        except Exception as ex:
            logger.critical({"message": "Error while checking prespawned narrative versions {}".format(repr(ex))})

    # Now make sure the narrative prespawn spool is at the desired level
    if cfg.get("num_prespawn", 0) > 0 and cfg['mode'] == "rancher":
        prespawn_narrative(cfg['num_prespawn'])
    return(reaped)

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
        dirty_user = auth_status['userid']
        userid = clean_userid(dirty_user)
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
                # name against what Traefik would call
                # (this seems to not be matching anything for some reason)
                # possible future work: use helper function to delete entry from narr_activity in db
                name_match = naming_regex.format(name)
                try:
                    narr_activity = get_narr_activity_from_db()
                except Exception as e:
                    logger.critical({"message": "Could not get data from database: {}".format(repr(e))})
                    raise(e)
                for narr_name in narr_activity.keys():
                    if re.match(name_match, narr_name):
                        delete_from_narr_activity_db(narr_activity[narr_name])
                        break
                resp = flask.Response("Service {} deleted".format(name), 200)
            except Exception as e:
                logger.critical({"message": "Error: Unhandled exception while trying to reap container {}: {}".format(name, repr(e))})
                resp = flask.Response("Error deleteing service {}: {}".format(name, repr(e)), 200)
    else:
        resp = flask.Response('Valid kbase authentication token required', 401)
    return resp


def narrative_services() -> List[dict]:
    """
    Queries the rancher APIs to build a list of narrative container descriptors
    """
    narr_names = find_narratives()
    narr_services = []
    prespawn_pre = cfg['container_name_prespawn'].format('')
    narr_pre = cfg['container_name'].format('')
    try:
        narr_activity = get_narr_activity_from_db()
        logger.critical({"message": "keys from narr_activity db:{}".format(",".join(narr_activity.keys()))})
    except Exception as e:
        logger.critical({"message": "Could not get data from database for narrative_status, faking last_seen: {}".format(repr(e))})
        narr_activity = None
    
    try:
        suffix = stack_suffix()
    except:
        suffix = ""
    
    for name in narr_names:
        if name.startswith(prespawn_pre):
            info = {"state": "queued", "session_id": "*", "instance": name, 'last_seen': time.asctime() }
        else:
            user = name.replace(narr_pre, "", 1)
            info = {"instance": name, "state": "active", "session_id": user}
            if narr_activity:
                try:
                    info['last_seen'] = time.asctime(narr_activity[name+suffix])
                except Exception as ex:
                    logger.critical({"message": "Error: adding last_seen field", "error": repr(ex),
                                     "container": name})
                    info['last_seen'] = time.asctime() # just use current time as last seen
            else:
                    info['last_seen'] = time.asctime()
            try:
                svc = find_service(name)
                info['session_key'] = svc['launchConfig']['labels']['session_id']
                info['image'] = svc['launchConfig']['imageUuid']
                info['publicEndpoints'] = str(svc['publicEndpoints'])
                match = re.match(r'client-ip:(\S+) timestamp:(\S+)', svc['description'])
                if match:
                    info['last_ip'] = match.group(1)
                    info['created'] = match.group(2)
            except Exception as ex:
                logger.critical({"message": "Error: Unhandled exception while trying to query service {}: {}".format(name, repr(ex))})
                info['session_key'] = "Error querying api"
                info['image'] = None
                info['publicEndpoints'] = None
                info['last_ip'] = None
                info['created'] = None
        narr_services.append(info)
    return(narr_services)


@app.route("/narrative_status/", methods=['GET'])
def narrative_status():
    """
    Simple status endpoint to re-assure us that the service is alive. Unauthenticated access just returns
    a 200 code with the current time in JSON string. If a kbase auth cookie is found, and the username is in the
    list of ID's in cfg['status_users'] then a dump of the current narratives running and their last
    active time from narr_activity is returned in JSON form, easily sent to elasticsearch for ingest, roughly
    matching the old proxy_map output from original OpenRest lua code
    """

    logger.info({"message": "Status query received"})

    # Get narr_activity from the database
    # not currently used but may use in the future
    try:
        narr_activity = get_narr_activity_from_db()
    except Exception as e:
        logger.critical({"message": "Could not get narr_activity data from database: {}".format(repr(e))})
        return

    resp_doc = {"timestamp": datetime.now().isoformat(), "version": VERSION, "git_hash": cfg['COMMIT_SHA']}
    request = flask.request
    auth_status = valid_request(request)
    logger.debug({"message": "Status query received", "auth_status": auth_status})
    if 'userid' in auth_status:
        if cfg['status_role'] in auth_status['customroles']:
            resp_doc['narrative_services'] = narrative_services()
        else:
            logger.debug({"message": "{} roles does not contain {}".format(auth_status['userid'], cfg['status_role']),
                          "customroles": str(auth_status['customroles'])})
    return(flask.Response(json.dumps(resp_doc), 200, mimetype='application/json'))


@app.route("/reaper/", methods=['GET'])
def reaper_endpoint():
    """
    Endpoint that just runs the reaper once and returns the status
    """

    request = flask.request
    logger.info({"message": "Reaper endpoint called from {}".format(request.remote_addr)})

    if (ipaddress.ip_address(request.remote_addr) in ipaddress.ip_network(cfg['reaper_ipnetwork']) ):
        try:
            num = reaper()
            resp = flask.Response("Reaper success: {} deleted".format(num))
            resp.status_code=200
        except Exception as ex:
            resp = flask.Response("Reaper error: {}".format(repr(ex)))
            resp.status_code=500
    else:
        resp = flask.Response("Reaper error: access denied from IP {}".format(request.remote_addr))
        resp.status_code = 403
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
