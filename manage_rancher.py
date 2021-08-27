import requests
import os
import logging
import re
import random
import flask
from datetime import datetime
from typing import Dict, List, Optional


# Module wide logger
logger: Optional[logging.Logger] = None

# Setup default configuration values, overriden by values from os.environ later
cfg = {"hostname": u"localhost",
       "auth2": u"https://ci.kbase.us/services/auth/api/V2/token",
       "image_name": u"kbase/narrative",
       "image_tag": None,
       "es_type": "narrative-traefiker",
       "session_cookie": u"narrative_session",
       "container_name": u"narrative-{}",
       "container_name_prespawn": u"narrative_pre-{}",
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
       "rancher_stack_name": None,
       "mode": None,
       "narrenv": dict()}


def setup(main_cfg: dict, main_logger: logging.Logger) -> None:
    global cfg
    global logger

    if main_logger is None:
        logger = logging.getLogger()
    else:
        logger = main_logger

    if main_cfg is not None:
        cfg = main_cfg
    else:
        # We pull any environment variable that matches a config key into the config dictionary
        for cfg_item in cfg.keys():
            if cfg_item in os.environ:
                cfg[cfg_item] = os.environ[cfg_item]
        # To support injecting arbitrary environment variables into the narrative container, we
        # look for any environment variable with the prefix "NARRENV_" and add it into a narrenv
        # dictionary in the the config hash, using the env variable name stripped of "NARRENV_"
        # prefix as the key
        for k in os.environ.keys():
            match = re.match(r"^NARRENV_(\w+)", k)
            if match:
                cfg['narrenv'][match.group(1)] = os.environ[k]
                logger.debug({"message": "Setting narrenv from environment",
                              "key": match.group(1), "value": os.environ[k]})

# to do: figure out how to use method defined in app.py instead
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


def check_session(userid: str) -> str:
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
            logger.error({"message": msg, "status_code": r.status_code, "service_name": name, "response_body": r.text})
            raise(Exception(msg))
        res = r.json()
        svcs = res['data']
        if len(svcs) == 0:
            logger.debug({"message": "No previous session found", "service_name": name, "userid": userid})
            session_id = None
        else:
            session_id = svcs[0]['launchConfig']['labels']['session_id']
            logger.debug({"message": "Found existing session", "session_id": session_id, "userid": userid})
            if len(svcs) > 1:
                uuids = [svc['uuid'] for svc in svcs]
                logger.warning({"message": "Found multiple session matches against container name", "userid": userid,
                               "service_name": name, "rancher_uuids": uuids})
    except Exception as ex:
        logger.debug({"message": "Error trying to find existing session", "exception": format(str(ex)), "userid": userid})
        raise(ex)
    return(session_id)


def start(session: str, userid: str, prespawn: Optional[bool] = False) -> Dict[str, str]:
    """
    wrapper around the start_new function that checks to see if there are waiting narratives that
    can be assigned. Note that this method is subject to race conditions by competing workers, so we
    have 5 retries, and try to select a random waiting narrative before just spawning a new one. Someday maybe
    we can implement something to serialize selecting narratives for assignment, but that's a ToDo item.
    """
    if prespawn is True:
        start_new(session, userid, True)
    else:
        prespawned = find_prespawned()
        # The number of prespawned should be pretty stable around cfg['num_prespawn'], but during a
        # usage there might be spike that exhausts the pool of ready containers before replacements
        # are available.
        if len(prespawned) > 0:
            # if we're not already over the num)prespawn setting then
            # spawn a replacement and immediately rename an existing container to match the
            # userid. We are replicating the prespawn container name code here, maybe cause
            # issues later on if the naming scheme is changed!
            if len(prespawned) <= cfg['num_prespawn']:
                start_new(session, session[0:6], True)
            narr_name = cfg['container_name'].format(userid)
            offset = random.randint(0, len(prespawned)-1)
            session = None
            # Try max(5, # of prespawned) times to use an existing narrative, on success assign the session and break
            for attempt in range(max(5, len(prespawned))):
                candidate = prespawned[(offset+attempt) % len(prespawned)]
                try:
                    rename_narrative(candidate, narr_name)
                    container = find_service(narr_name)
                    session = container['launchConfig']['labels']['session_id']
                    logger.info({"message": "assigned_container", "userid": userid, "service_name": narr_name, "session_id": session,
                                 "client_ip": "127.0.0.1", "attempt": attempt, "status": "success"})
                    break
                except Exception as ex:
                    logger.info({"message": "assigned_container_fail", "userid": userid, "service_name": narr_name, "session_id": session,
                                 "client_ip": "127.0.0.1", "attempt": attempt, "status": "fail", "error": str(ex)})
            if session:
                return({"session": session, "prespawned": True})
            else:
                # Well, that was a bust, just spin up one explicitly for this user. Maybe we hit a race condition where all of the
                # cached containers have been assigned between when we queried and when we tried to rename it.
                # ToDo: need to write a pool watcher thread that wakes up periodically to make sure the number of prespawned
                # narratives are still at the desired level. Shouldn't be needed since there should be a 1:1 between assigning
                # and spawning replacements, but errors happen
                logger.debug({"message": "could not assign prespawned container, calling start_new", "userid": userid, "session_id": session})
                return({"session": start_new(session, userid, False)})
        else:
            return({"session": start_new(session, userid, False)})


def start_new(session: str, userid: str, prespawn: Optional[bool] = False):
    """
    Attempts to start a new container using the rancher API. Signature is identical to the start_docker
    method, with the equivalent rancher exceptions.
    """
    # Crazy long config needed for rancher container startup. Based on observing the traffic from rancher
    # GUI to rancher REST APIs. Might be able to prune it down with some research
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
                            u'capDrop': ["MKNOD", "NET_RAW", "SYS_CHROOT", "SETUID", "SETGID", "CHOWN", "SYS_ADMIN", "BPF",
                                         "DAC_OVERRIDE", "FOWNER", "FSETID", "SETPCAP", "AUDIT_WRITE", "SETFCAP"],
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
                            u'ports': [u'8888/tcp'],
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
                        u'system': False,
                        u'type': u'service',
                        u'uuid': None,
                        u'vip': None}
    if prespawn is False:
        name = cfg['container_name'].format(userid)
        client_ip = flask.request.headers.get("X-Real-Ip", flask.request.headers.get("X-Forwarded-For", None))
        try:  # Set client ip from request object if available
            container_config['description'] = 'client-ip:{} timestamp:{}'.format(client_ip,
                                                                                 datetime.utcnow().strftime('%Y-%m-%dT%H:%M:%S.%fZ'))
        except Exception:
            logger.error({"message": "Error checking flask.request.headers for X-Real-Ip or X-Forwarded-For"})
    else:
        name = cfg['container_name_prespawn'].format(userid)
        client_ip = None
    cookie = u'{}'.format(session)
    labels = dict()
    labels["io.rancher.container.pull_image"] = u"always"
    labels["io.rancher.container.start_once"] = u"true"
    labels["traefik.enable"] = u"True"
    labels["session_id"] = session
    # create a rule for list of hostnames that should match from cfg['hostname']
    host_rules = " || ".join([u"Host(\"{}\")".format(hostname) for hostname in cfg['hostname']])
    remaining_rule = u" && PathPrefix(\"{}\") && HeadersRegexp(\"Cookie\",`{}`)"
    labels["traefik.http.routers." + userid + ".rule"] = host_rules + remaining_rule.format("/narrative/", cookie)
    labels["traefik.http.routers." + userid + ".entrypoints"] = u"web"
    container_config['launchConfig']['labels'] = labels
    container_config['launchConfig']['name'] = name
    if (cfg['image_tag'] is not None):
        imageUuid = "{}:{}".format(cfg['image_name'], cfg['image_tag'])
    else:
        imageUuid = "{}:{}".format(cfg['image_name'], narr_last_version)
    container_config['launchConfig']['imageUuid'] = "docker:{}".format(imageUuid)
    container_config['launchConfig']['environment'].update(cfg['narrenv'])
    container_config['name'] = name
    container_config['stackId'] = cfg['rancher_stack_id']

    # Attempt to bring up a container, if there is an unrecoverable error, clear the session variable to flag
    # an error state, and overwrite the response with an error response
    try:
        r = requests.post(cfg["rancher_env_url"]+"/service", json=container_config, auth=(cfg["rancher_user"], cfg["rancher_password"]))
        logger.info({"message": "new_container", "image": imageUuid, "userid": userid, "service_name": name, "session_id": session,
                    "client_ip": client_ip})  # request.remote_addr)
        if not r.ok:
            msg = "Error - response code {} while creating new narrative rancher service: {}".format(r.status_code, r.text)
            logger.error({"message": msg})
            raise(Exception(msg))
    except Exception as ex:
        raise(ex)
    return(session)


def find_stack() -> Dict[str, str]:
    """
    Query the rancher-metadata service for the name of the stack we're running in, and then
    go to the rancher_url and walk down through the stacks in the rancher environments we
    have access to that find the the endpoint that matches the name
    """
    r = requests.get(cfg['rancher_meta']+"2016-07-29/self/stack/environment_name")
    env_name = r.text
    logger.info("Found environment name: {}".format(env_name))
    r = requests.get(cfg['rancher_meta']+"2016-07-29/self/stack/name")
    stack_name = r.text
    logger.info("Found stack name: {}".format(stack_name))
#   set this in info instead, to set all rancher vars in verify_config
#    cfg['rancher_stack_name'] = stack_name
    url = cfg['rancher_url']+"projects"
    logger.info("Querying {} with supplied credentials".format(url))
    r = requests.get(url, auth=(cfg['rancher_user'], cfg['rancher_password']))
    if not r.ok:
        msg = "Error querying {}: {} {}".format(url, r.status_code, r.text)
        logger.error(msg)
        raise IOError(msg)

    resp = r.json()
    x = [env['links']['self'] for env in resp['data'] if env['name'].lower() == env_name.lower()]
    env_endpoint = x[0]
    logger.info("Found environment endpoint: {}".format(env_endpoint))
    r = requests.get(env_endpoint+"/stacks", auth=(cfg['rancher_user'], cfg['rancher_password']))
    resp = r.json()
    x = [stack['id'] for stack in resp['data'] if stack['name'].lower() == stack_name.lower()]
    logger.info("Found stack id: {}".format(x[0]))
    return({"url": env_endpoint, "stack_id": x[0], "stack_name": stack_name})


def stack_suffix() -> str:
    """
    Returns the stack suffix that traefik appends to service names.
    """
    return("_{}".format(cfg['rancher_stack_name']))


def find_service(traefikname: str) -> dict:
    """
    Given a service name, return the JSON service object from Rancher of that name. Throw an exception
    if (exactly) one isn't found.
    """
    suffix = stack_suffix()
    name = traefikname.replace(suffix, "")  # Remove trailing _traefik suffix that traefik adds
    url = "{}/service?name={}".format(cfg['rancher_env_url'], name)
    r = requests.get(url, auth=(cfg['rancher_user'], cfg['rancher_password']))
    if r.ok:
        results = r.json()
    if len(results['data']) == 0:
        # Assume that the container has already been reaped and ignore
        return(None)
    else:
        res = results['data'][0]
        if len(results['data']) > 1:
            # If we have more than 1 result, then something is broken. Delete all but the newest image and
            # return that one
            logger.error({"message": "There can be only one...container with a name match. Deleting all but the first entry"})
            for svc in results['data'][1:]:
                remove_url = svc['actions']['remove']
                r = requests.delete(remove_url, auth=(cfg['rancher_user'], cfg['rancher_password']))
                if r.ok:
                    logger.info({"message": "Removed duplicate narrative {} {}".format(svc['id'], svc['name'])})
                else:
                    raise(Exception("Problem duplicate narrative {} {} .: response code {}: {}".format(svc['id'], svc['name'], r.status_code, r.text)))
        return(res)


def find_stopped_services() -> dict:
    """
    Query rancher for services with the state "healthState=started-once" and return the names of matching services
    Result can be an empty dictionary
    """
    url = "{}/service?healthState=started-once".format(cfg['rancher_env_url'])
    r = requests.get(url, auth=(cfg['rancher_user'], cfg['rancher_password']))
    if r.ok:
        results = r.json()
        names = {svc['name']: svc for svc in results['data']}
        return(names)
    else:
        raise(Exception("Error querying for stopped services: Response code {}".format(r.status_code)))


def find_image(name: str) -> str:
    """
    Given a service name, return the docker image that the service is running. If the service doesn't exist
    then return None, as this may mean that service has been reaped already
    """
    try:
        container = find_service(name)
        if container is not None:
            src, image = container["launchConfig"]["imageUuid"].split(":", 1)
        else:
            logger.info("Could not find_service named {}".format(name))
            image = None
        return(image)
    except Exception as ex:  # Just reraise any other exception
        raise(ex)


def reap_narrative(name: str) -> None:
    res = find_service(name)
    # if there is a None return, the image may have been reaped already just return
    if res is None:
        return
    remove_url = res['actions']['remove']
    r = requests.delete(remove_url, auth=(cfg['rancher_user'], cfg['rancher_password']))
    if r.ok:
        return
    else:
        raise(Exception("Problem reaping narrative {}: response code {}: {}".format(name, r.status_code, r.text)))


def rename_narrative(name1: str, name2: str) -> None:
    res = find_service(name1)
    # if there is a None return, the image may have been reaped already just return
    if res is None:
        return
    put_url = res['links']['self']
    # Object with updated values for the service
    data = {"name": name2}
    # On a rename, the request object should always exist, but just in case
    client_ip = flask.request.headers.get("X-Real-Ip", flask.request.headers.get("X-Forwarded-For", None))
    data['description'] = 'client-ip:{} timestamp:{}'.format(client_ip,
                                                             datetime.utcnow().strftime('%Y-%m-%dT%H:%M:%S.%fZ'))
    r = requests.put(put_url, auth=(cfg['rancher_user'], cfg['rancher_password']), data=data)
    if r.ok:
        return
    else:
        raise(Exception("Problem renaming narrative {} to {}: response code {}: {}".format(name1, name2, r.status_code, r.text)))


def find_prespawned() -> List[str]:
    """ returns a list of the prespawned narratives waiting to be assigned """
    narratives = find_narratives()
    idle_narr = [narr for narr in narratives if cfg['container_name_prespawn'].format("") in narr]
    return(idle_narr)


def find_narratives(image_name: Optional[str] = None) -> List[str]:
    """
    This query hits the endpoint for the stack (cfg['rancher_stack_id']), and returns a list of all the
    names of services that are have an imageUuid with a match for "docker:"+image_name. If no parameter is
    given (the original function signature), then the default value of cfg['image'] is used.
    """
    if image_name is None:
        image_name = cfg['image_name']
    query_params = {'limit': 1000}
    url = "{}/stacks/{}/services".format(cfg['rancher_env_url'], cfg['rancher_stack_id'])
    r = requests.get(url, auth=(cfg['rancher_user'], cfg['rancher_password']), params=query_params)
    imageUuid = "docker:{}".format(image_name)
    logger.debug({"message": "querying rancher for services matching {}".format(imageUuid)})

    if not r.ok:
        raise(Exception("Error querying for services at {}: Response code {}: {}".format(url,
              r.status_code, r.body)))
    results = r.json()
    svcs = results['data']
    svc_names = [svc['name'] for svc in svcs if svc['launchConfig']['imageUuid'].startswith(imageUuid)]
    return(svc_names)


def find_narrative_labels(svc_list: list) -> dict:
    """
    Takes a list of narrative servicenames and return a dictionary keyed on servicename that
    contains the label information for each service.
    """
    label_dict = dict()
    for svc in svc_list:
        try:
            svc_obj = find_service(svc)
            url = svc_obj['links']['instances']
            r = requests.get(url, auth=(cfg['rancher_user'], cfg['rancher_password']))
            # The instance should be there because the reaper shouldn't delete a container during this
            # functions run, throw an error
            if not r.ok:
                raise(Exception("Error querying for instance at {}: Response code {}: {}".format(url,
                      r.status_code, r.body)))
            results = r.json()
            label_dict[svc] = results['data'][0]['labels']
        except Exception as ex:
            logger.critical("Error querying rancher instance info for {}: {}".format(svc, str(ex)))
    return(label_dict)


def verify_config(cfg2: dict) -> None:
    """
    Check that we can access the rancher api, then make sure that the endpoints for the environment and the stack_id are good.
    If we have the rancher_url endpoint, but nothing else, try to figure it out using the rancher-metadata endpoint
    """
    cfg.update(cfg2)
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
    if (cfg['rancher_stack_id'] is None or cfg['rancher_env_url'] is None or cfg['rancher_stack_name'] is None):
        logger.info("rancher_stack_id, rancher_stack_name, or rancher_env_url not set - introspecting rancher-metadata service")
        try:
            info = find_stack()
            cfg['rancher_stack_id'] = info['stack_id']
            cfg['rancher_stack_name'] = info['stack_name']
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
