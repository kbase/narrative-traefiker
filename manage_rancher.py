import requests
import os
import logging

# Module wide logger
logger = None

# Setup default configuration values, overriden by values from os.environ later
cfg = {"hostname": u"localhost",
       "auth2": u"https://ci.kbase.us/services/auth/api/V2/token",
       "image": u"kbase/narrative:latest",
       "es_type": "narrative-traefiker",
       "session_cookie": u"narrative_session",
       "container_name": u"narrative-{}",
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
       "mode": None}


def setup(main_cfg, main_logger):
    global cfg
    if main_cfg is not None:
        cfg = main_cfg
    else:
        for cfg_item in cfg.keys():
            if cfg_item in os.environ:
                cfg[cfg_item] = os.environ[cfg_item]
    global logger
    if main_logger is None:
        logger = logging.getLogger()
    else:
        logger = main_logger


def check_session(userid):
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
            logger.error({"message": msg, "status_code": r.status_code, "name": name, "response_body": r.text})
            raise(Exception(msg))
        res = r.json()
        svcs = res['data']
        if len(svcs) == 0:
            logger.debug({"message": "No previous session found", "name": name, "userid": userid})
            session_id = None
        else:
            session_id = svcs[0]['launchConfig']['labels']['session_id']
            logger.debug({"message": "Found existing session", "session_id": session_id, "userid": userid})
            if len(svcs) > 1:
                uuids = [svc['uuid'] for svc in svcs]
                logger.warning({"message": "Found multiple session matches against container name", "userid": userid,
                               "name": name, "rancher_uuids": uuids})
    except Exception as ex:
        logger.debug({"message": "Error trying to find existing session", "exception": format(str(ex)), "userid": userid})
        raise(ex)
    return(session_id)


def start(session, userid, request):
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
    cookie = u'{}\\={}'.format(cfg['session_cookie'], session)
    labels = dict()
    labels["io.rancher.container.pull_image"] = u"always"
    labels["traefik.enable"] = u"True"
    labels["session_id"] = session
    rule = u"Host(\"{}\") && PathPrefix(\"{}\") && HeadersRegexp(\"Cookie\",\"{}\")"
    labels["traefik.http.routers." + userid + ".rule"] = rule.format(cfg['hostname'], "/narrative", cookie)
    labels["traefik.http.routers." + userid + ".entrypoints"] = u"web"
    container_config['launchConfig']['labels'] = labels
    container_config['launchConfig']['name'] = name
    container_config['name'] = name
    container_config['stackId'] = cfg['rancher_stack_id']
    # Attempt to bring up a container, if there is an unrecoverable error, clear the session variable to flag
    # an error state, and overwrite the response with an error response
    try:
        r = requests.post(cfg["rancher_env_url"]+"/service", json=container_config, auth=(cfg["rancher_user"], cfg["rancher_password"]))
        logger.info({"message": "new_container", "image": cfg['image'], "userid": userid, "name": name, "session_id": session,
                    "client_ip": "127.0.0.1"})  # request.remote_addr)
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
    logger.info("Found environment endpoint: {}".format(env_endpoint))
    r = requests.get(env_endpoint+"/stacks", auth=(cfg['rancher_user'], cfg['rancher_password']))
    resp = r.json()
    x = [stack['id'] for stack in resp['data'] if stack['name'].lower() == stack_name.lower()]
    logger.info("Found stack id: {}".format(x[0]))
    return({"url": env_endpoint, "stack_id": x[0]})


def find_service(traefikname):
    """
    Given a service name, return the JSON service object from Rancher of that name. Throw an exception
    if (exactly) one isn't found.
    """
    name = traefikname.replace("_traefik", "")  # Remove trailing _traefik suffix that traefik adds
    url = "{}/service?name={}".format(cfg['rancher_env_url'], name)
    r = requests.get(url, auth=(cfg['rancher_user'], cfg['rancher_password']))
    if r.ok:
        results = r.json()
        if len(results['data']) == 1:
            return(results['data'][0])
        else:
            raise(Exception("Error querying for {}: expected exactly 1 result, got {}".format(name, len(results['data']))))
    else:
        raise(Exception("Error querying for {}: Response code {}: {}".format(name, r.status_code, r.body)))


def find_image(name):
    """
    Given a service name, return the docker image that the service is running. If the service doesn't exist
    then return None, as this may mean that service has been reaped already
    """
    try:
        container = find_service(name)
        if container is not None:
            src, image = container["launchConfig"]["imageUuid"].split(":", 1)
        else:
            image = None
        return(image)
    except Exception as ex:  # Just reraise any other exception
        raise(ex)


def reap_narrative(name):
    res = find_service(name)
    remove_url = res['actions']['remove']
    r = requests.delete(remove_url, auth=(cfg['rancher_user'], cfg['rancher_password']))
    if r.ok:
        return
    else:
        raise(Exception("Problem reaping narrative {}: response code {}: {}".format(name, r.status_code, r.text)))


def verify_config(cfg2):
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
