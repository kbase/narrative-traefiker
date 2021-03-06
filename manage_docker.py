import docker
import os
import logging
from typing import Dict, List, Optional


# Module wide docker client
client: Optional[docker.DockerClient] = None

# Module wide logger
logger: Optional[logging.Logger] = None

# Module wide config
cfg = {"docker_url": u"unix://var/run/docker.sock",
       "hostname": u"localhost",
       "image": u"kbase/narrative:latest",
       "es_type": "narrative-traefiker",
       "session_cookie": u"narrative_session",
       "container_name": u"narrative-{}",
       "dock_net": u"narrative-traefiker_default",
       "reload_secs": 5,
       "log_level": logging.DEBUG,
       "log_dest": None,
       "log_name": u"traefiker"}


def setup(main_cfg: dict, main_logger: logging.Logger) -> None:
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

    global client
    client = docker.DockerClient(base_url=cfg['docker_url'])


def find_narratives() -> List[str]:
    """
    This query hits the docker api looking for containers that are running cfg['image'], this should
    be any container running narratives
    ToDo: Implement actual code
    """
    return([])


def find_service(service_name: str) -> dict:
    """
    Given a service name, return the JSON service object from docker of that name. Throw an exception
    if (exactly) one isn't found.
    ToDo: Implement more than the stub
    """
    return({})

def verify_config(cfg: dict) -> None:
    """ Quickly test the docker socket, if it fails, rethrow the exception after some explanatory logging """
    try:
        client.containers.list()
    except Exception as ex:
        logger.critical("Error trying to list containers using {} as docker socket path.".format(cfg['docker_url']))
        raise(ex)


def find_image(name: str) -> str:
    """
    Given a service name, return the docker image that the service is running. If the service doesn't exist
    then raise and exception
    """
    try:
        container = client.containers.get(name)
    except docker.errors.NotFound:
        if cfg['debug']:
            print("Service {} not found (might be part of core stack or reaped already)".format(name))
        return(None)
    return(container.image.attrs["RepoTags"])


def reap_narrative(container_name: str) -> None:
    try:
        killit = client.containers.get(container_name)
        killit.stop()
    except docker.errors.NotFound:
        print("Container not found - may have been reaped already")
    except Exception as e:
        raise(e)  # Unhandled exception, rethrow
    return


def check_session(userid: str) -> str:
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
        logger.error({"message": msg, "container_name": name, "exception": str(err)})
        session_id = None
    return(session_id)


def start(session: str, userid: str) -> Dict[str, str]:
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
    labels["traefik.http.routers." + userid + ".rule"] = u"Host(\"" + cfg['hostname'] + u"\") && PathPrefix(\"/narrative/\")"
    labels["traefik.http.routers." + userid + ".rule"] += u" && HeadersRegexp(\"Cookie\",\"" + cookie + u"\")"
    labels["traefik.http.routers." + userid + ".entrypoints"] = u"web"
    # Attempt to bring up a container, if there is an unrecoverable error, clear the session variable to flag
    # an error state, and overwrite the response with an error response
    try:
        name = cfg['container_name'].format(userid)
        container = client.containers.run(cfg['image'], detach=True, labels=labels, hostname=name,
                                          auto_remove=True, name=name, network=cfg["dock_net"])
        logger.info({"message": "new_container", "image": cfg['image'], "userid": userid, "container_name": name,
                    "session_id": session})
    except docker.errors.APIError as err:
        # If there is a race condition because a container has already started, then this should catch it.
        # Try to get the session for it, if that fails then bail with error message
        session = check_session(userid)
        if session is None:
            raise(err)
        else:
            logger.info({"message": "previous_session", "userid": userid, "container_name": name, "session_id": session})
            container = client.get_container(name)
    if container.status != u"created":
        raise(Exception("Error starting container: container status {}".format(container.status)))
    return({"session": session})
