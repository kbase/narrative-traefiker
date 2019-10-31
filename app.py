import flask
import requests
import docker
import hashlib
import os

# Setup default configuration values, overriden by values from os.environ later
cfg = {"docker_url": "unix://var/run/docker.sock",
       "hostname": "localhost",
       "auth2": "https://ci.kbase.us/services/auth/api/V2/token",
       "image": "kbase/narrative:latest",
       "session_cookie": "narrative_session",
       "kbase_cookie": "kbase_session",
       "base_url": "/narrative/"}

for cfg_item in cfg.keys():
    if cfg_item in os.environ:
        cfg[cfg_item] = os.environ[cfg_item]

client = docker.DockerClient(base_url=cfg['docker_url'])
app = flask.Flask(__name__)


def valid_request(request):
    """
    Validate request has a legit auth token and return a dictionary that has a userid field if
    it is legit, otherwise return the error message in the message field
    """
    auth_status = dict()
    return(auth_status)


def get_container(userid, request):
    """
    Given the request object and the username from validating the token, either find or spin up
    the narrative container that should handle this user's narrative session. Return a flask response
    object that contains the necessary cookie for traefik to use for routing, as well as a brief
    message that reloads the page so that traefik reroutes to the right place
    """
    resp = flask.Response()
    return(resp)


def error_response(auth_status, request):
    """
    Return an error response that is appropriate for the message in the auth_status dict.
    """
    resp = flask.Response()
    return(resp)


@app.route(cfg['base_url'] + '<path:narrative>')
def hello(narrative):
    """
    Main handler for the auth service. Validate the request, get the container is should be routed
    to and return a cookie that will result in traefik routing to the right place for subsequent
    requests. Returns an error in the flask response if requirements are not met or if an error
    occurs
    """
    request = flask.request
    auth_status = valid_request(request)
    if 'userid' in auth_status:
        resp = get_container(auth_status['userid'], request)
    else:
        resp = error_response(auth_status, request)
    return resp


if __name__ == '__main__':
    app.run()
