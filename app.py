import flask
import requests
import docker
import base64
import os
import random

# Setup default configuration values, overriden by values from os.environ later
cfg = {"docker_url": "unix://var/run/docker.sock",
       "hostname": "localhost",
       "auth2": "https://ci.kbase.us/services/auth/api/V2/token",
       "image": "kbase/narrative:latest",
       "session_cookie": "narrative_session",
       "kbase_cookie": "kbase_session",
       "base_url": "/narrative/",
       "container_name": "narrative_{}"}

for cfg_item in cfg.keys():
    if cfg_item in os.environ:
        cfg[cfg_item] = os.environ[cfg_item]

client = docker.DockerClient(base_url=cfg['docker_url'])
app = flask.Flask(__name__)

# Put all error strings in 1 place for ease of maintenance and to do comparisons for
# error handling
errors = {'no_cookie': "No {} cookie in request".format(cfg['kbase_cookie']),
          'auth_error': "Session cookie failed to validation at {}".format(cfg['auth2'])}

# Seed the random number generator based on default (time)
random.seed()


def reload_msg(narrative):
    msg = """
<html>
<head>
<META HTTP-EQUIV="refresh" CONTENT="5;URL='/narrative/{}'">
</head>
<body>
Starting container - will reload in 5 seconds
</body>
</html>
"""
    return msg.format(narrative)


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
    it is legit, otherwise return the error message in the message field
    """
    auth_status = dict()
    if cfg['kbase_cookie'] not in request.cookies:
        auth_status['message'] = errors['no_cookie']
    else:
        token = request.cookies[cfg['kbase_cookie']]
        r = requests.get(cfg['auth2'], headers={'Authorization': token})
        authresponse = r.json()
        if r.status_code == 200:
            auth_status['userid'] = authresponse['user']
        else:
            auth_status['message'] = errors['auth_error']
            auth_status['details'] = authresponse['error']['message']
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


def get_container(userid, request, narrative):
    """
    Given the request object and the username from validating the token, either find or spin up
    the narrative container that should handle this user's narrative session. Return a flask response
    object that contains the necessary cookie for traefik to use for routing, as well as a brief
    message that reloads the page so that traefik reroutes to the right place
    """
    # See if there is an existing session for this user, if so, reuse it
    session = check_session(userid)
    if session is None:
        print("Starting container for user " + userid)
        resp = flask.Response(reload_msg(narrative), status=200)
        session = base64.b64encode(str(random.getrandbits(128)))
        labels = dict()
        labels["traefik.enable"] = "True"
        labels["session_id"] = session
        cookie = "{}={}".format(cfg['narrative_session'], session)
        labels["traefik.http.routers." + userid + ".rule"] = "Host(\"" + cfg['hostname'] + "\") && PathPrefix(\"/narrative\")"
        labels["traefik.http.routers." + userid + ".rule"] += " && HeadersRegexp(\"Cookie\",\"" + cookie + "\")"
        labels["traefik.http.routers." + userid + ".entrypoints"] = "web"
        # Attempt to bring up a container, if there is an unrecoverable error, clear the session variable to flag
        # an error state, and overwrite the response with an error response
        try:
            name = cfg['container_name'].format(userid)
            container = client.containers.run('kbase/narrative', detach=True, labels=labels, hostname=userid,
                                              auto_remove=True, name=name, network="traefik_poc_default")
        except docker.errors.ImageNotFound as err:
            resp = flask.Response(container_err_msg(repr(err)), status=200)
            session = None
        except docker.errors.APIError as err:
            # If there is a race condition because a container has already started, then this should catch it.
            # Try to get the session for it, if that fails then bail with error message
            session = check_session(userid)
            if session is None:
                resp = flask.Response(container_err_msg(repr(err)), status=200)
        if session is not None:
            if container.status != u"created":
                msg = container_err_msg("Problem starting container - container status '{}'".format(container.status))
                resp = flask.Response(msg, status=200)
    if session is not None:
        cookie = "{}={}".format(cfg['narrative_session'], session)
        print("Routing based on " + cookie)
        resp.set_cookie(cfg['session_cookie'], session)
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
        resp = get_container(auth_status['userid'], request, narrative)
    else:
        resp = error_response(auth_status, request)
    return resp


if __name__ == '__main__':
    app.run()
