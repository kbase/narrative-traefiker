# narrative-traefiker
Narrative container lifecycle management for traefik

This is a replacement for the original OpenRESTy based Lua narrative lifecycle management code. It uses the same underlying reverse proxy service that JupyterHub is moving towards ( https://blog.jupyter.org/introducing-traefikproxy-a-new-jupyterhub-proxy-based-on-traefik-4839e972faf6 )

# Notes on startup configuration #

The narrative-traefiker container must run in the same stack as the traefik instance. On startup the initialization code will examine the rancher metadata services to find the appropriate stack_id

The following environment variables should be in the startup environment:

* hostname - set to the hostname that should be in the traefik routing rules for narratives
* rancher_user - the user id used in the rancher credentials for accessing the rancher API. These credential should have create privs in the environment that traefik and narrative-traefiker are running
* rancher_password - password for rancher access
* rancher_url - endpoint for the rancher API, this service is currently written to use the "v2-beta" api

Any config key in the cfg dictionary can be overridden by an environment variable.

Any environment variable with the prefix "NARRENV_" will be passed to the narrative containers when they are started, with the "NARRENV_" prefix stripped out. For example, NARRENV_testvar="test" will result in testvar="test" being set in the startup for natrratives.

The following labels need to be set to have traefik recognize this container and start routing for it:
* traefik.enable = true
* traefik.http.routers.authsvc.rule = Host("logstashanl.chicago.kbase.us") && PathPrefix("/narrative")
* traefik.http.routers.authsvc.entrypoints = web

A port has to be exposed on this container for traefik to properly route to it. Internally this service uses port 5000, recommendation is to export 5000 as well.

The location for finding metrics on container activity is in the configuration "traefik_metrics" and defaults to "http://traefik:8080/metrics". This means the traefik service needs to be named "traefik" and exposing metrics on port 8080.

The code is currently configured to assume that the name of the rancher stack is "traefik", if it is named otherwise there will be problems with resolving names of containers for reaping ( ToDo: fix this )

# Caveats #

The reaper algorithm is based on the metrics that Traefik reports for activity. If there has been no traffic to a container/service then it will not appear among the metrics. This means that it won't be noticed for the purposes of reaping. Restarting traefik means that metrics for idle narratives will be wiped out, and they won't be reaped. (ToDo: Fix )


