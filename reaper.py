import requests
import docker
import time
import re
import os
import signal

# Setup default configuration values, overriden by values from os.environ later
cfg = {"docker_url": "unix://var/run/docker.sock",
       "narr_img": "kbase/narrative:latest",
       "container_prefix": "narrative",
       "traefik_metrics": "http://localhost:8080/metrics",
       "timeout_secs": 600,
       "sleep": 30,
       "debug": 0}

for cfg_item in cfg.keys():
    if cfg_item in os.environ:
        cfg[cfg_item] = os.environ[cfg_item]

client = docker.DockerClient(base_url=cfg['docker_url'])


def reap_narrative(container_name):
    try:
        killit = client.containers.get(container_name)
        killit.stop()
    except docker.errors.NotFound:
        print("Container not found - may have been reaped already")
    except Exception as e:
        raise(e)  # Unhandled exception, rethrow
    return


def get_active_traefik_svcs():
    try:
        r = requests.get(cfg['traefik_metrics'])
        if r.status_code == 200:
            narr_activity = dict()
            body = r.text.split("\n")
            service_conn = [line for line in body if "traefik_service_open_connections{" in line]
            service_websocket_open = [line for line in service_conn if "protocol=\"websocket\"" in line]
            # Containers is a dictionary keyed on container name with the value as the # of active web sockets
            containers = dict()
            for line in service_websocket_open:
                if cfg['debug']:
                    print("websocket line:", line)
                matches = re.search(r"service=\"(\S+)@.+ (\d+)", line)
                containers[matches.group(1)] = int(matches.group(2))
            for name in containers.keys():
                # Skip any containers that don't match the container prefix, to avoid wasting time on the wrong containers
                if name.startswith(cfg['container_prefix']):
                    try:
                        svc_container = client.containers.get(name)
                    except docker.errors.NotFound:
                        print("Service {} not found (might be part of core stack or reaped already)".format(name))
                        continue
                    # Filter out any container that isn't the image type we are reaping
                    if (cfg['narr_img'] in svc_container.image.attrs["RepoTags"]):
                        # only update timestamp if the container has active websockets or this is the first
                        # time we've seen it
                        if (containers[name] > 0) or (name not in containers):
                            narr_activity[name] = time.time()
                            if cfg['debug']:
                                print("Updated timestamp for "+name)
                    else:
                        if cfg['debug']:
                            print("Skipping because {} not in {}".format(cfg['narr_img'], svc_container.image.attrs['RepoTags']))
                else:
                    if cfg['debug']:
                        print("Skipped {} because it didn't match prefix {}".format(name, cfg['container_prefix']))
            return(narr_activity)
        else:
            raise(Exception("Error querying {}:{} {}".format(cfg['traefik_metrics'], r.status_code, r.text)))
    except Exception as e:
        raise(e)


def reaper_loop(narr_activity):
    """ Main loop that checks the narrative state and reaps containers that have been abandoned for too long """
    while True:
        try:
            narr_activity.update(get_active_traefik_svcs())
        except Exception as e:
            print("ERROR: {}".format(repr(e)))
            continue
        now = time.time()
        for name, timestamp in narr_activity.items():
            if (now - timestamp) > cfg['timeout_secs']:
                msg = "Container {} has been inactive longer than {}. Reaping.".format(name, cfg['timeout_secs'])
                print(msg)
                try:
                    reap_narrative(name)
                    del narr_activity[name]
                except Exception as e:
                    print("Error: Unhandled exception while trying to reap container {}: {}".format(name, repr(e)))
        time.sleep(cfg['sleep'])


if __name__ == '__main__':
    print("Starting narrative reaper with {} seconds timeout and {} seconds sleep interval\n".format(cfg["timeout_secs"], cfg["sleep"]))
    narr_activity = dict()
    # Allow the USR1 signal to be used to dump the narrative status dictionary

    def narr_status(signalNumber, frame):
        print("Current time: {}".format(time.asctime()))
        for container in narr_activity.keys():
            print("  {} last activity at {}".format(container, time.asctime(time.localtime(narr_activity[container]))))

    signal.signal(signal.SIGUSR1, narr_status)

    reaper_loop(narr_activity)
