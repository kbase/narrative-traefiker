import requests
import time
import re
import os
import signal
import manage_rancher
import manage_docker
import logging


# Setup default configuration values, overriden by values from os.environ later
cfg = {"docker_url": "unix://var/run/docker.sock",
       "narr_img": "kbase/narrative:latest",
       "container_prefix": "narrative",
       "traefik_metrics": "http://traefik:8080/metrics",
       "timeout_secs": 600,
       "sleep": 30,
       "debug": 0,
       "mode": None,
       "rancher_user": None,
       "rancher_password": None,
       "rancher_url": None,
       "rancher_meta": "http://rancher-metadata/",
       "rancher_env_url": None,
       "rancher_stack_id": None}

for cfg_item in cfg.keys():
    if cfg_item in os.environ:
        cfg[cfg_item] = os.environ[cfg_item]


def get_active_traefik_svcs(narr_activity):
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
                if cfg['debug']:
                    print("websocket line:", line)
                matches = re.search(r"service=\"(\S+)@.+ (\d+)", line)
                containers[matches.group(1)] = int(matches.group(2))
            if cfg['debug']:
                print("Looking for containers that with name prefix {} and image name {}".format(cfg['container_prefix'], cfg['narr_img']))
            for name in containers.keys():
                if cfg['debug']:
                    print("Examing container: {}".format(name))
                # Skip any containers that don't match the container prefix, to avoid wasting time on the wrong containers
                if name.startswith(cfg['container_prefix']):
                    if cfg['debug']:
                        print("Matches prefix")
                    image_name = find_image(name)
                    # Filter out any container that isn't the image type we are reaping
                    if (cfg['narr_img'] in image_name):
                        if cfg['debug']:
                            print("Matches image name")
                        # only update timestamp if the container has active websockets or this is the first
                        # time we've seen it
                        if (containers[name] > 0) or (name not in narr_activity):
                            narr_activity[name] = time.time()
                            if cfg['debug']:
                                print("Updated timestamp for "+name)
                    else:
                        if cfg['debug']:
                            print("Skipping because {} not in {}".format(cfg['narr_img'], image_name))
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
    if cfg['mode'] == 'docker':
        reap_narrative = manage_docker.reap_narrative
    elif cfg['mode'] == 'rancher':
        reap_narrative = manage_rancher.reap_narrative
    else:
        raise RuntimeError('Unknown orchestration mode: {}'.format(cfg['mode']))

    def narr_status(signalNumber, frame):
        print("Current time: {}".format(time.asctime()))
        for container in narr_activity.keys():
            print("  {} last activity at {}".format(container, time.asctime(time.localtime(narr_activity[container]))))

    signal.signal(signal.SIGUSR1, narr_status)

    while True:
        try:
            newtimestamps = get_active_traefik_svcs(narr_activity)
            narr_activity.update(newtimestamps)
        except Exception as e:
            print("ERROR: {}".format(repr(e)))
            continue
        now = time.time()
        reap_list = [name for name, timestamp in narr_activity.items() if (now - timestamp) > cfg['timeout_secs']]

        for name in reap_list:
            msg = "Container {} has been inactive longer than {}. Reaping.".format(name, cfg['timeout_secs'])
            print(msg)
            try:
                reap_narrative(name)
            except Exception as e:
                print("Error: Unhandled exception while trying to reap container {}: {}".format(name, repr(e)))
        time.sleep(cfg['sleep'])


if __name__ == '__main__':
    if (cfg["rancher_url"] is not None):
        cfg['mode'] = "rancher"
        manage_rancher.setup(cfg, logging.getLogger())
        manage_rancher.verify_config(cfg)
    else:
        cfg['mode'] = "docker"
        manage_docker.setup(cfg, logging.getLogger())
        manage_docker.verify_config(cfg)
    print("Starting narrative reaper with {} seconds timeout and {} seconds sleep interval".format(cfg["timeout_secs"], cfg["sleep"]))
    print("Send this process a SIGUSR1 to output the contents of the reaper timestamps")
    narr_activity = dict()
    # Allow the USR1 signal to be used to dump the narrative status dictionary

    reaper_loop(narr_activity)
