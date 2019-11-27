import requests
import os
import pprint

# This config was derived from examining the network traffic between the rancher GUI and the rancher service
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
                            u'traefik.enable': u'True',
                            u'traefik.http.routers.sychan.entrypoints': u'web',
                            u'traefik.http.routers.sychan.rule': u'Host("logstashanl.chicago.kbase.us") && PathPrefix("/narrative/") && HeadersRegexp("Cookie","narrative_session=BloMDyc1EX9VrnqHpJ9sWg==")'},
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
                    u'name': u'narrative-sychan',
                    u'removed': None,
                    u'scale': 1,
                    u'secondaryLaunchConfigs': [],
                    u'selectorContainer': None,
                    u'selectorLink': None,
                    u'stackId': u'1st795',
                    u'startOnCreate': True,
                    u'type': u'service',
                    u'uuid': None,
                    u'vip': None}

username = os.environ["rancher_user"]
password = os.environ['rancher_password']
rancher_url = os.environ.get("rancher_url", "https://rancher.berkeley.kbase.us/v2-beta/")
rancher_meta = "http://rancher-metadata/"


def find_stack():
    """
    Query the rancher-metadata service for the name of the stack we're running in, and then
    go to the rancher_url and walk down through the stacks in the rancher environments we
    have access to that find the the endpoint that matches the name
    """
    r = requests.get(rancher_meta+"2016-07-29/self/stack/environment_name")
    env_name = r.text
    r = requests.get(rancher_meta+"2016-07-29/self/stack/name")
    stack_name = r.text
    r = requests.get(rancher_url+"projects", auth=(username, password))
    resp = r.json()
    x = [env['links']['self'] for env in resp['data'] if env['name'].lower() == env_name.lower()]
    env_endpoint = x[0]
    print("Found environment endpoint: {}".format(env_endpoint))
    r = requests.get(env_endpoint+"/stacks", auth=(username, password))
    resp = r.json()
    x = [stack['id'] for stack in resp['data'] if stack['name'].lower() == stack_name.lower()]
    print("Found stack id: {}".format(x[0]))
    return({"url": env_endpoint, "stack_id": x[0]})


endpoint_info = find_stack()
container_config['stackId'] = endpoint_info['stack_id']
endpoint_url = endpoint_info['url']
response = requests.post(endpoint_url+"/service", json=container_config, auth=(username, password))

pprint.pprint(response.json())
