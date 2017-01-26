#!/usr/bin/env python3

import datetime
import time
import logging
import json
import urllib.request
import pickle
import signal

configFile = '/etc/pdns/keyroller.ini'

config = {
    'loglevel': 'debug',
    'pdns_url': 'http://127.0.0.1:8084/api/v1/servers/localhost',
    'timeout': 2,
    'statefile': '/var/lib/pdns/keyroller.state',
    'api-key': 'secret',
    'domains': [],
}

status = {}

def loadState():
    pass

"""Will do an HTTP request to the url (optionally with headers and/or data)
and will return the response"""
def sendRequest(url, headers={}, data = None):
    headers.update({ 'X-Api-Key': config['api-key'] })
    requestUrl = '{}{}'.format(config['pdns_url'], url)
    request = urllib.request.Request(requestUrl, data=data, headers=headers)
    try:
        logging.debug("Sending {} request to {} ".format(
            request.get_method(), request.get_full_url()))
        response = urllib.request.urlopen(request, timeout=2)
    except urllib.request.URLError as e:
        logging.error("Unable to fetch {}: {}".format(
            requestUrl, e.reason))
        raise

    stringResp = response.read()
    logging.debug('Got response: {}'.format(stringResp))
    return stringResp

def parseConfig():
    global config
    newConfig = config.copy()

    # XXX load the new config and store into newConfig

    loglevel = getattr(logging, newConfig['loglevel'].upper(), None)
    if not isinstance(loglevel, int):
        logging.basicConfig(level=logging.WARNING)
        logging.warning(
            '{} is not a valid loglevel, setting to warning'.format(
                newConfig['loglevel']))
        loglevel = logging.WARNING

    newConfig['loglevel'] = loglevel
    logging.basicConfig(level=newConfig['loglevel'])
    config = newConfig

def getKeysForDomain(domain):
    url = '/zones/{}/cryptokeys'.format(domain)
    try:
        response = sendRequest(url)
    except urllib.request.URLError as e:
        return []

    return(json.loads(response))

def saveState():
    with open(config['statefile'], 'rw') as f:
        newState = pickle.dump(state, f)

def loadState():
    newState = {}
    try:
        with open(config['statefile']) as f:
            newState = pickle.load(f)
    except FileNotFoundError as e:
        logging.info('State file ({}) not found'.format(config['statefile']))
        return
    state = newState.copy()

def signalHandler(signum, frame):
    if signum in [signal.SIGINT, signal.SIGTERM]:
        saveState()
        sys.exit(0)
    if signum == signal.SIGHUP:
        parseConfig()
        return
    return

signal.signal(signal.SIGINT, signalHandler)
signal.signal(signal.SIGTERM, signalHandler)
signal.signal(signal.SIGHUP, signalHandler)

parseConfig()
loadState()

while(True):
    now = datetime.datetime.now()
    workDomains = []
    for domain in config['domains']:
        domainStatus = status.get(domain)
        if not domainStatus:
            domainStatus = makeDomainStatus(domain)
        if domainStatus['actionDatetime'] >= now:
            workDomains.append(domain)
