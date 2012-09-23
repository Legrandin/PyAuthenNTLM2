#!/usr/bin/python
#
# PyAuthenNTLM2: A mod-python module for Apache that carries out NTLM authentication
#
# http_client.py
#
# Copyright 2012 Legrandin <helderijs@gmail.com>
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
# http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

import sys
import time
import getopt
import base64
from PyAuthenNTLM2.ntlm_client import NTLM_Client
import httplib
import urlparse

def print_help():
    print
    print "Perform an authenticated HTTP GET request. Basic Authentication or NTLM can be used."
    print "http_client {-u|--user} usr {-p|--password} pwd [{-d|--domain} DOMAIN] URL"
    print
    print "If the -d option is not provided, use Basic. If it is, use NTLM" 
    sys.exit(-1)

headers = {}
conn = None

def basic_request(url, user, password, reuse=False):
    global conn, headers

    if not url.startswith('http'):
        url = '//' + url
    (scheme, hostport, path, params, query, frag ) = urlparse.urlparse(url)

    if conn and not reuse:
        conn.close()
    if not conn or not reuse:
        conn = httplib.HTTPConnection(hostport)
    if reuse:
        headers['Connection'] = 'Keep-alive'
    else:
        if 'Connection' in headers:
            del headers['Connection']

    conn.request('GET',path,None,headers)
    resp = conn.getresponse()
    resp.read()
    if resp.status<400:
        return 'Authorization' in headers
    if resp.status!=401:
        print "Error in HTTP request", resp.status, resp.reason
        return False
    if 'basic' not in resp.getheader('WWW-Authenticate').lower():
        print "Basic Authentication is not supported"
        return False
    conn.close()

    # Process 401
    conn = httplib.HTTPConnection(hostport)
    auth = "Basic " + base64.b64encode(user+':'+password)
    headers = { 'Authorization' : auth }
    conn.request('GET',path,None,headers)
    resp = conn.getresponse()
    resp.read()
    if not resp.status<400:
        print "Failed authentication for HTTP request", resp.status, resp.reason
        return False
    if not reuse:
        conn.close()
        conn = False
    return True

def ntlm_request(url, user, password, domain):
    
    if not url.startswith('http'):
        url = '//' + url
    (scheme, hostport, path, params, query, frag ) = urlparse.urlparse(url)

    conn = httplib.HTTPConnection(hostport)

    conn.request('GET',path)
    resp = conn.getresponse()
    resp.read()
    if resp.status<400:
        return 'Authorization' in headers
    if resp.status!=401:
        print "Error in HTTP request", resp.status, resp.reason
        return False
    if 'ntlm' not in resp.getheader('WWW-Authenticate').lower():
        print "NTLM Authentication is not supported"
        return False
    conn.close()
    
    # Process 401
    conn = httplib.HTTPConnection(hostport)
    client = NTLM_Client(user, domain, password)

    type1 = client.make_ntlm_negotiate()
    auth = "NTLM " + base64.b64encode(type1)
    headers = { 'Authorization' : auth }
    conn.request('GET',path,None,headers)
    resp = conn.getresponse()
    resp.read()
    if resp.status!=401:
        print "First round NTLM authentication for HTTP request failed", resp.status, resp.reason
        return False

    # Extract Type2, respond to challenge
    type2 = base64.b64decode(resp.getheader('WWW-Authenticate').split(' ')[1])
    client.parse_ntlm_challenge(type2)
    type3 = client.make_ntlm_authenticate()

    auth = "NTLM " + base64.b64encode(type3)
    headers = { 'Authorization' : auth }
    conn.request('GET',path,None,headers)
    resp = conn.getresponse()
    resp.read()
    if resp.status>=400:
        print "Second round NTLM authentication for HTTP request failed", resp.status, resp.reason
        return False

    return True

if __name__ == '__main__':
    config = dict()

    if len(sys.argv)<2:
        print_help()

    try:
        options, remain = getopt.getopt(sys.argv[1:],'hu:p:d:',['help', 'user=', 'password=', 'domain='])
    except getopt.GetoptError, err:
        print err.msg
        print_help()
    if not remain or len(remain)!=1:
        print "You must provide only one URL."
        print_help()
    else:
        url = remain[0]

    for o, v in options: 
        if o in ['-h', '--help']:
            print_help()
        elif o in ['-u', '--user']:
            config['user'] = v
        elif o in ['-p', '--password']:
            config['password'] = v
        elif o in ['-d', '--domain']:
            config['domain'] = v

    if len(config)==2:
        if 'user' in config and 'password' in config:
            config['scheme']='Basic'
        else:
            print 'For Basic authentication, specify only -u and -p\n\n'
            print_help()
    else:
        if len(config)!=3:
            print "Incorrect number of options specified."
            print_help()
        else:
            config['scheme']='NTLM'

    try:
        success = True
        if config['scheme']=='Basic':
            for reuse in (False, True, True, False):
                success &= basic_request(url, config['user'], config['password'], reuse)
                if not success: break
        else:
            for x in xrange(1,3):
                success &= ntlm_request(url, config['user'], config['password'], config['domain'])
                if not success: break
        if success:
            print "OK"
        else:
            print "Authentication failed"

    except IOError, e:
        print e

