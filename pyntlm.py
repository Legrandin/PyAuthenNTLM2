#!/usr/bin/env python
#
# PyAuthenNTLM2: A mod-python module for Apache that carries out NTLM authentication
#
# pyntlm.py
#
# Copyright 2011 Legrandin <helderijs@gmail.com>
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
import base64
import time
import urllib
from struct import unpack
from threading import Lock
from binascii import hexlify
from urlparse import urlparse

from mod_python import apache
from PyAuthenNTLM2.ntlm_dc_proxy import NTLM_DC_Proxy
from PyAuthenNTLM2.ntlm_ad_proxy import NTLM_AD_Proxy

use_basic_auth = True
try:
    from PyAuthenNTLM2.ntlm_client import NTLM_Client
except ImportError:
    use_basic_auth = False

#
# A connection can be in one of the following states when a request arrives:
#
# 1 Freshly opened: no authentication step has taken place yet.
#   req.connection.notes does not contain the key 'NTLM_AUTHORIZED' and
#   the cache does not contain any tuple under the connection's id.
#
# 2 Pending authentication: we sent the NTLM challenge to the client, and we 
#   are waiting for the response. req.connection.notes does not contain the
#   the key 'NTLM_AUTHORIZED' but the cache contains one tuple (NTLM_Proxy, timestamp)
#   under the connection's id.
#
# 3 Authenticated: all steps completed successfully. 
#   req.connection.notes contains the key 'NTLM_AUTHORIZED' (username) or
#   'BASIC_AUTHORIZED' (username and a password).
#   The cache should not contain any tuple under the connection's id.
#
# Since connections may be interrupted before receiving the challenge, objects older
# than 60 seconds are removed from cache when we have the chance.

class CacheConnections:

    def __init__(self):
        self._mutex = Lock()
        self._cache = {}

    def __len__(self):
        return len(self._cache)

    def remove(self, id):
        self._mutex.acquire()
        (proxy, ts) = self._cache.get(id, (None,None))
        if proxy:
            proxy.close()
            del self._cache[id]
        self._mutex.release()

    def add(self, id, proxy):
        self._mutex.acquire()
        self._cache[id] = ( proxy, int(time.time()) )
        self._mutex.release()
    
    def clean(self):
        now = int(time.time())
        self._mutex.acquire()
        for id, conn in self._cache.items():
            if conn[1]+60<now:
                conn[0].close()
                del self._cache[id]
        self._mutex.release()

    def has_key(self,id):
        return self._cache.has_key(id)

    def get_proxy(self, id):
        self._mutex.acquire()
        proxy = self._cache[id][0]
        self._mutex.release()
        return proxy

class CacheGroups:

    def __init__(self):
        self._mutex = Lock()
        self._cache = {}

    def __len__(self):
        return len(self._cache)

    def add(self, group, user):
        self._mutex.acquire()
        if not self._cache.has_key(group):
            self._cache[group]={}
        self._cache[group][user]=int(time.time())
        self._mutex.release()
    
    def clean(self):
        now = int(time.time())
        self._mutex.acquire()
        old = []
        for group, members in self._cache.items():
            for user in members:
                if members[user]+3*60*60<now:
                    old.append((group,user))
        for group, user in old:
            del self._cache[group][user]
        self._mutex.release()

    def has(self, group, user):
        if not self._cache.has_key(group):
            return False
        return self._cache[group].has_key(user)

cache = CacheConnections()
cacheGroups = CacheGroups()

def ntlm_message_type(msg):
    if not msg.startswith('NTLMSSP\x00') or len(msg)<12:
        raise RuntimeError("Not a valid NTLM message: '%s'" % hexlify(msg))
    msg_type = unpack('<I', msg[8:8+4])[0]
    if msg_type not in (1,2,3):
        raise RuntimeError("Incorrect NTLM message Type: %d" % msg_type)
    return msg_type

def parse_ntlm_authenticate(msg):
    '''Parse a Type3 NTLM message (binary form, not encoded in Base64).

    @return a tuple (username, domain)
    '''
    
    NTLMSSP_NEGOTIATE_UNICODE = 0x00000001
    idx = 28
    length, offset = unpack('<HxxI', msg[idx:idx+8])
    domain = msg[offset:offset+length]
    idx += 8
    length, offset = unpack('<HxxI', msg[idx:idx+8])
    username = msg[offset:offset+length]
    idx += 24
    flags = unpack('<I', msg[idx:idx+4])[0]
    if flags & NTLMSSP_NEGOTIATE_UNICODE:
        domain = str(domain.decode('utf-16-le'))
        username = str(username.decode('utf-16-le'))
    return username, domain

def set_remote_user(req, username, domain):
    format = req.get_options().get('NameFmt', 'SAM').lower()
    if format=='logon':
        req.user = domain + '\\' + username
    else:
        req.user = username

def decode_http_authorization_header(auth):
    '''Return a tuple with the parsed content of an HTTP Authorization header

    In case of NTLM, the first item is 'NTLM' and the second the Type 1 challenge.
    In case of Basic, the first item is 'Basic', the second the user name,
    and the third the password.

    In case of error, False is returned'''
    ah = auth.split(' ')
    if len(ah)==2:
        b64 = base64.b64decode(ah[1])
        if ah[0]=='NTLM':
            return ('NTLM', b64)
        elif ah[0]=='Basic' and use_basic_auth:
            (user, password) = b64.split(':')
            return ('Basic', user, password)
    return False

def handle_unauthorized(req):
    '''Prepare the correct HTTP headers for a 401 response.

    @return     The Apache return code for 401 response.
    '''

    req.err_headers_out.add('WWW-Authenticate', 'NTLM')
    if use_basic_auth:
        req.err_headers_out.add('WWW-Authenticate', 'Basic realm="%s"' % req.auth_name())
    req.err_headers_out.add('Connection', 'close')
    return apache.HTTP_UNAUTHORIZED

def connect_to_proxy(req, type1):
    '''Try to sequentially connect to all Domain Controllers in the list
    until one is available and can handle the NTLM transaction.

    @return A tuple with a NTLM_Proxy object and a NTLM challenge (Type 2).'''

    # Get configuration entries in Apache file
    try:
        domain = req.get_options()['Domain']
        pdc = req.get_options()['PDC']
        bdc = req.get_options().get('BDC', False)
    except KeyError, e:
        req.log_error('PYNTLM: Incorrect configuration for pyntlm = %s' % str(e), apache.APLOG_CRIT)
        raise
    ntlm_challenge = None
    for server in (pdc, bdc):
        if not server: continue
        try:
            if server.startswith('ldap:'):
                url = urlparse(server)
                decoded_path =urllib.unquote(url.path)[1:]
                req.log_error('PYTNLM: Initiating connection to Active Directory server %s (domain %s) using base DN "%s".' %
                    (url.netloc, domain, decoded_path), apache.APLOG_INFO)
                proxy = NTLM_AD_Proxy(url.netloc, domain, base=decoded_path)
            else:
                req.log_error('PYTNLM: Initiating connection to Domain Controller server %s (domain %s).' %
                    (server, domain), apache.APLOG_INFO)
                proxy = NTLM_DC_Proxy(server, domain)
            ntlm_challenge = proxy.negotiate(type1)
        except Exception, e:
            req.log_error('PYNTLM: Error when retrieving Type 2 message from server(%s) = %s' % (server,str(e)), apache.APLOG_CRIT)
        if ntlm_challenge: break
        proxy.close()
    else:
        raise RuntimeError("None of the Domain Controllers are available.")
    return (proxy, ntlm_challenge)

def handle_type1(req, ntlm_message):
    '''Handle a Type1 NTLM message. Send it to the Domain Controller
    and get back the challenge (the Type2 NTLM message that is).

    @req            The request that carried the message
    @ntlm_message   The actual Type1 message, in binary format
    '''
    cache.remove(req.connection.id)
    cache.clean()

    try:
        (proxy, ntlm_challenge) = connect_to_proxy(req, ntlm_message)
    except Exception, e:
        return apache.HTTP_INTERNAL_SERVER_ERROR

    cache.add(req.connection.id, proxy)
    req.err_headers_out.add('WWW-Authenticate', "NTLM " + base64.b64encode(ntlm_challenge))
    return apache.HTTP_UNAUTHORIZED

def check_authorization(req, username, proxy):
    '''Check if a user that was already authenticated by some previous steps
    is also authorized.

    Authorization is granted depending on the following Apache directives:

    Require valid-user must always be present
    Require user XYZ   authorizes any user named XYZ.
    Require group WER  authorizes any user which is member of the group WER.
                       Group membership is checked at the Active Directory
                       server.
    
    Multiple users and groups can be specified on the same Require line,
    provided they are separated by a comma.

    @req        The request for which authentication was successful.
    @username   Name of the user that has already successfully authenticated (it exists).
                It contains no domain parts.
    @proxy      The proxy that keeps membership data.
    @return     True if the user is authorized, False otherwise.
    '''
   
    rules = ''.join(req.get_options()['Require'])
    if rules=='valid-user' or cacheGroups.has(rules, username):
        return True
    groups = []
    for r in req.requires():
        if r.lower().startswith("user "):
            users = [ u.strip() for u in r[5:].split(",")]
            if username in users:
                req.log_error('PYNTLM: Authorization succeeded for user %s and URI %s.' %
                    (username,req.unparsed_uri), apache.APLOG_INFO)
                return True
        if r.lower().startswith("group "):
            groups += [ g.strip() for g in r[6:].split(",")]

    if groups:
        try:
            res = proxy.check_membership(username, groups)
        except Exception, e:
            req.log_error('PYNTLM: Unexpected error when checking membership of %s in groups %s for URI %s: %s' % (username,str(groups),req.unparsed_uri,str(e)))
        if res:
            #req.log_error('PYNTLM: Groups before %s' % str(cacheGroups._cache))
            cacheGroups.add(rules, username)
            #req.log_error('PYNTLM: Groups after %s' % str(cacheGroups._cache))
            req.log_error('PYNTLM: Membership check succeeded for %s in groups %s for URI %s.' %
                (username,str(groups),req.unparsed_uri), apache.APLOG_INFO)
            return True
        req.log_error('PYNTLM: Membership check failed of %s in groups %s for URI %s.' %
            (username,str(groups),req.unparsed_uri))
    else:
        req.log_error('PYNTLM: Authorization failed for %s and URI %s.' %
            (username,req.unparsed_uri))
    return False

def handle_type3(req, ntlm_message):
    '''Handle a Type3 NTLM message. Send it to the Domain Controller
    and get back the final authentication outcome.

    @req            The request that carried the message
    @ntlm_message   The actual Type3 message, in binary format
    '''
    
    proxy = cache.get_proxy(req.connection.id)
    try:
        user, domain = parse_ntlm_authenticate(ntlm_message)
        if not domain:
            domain = req.get_options().get('Domain', req.auth_name())
        result = proxy.authenticate(ntlm_message)
    except Exception, e:
        req.log_error('PYNTLM: Error when retrieving Type 3 message from server = %s' % str(e), apache.APLOG_CRIT)
        user, domain = 'invalid', 'invalid'
        result = False
    if not result:
        cache.remove(req.connection.id)
        req.log_error('PYNTLM: User %s/%s authentication for URI %s' % (
            domain,user,req.unparsed_uri))
        return handle_unauthorized(req)

    req.log_error('PYNTLM: User %s/%s has been authenticated to access URI %s' % (user,domain,req.unparsed_uri), apache.APLOG_NOTICE)
    set_remote_user(req, user, domain)
    result = check_authorization(req, user, proxy)
    cache.remove(req.connection.id)

    if not result:
        return apache.HTTP_FORBIDDEN

    req.connection.notes.add('NTLM_AUTHORIZED',req.user)
    return apache.OK
    
def handle_basic(req, user, password):
    '''Handle a request authenticated using the Basic Access Authentication
    mechanism (RFC2617).
    '''
    req.log_error('Handling Basic Access Authentication for URI %s' % (req.unparsed_uri))

    domain = req.get_options().get('Domain', req.auth_name())
    client = NTLM_Client(user, domain, password)
    type1 = client.make_ntlm_negotiate()

    try:
        (proxy, type2) = connect_to_proxy(req, type1)
    except Exception, e:
        return apache.HTTP_INTERNAL_SERVER_ERROR
    
    client.parse_ntlm_challenge(type2)
    type3 = client.make_ntlm_authenticate()
    if not proxy.authenticate(type3):
        proxy.close()
        req.log_error('PYNTLM: User %s/%s failed Basic authentication for URI %s' % (
            user,domain,req.unparsed_uri))
        return handle_unauthorized(req)
    
    req.log_error('PYNTLM: User %s/%s has been authenticated (Basic) to access URI %s' % (user,domain,req.unparsed_uri), apache.APLOG_NOTICE)
    set_remote_user(req, user, domain)
    result = check_authorization(req, user, proxy)
    proxy.close()

    if not result:
        return apache.HTTP_FORBIDDEN

    req.connection.notes.add('BASIC_AUTHORIZED', user+password)
    return apache.OK
    
def authenhandler(req):
    '''The request handler called by mod_python in the authentication phase.'''
    req.log_error("PYNTLM: Handling connection 0x%X for %s URI %s. %d entries in connection cache." % (
        req.connection.id, req.method,req.unparsed_uri,len(cache)), apache.APLOG_INFO)

    # Extract Authorization header, as a list (if present)
    auth_headers = req.headers_in.get('Authorization', [])
    if not isinstance(auth_headers, list):
        auth_headers = [ auth_headers ]

    # If this connection was authenticated with NTLM, quit immediately with an OK
    # (unless it comes from IE).
    user = req.connection.notes.get('NTLM_AUTHORIZED', None)
    if user:
        req.user = user
        # Internet Explorer sends a Type 1 authorization request with an empty
        # POST, even if the connection is already authenticated.
        # We don't de-authenticate the user (meaning that we don't remove the
        # NTLM_AUTHORIZED key from connection.notes), but we still let a new
        # challenge-response exchange take place.
        # For other methods, it is acceptable to return OK immediately.
        if  auth_headers:
            req.log_error('PYTNLM: Spurious authentication request on connection 0x%X. Method = %s. Content-Length = %d. Headers = %s' % (
            req.connection.id, req.method, req.clength, auth_headers), apache.APLOG_INFO)
            if req.method!='POST' or req.clength>0:
                return apache.OK
        else:
            return apache.OK
    
    # If there is no Authorization header it means it is the first request.
    # We reject it with a 401, indicating which authentication protocol we understand.
    if not auth_headers:
        return handle_unauthorized(req)

    # Extract authentication data from any of the Authorization headers
    try:
        for ah in auth_headers:
            ah_data = decode_http_authorization_header(ah)
            if ah_data:
                break
    except:
        ah_data = False
    
    if not ah_data:
        req.log_error('Error when parsing Authorization header for URI %s' % req.unparsed_uri, apache.APLOG_ERR)
        return apache.HTTP_BAD_REQUEST

    if ah_data[0]=='Basic':
        # If this connection was authenticated with Basic, verify that the
        # credentials match and return 200 (if they do) or 401 (if they
        # don't). We don't need to actually query the DC for that.
        userpwd = req.connection.notes.get('BASIC_AUTHORIZED', None)
        if userpwd:
            if userpwd != ah_data[1]+ah_data[2]:
                return handle_unauthorized(req)
            domain = req.get_options().get('Domain', req.auth_name())
            set_remote_user(req, ah_data[1], domain)
            return apache.OK
        # Connection was not authenticated before
        return handle_basic(req, ah_data[1], ah_data[2])

    # If we get here it means that there is an Authorization header, with an
    # NTLM message in it. Moreover, the connection needs to be (re)authenticated.
    # Most likely, the NTLM message is of:
    # - Type 1 (and there is nothing in the cache): the client wants to
    #   authenticate for the first time,
    # - Type 3 (and there is something in the cache): the client wants to finalize
    #   a pending authentication request.
    #
    # However, it could still be that there is a Type 3 and nothing in the
    # cache (the final client message was erroneously routed to a new connection),
    # or that there is a Type 1 with something in the cache (the client wants to
    # initiate an cancel a pending authentication).

    try:
        ntlm_version = ntlm_message_type(ah_data[1])
        if ntlm_version==1:
            return handle_type1(req, ah_data[1]) 
        if ntlm_version==3:
            if cache.has_key(req.connection.id):
                return handle_type3(req, ah_data[1])
            req.log_error('Unexpected NTLM message Type 3 in new connection for URI %s' %
                (req.unparsed_uri), apache.APLOG_INFO)
            return handle_unauthorized(req)
        error = 'Type 2 message in client request'
    except Exception, e:
        error = str(e)
    req.log_error('Incorrect NTLM message in Authorization header for URI %s: %s' %
            (req.unparsed_uri,error), apache.APLOG_ERR)
    return apache.HTTP_BAD_REQUEST

