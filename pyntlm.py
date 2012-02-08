#!/usr/bin/env python
#
# PyAuthenNTLM2: A mod-python module for Apache that carries out NTLM authentication
#
# pyntlm.py
#
# Copyright 2011 Legrandin <gooksankoo@hoiptorrow.mailexpire.com>
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
from struct import unpack
from threading import Lock

from mod_python import apache
from ntlm_proxy import NTLM_Proxy
import ldap,ldap.sasl

#
# A connection can be in on the following states when a request arrives:
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
#   req.connection.notes contains the key 'NTLM_AUTHORIZED'. The cache should not
#   contain any tuple under the connection's id.
#
# Since connections may be interrupted before receiving the challenge, objects older
# than 60 seconds are removed from cache when we have the chance.

mutex = Lock()
cache = {}

def parse_ntlm_authenticate(msg):
    '''Parse a Type3 NTLM message (binary form, not encoded in Base64).

    @return a tuple (username, domain)
    '''
    
    NTLMSSP_NEGOTIATE_UNICODE = 0x00000001
    if not msg.startswith('NTLMSSP\x00\x03\x00\x00\x00'):
        return
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

def decode_authorization(auth):
    '''Return the binary NTLM message that was contained in the HTTP Authorization header'''
    ah = auth.split(' ')
    if len(ah)==2:
        if ah[0]=='NTLM':
            return base64.b64decode(ah[1])
            
        elif ah[0]=='Basic':
            return 'basic:%s' %(base64.b64decode(ah[1]))

    return False

def handle_type1(req, ntlm_message):
    '''Handle a Type1 NTLM message. Send it to the Domain Controller
    and get back the challenge (the Type2 NTLM message that is).

    @req            The request that carried the message
    @ntlm_message   The actual Type1 message, in binary format
    '''
    # Cache clean up: everything older than 60 seconds is removed
    now = int(time.time())
    mutex.acquire()
    for id, conn in cache.items():
        if conn[1]+60<now:
            conn[0].close()
            del cache[id]
    mutex.release()

    # Get configuration entries in Apache file
    try:
        domain = req.get_options()['Domain']
        pdc = req.get_options()['PDC']
        bdc = req.get_options().get('BDC', False)
    except Exception, e:
        req.log_error('PYNTLM: Incorrect configuration for pyntlm = %s' % str(e), apache.APLOG_CRIT)
        return apache.HTTP_INTERNAL_SERVER_ERROR
 
    try:
        proxy = NTLM_Proxy(pdc, domain)
        ntlm_challenge = proxy.negotiate(ntlm_message)
    except Exception, e:
        proxy.close()
        req.log_error('PYNTLM: Error when retrieving Type 2 message from PDC(%s) = %s' % (pdc,str(e)), apache.APLOG_CRIT)
        if not bdc:
            return apache.HTTP_SERVICE_UNAVAILABLE
        try:
            proxy = NTLM_Proxy(bdc, domain)
            ntlm_challenge = proxy.negotiate(ntlm_message)
        except Exception, e:
            proxy.close()
            req.log_error('PYNTLM: Error when retrieving Type 2 message BDC(%s) = %s ' % (bdc,str(e)), apache.APLOG_CRIT)
            return apache.HTTP_SERVICE_UNAVAILABLE

    mutex.acquire()
    cache[req.connection.id] = ( proxy, int(time.time()) )
    mutex.release()
    req.err_headers_out.add('WWW-Authenticate', "NTLM " + base64.b64encode(ntlm_challenge))
    return apache.HTTP_UNAUTHORIZED

def handle_type3(req, ntlm_message):
    '''Handle a Type3 NTLM message. Send it to the Domain Controller
    and get back the final authentication outcome.

    @req            The request that carried the message
    @ntlm_message   The actual Type3 message, in binary format
    '''
    
    mutex.acquire()
    proxy = cache[req.connection.id][0]
    mutex.release()
    try:
        user, domain = parse_ntlm_authenticate(ntlm_message)
        result = proxy.authenticate(ntlm_message)
    except Exception, e:
        req.log_error('PYNTLM: Error when retrieving Type 3 message from DC = %s' % str(e), apache.APLOG_CRIT)
        result = False
    mutex.acquire()
    proxy.close()
    if cache.has_key(req.connection.id):
        req.log_error("PYNTLM: Cleaning up cache from connection 0x%X" % req.connection.id, apache.APLOG_DEBUG)
        del cache[req.connection.id]
    mutex.release()
    if result:
        req.log_error('PYNTLM: User %s/%s has been authenticated to access URI %s' % (domain,user,req.unparsed_uri), apache.APLOG_NOTICE)
        req.connection.notes.add('NTLM_AUTHORIZED',user)
        req.user = user
        return apache.OK
    else:
        req.log_error('PYNTLM: User %s/%s at %s failed authentication for URI %s' % (
            domain,user,req.connection.remote_ip,req.unparsed_uri))
        req.err_headers_out.add('WWW-Authenticate', 'NTLM')
        req.err_headers_out.add('Connection', 'close')
        return apache.HTTP_UNAUTHORIZED
    
def handle_basic(req, ntlm_message):
    req.log_error('Handling Basic Authentication for URI %s' % (req.unparsed_uri))
    
    # show the password dialog, retrieve password and user
    ah = ntlm_message.split(':')
    server = req.get_options()['PDC']
    domain = req.get_options()['Domain']
    user = "%s\%s" %(domain,ah[1])
    pw = "%s" %ah[2]
    
    try:
        # open a connection to our LDAP server
        req.log_error('Authenticating %s against %s' %(user,server))
        l = ldap.open(server)
        # attempt to bind to the LDAP server
        l.simple_bind_s(user, pw)
        dn = l.whoami_s()
        l.unbind()
        req.user = user
        return apache.OK

    except ldap.LDAPError,e:
        req.log_error('Basic authentication failure: %s' %(e.message['desc'] if type(e.message) == dict and e.message.has_key('desc') else str(e)))
        return do_challenge(req)
    
def do_challenge(req):
    req.err_headers_out.add('WWW-Authenticate', 'NTLM')
    req.err_headers_out.add('WWW-Authenticate', 'Basic realm="' + req.auth_name() + '"')
    req.err_headers_out.add('Connection', 'close')
    return apache.HTTP_UNAUTHORIZED        

def authenhandler(req):
    '''The request handler called by mod_python in the authentication phase.'''
    req.log_error("PYNTLM: Handling connection 0x%X from address %s for %s URI %s. %d entries in connection cache." % (
        req.connection.id, req.connection.remote_ip,req.method,req.unparsed_uri,len(cache)), apache.APLOG_INFO)

    # Extract Authorization header, as a list (if present)
    auth_headers = req.headers_in.get('Authorization', [])
    if not isinstance(auth_headers, list):
        auth_headers = [ auth_headers ]

    # If this connection is authenticated already, quit immediately with an OK
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
        return do_challenge(req)

    # Extract ntlm_message from any of the Authorization headers
    try:
        for ah in auth_headers:
            ntlm_message = decode_authorization(ah)
            if ntlm_message:
                break
    except:
        ntlm_message = False
    
    if not ntlm_message:
        req.log_error('Error when parsing NTLM Authorization header from address %s and URI %s' % (
        req.connection.remote_ip,req.unparsed_uri), apache.APLOG_ERR)
        return apache.HTTP_BAD_REQUEST

    if ntlm_message.startswith('basic:'):
        return handle_basic(req, ntlm_message)

    if cache.has_key(req.connection.id):
        return handle_type3(req, ntlm_message)
    
    return handle_type1(req, ntlm_message) 

