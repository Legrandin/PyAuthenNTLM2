#!/usr/bin/env python
#
# PyAuthenNTLM2: A mod-python module for Apache that carries out NTLM authentication
#
# ntlm_ad_proxy.py
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

import socket
from gssapi import *
from ntlm_proxy import NTLM_Proxy

class LDAP_Parse_Exception(Exception):
    pass

class LDAP_Context:
    # resultCode
    LDAP_Result_success             = 0
    LDAP_Result_saslBindInProgress  = 14

    # scope in SearchRequest
    Scope_baseObject                = 0
    Scope_singleLevel               = 1
    Scope_wholeSubtree              = 2

    # Minimum amount of data to peek from TCP stream, to know
    # how long the LDAPMessage is
    minimumData = 6

    def __init__(self):
        self.messageID = 0

    def getTransportLength(self, berHeader):
        (length, pstart) = parselen(berHeader)
        return length+pstart-self.minimumData

    # Negotiation is not necessary
    def make_negotiate_protocol_req(self):
        pass

    def make_session_setup_req(self, ntlm_token, type1=True):
        """Create an LDAP bind request, that can be sent to the AD server."""
        
        credentials = makeoctstr(make_token(ntlm_token, type1))
        # authentication has CONTEXT IMPLICIT tag [3] for constructed type (SEQUENCE)
        authentication = maketlv('\xA3', makeoctstr('GSS-SPNEGO') + credentials)
        # BindRequest has APPLICATION IMPLICIT tag [0] for constructed type (SEQUENCE)
        bindRequest = maketlv('\x60', makeint(3) + makeoctstr('') + authentication)
        # LDAPMessage
        self.messageID += 1
        return makeseq(makeint(self.messageID) + bindRequest)

    def parse_session_setup_resp(self, response):
        """Parse an LDAP bind response."""
        
        # LDAPMessage
        data = parseseq(response)
        messageID, data = parseint(data, True)
        if messageID!=self.messageID:
            raise LDAP_Parse_Exception("Unexpected MessageID: %d" % messageID)
        # BindResponse has APPLICATION IMPLICIT tag [1] for constructed type (SEQUENCE)
        data = parsetlv('\x61', data)
        # LDAPResult components
        resultCode, data = parseenum(data, True)
        matchedDN, data = parseoctstr(data, True)
        diagnosticMessage, data = parseoctstr(data, True)
        # Assume no referral !
        if resultCode==self.LDAP_Result_success:
            return (True, '')
        if resultCode!=self.LDAP_Result_saslBindInProgress:
            raise LDAP_Parse_Exception(diagnosticMessage)
        # SASL credentials has CONTEXT IMPLICIT tag [7] for primitive type (OCTET STRING)
        serverSaslCreds = parsetlv('\x87', data)
        return (True, extract_token(serverSaslCreds))

    def make_search_req(self, base, criteria, attributes):
        """Create an LDAP search request that can be sent to the AD server.
         
         @base          The DN to start the search from.
         @criteria      A dictionary with the attributes to look for (must be one only for now)
         @attributes    A list of attributes to return.
         @return        The LDAP request to send to the AD server.
        """

        assert(len(criteria)==1)

        # AttributeSelection
        ldapattributes = makeseq(''.join([makeoctstr(x) for x in attributes]))
        # Filter is a choice with CONTEXT IMPLICIT tags
        # Here we only use equalityMatch which has tag [3] for constructured type (SEQUENCE)
        ldapfilter = maketlv('\xA3', makeoctstr(criteria.keys()[0]) + makeoctstr(criteria.values()[0]))
        # SearchRequest has APPLICATION IMPLICIT tag [3] for constructed type (SEQUENCE)
        searchRequest = maketlv('\x63', makeoctstr(base) + makeenum(self.Scope_wholeSubtree) +
            makeenum(3) + makeint(0) + makeint(0) + makebool(False) + ldapfilter + ldapattributes)
        # LDAPMessage
        self.messageID += 1
        return makeseq(makeint(self.messageID) + searchRequest)

    def parse_search_resp(self, response):
        """Parse an LDAP search response received from the AD server.
        
        @return         A tuple (True, string) if the search is complete.
                        A tuple (False, objectName, attributes) where objectName is a DN, and
                        attributes is a dictionary of lists. In attributes, the key is the
                        attribute name; the list contain all the values for such attribute.
        """

        # LDAPMessage
        data = parseseq(response)
        messageID, data = parseint(data, True)
        if messageID!=self.messageID:
            raise LDAP_Parse_Exception("Unexpected MessageID: %d" % messageID)
        # SearchResultDone has APPLICATION IMPLICIT tag [5] for primitive type (OCTET STRING)
        if data[0]=='\x65':
            data = parsetlv('\x65', data)
            resultCode, data = parseenum(data, True)
            matchedDN, data = parseoctstr(data, True)
            diagnosticMessage, data = parseoctstr(data, True)
            print "Finished search results. Code %d. Message: %s." % (resultCode, diagnosticMessage)
            return (True, diagnosticMessage)
        # SearchResultReference has APPLICATION IMPLICIT tag [19] for constructed type (SEQUENCE)
        if data[0]=='\x73':
            data = parsetlv('\x73', data)
            while data:
                uri, data = parseoctstr(data, True)
                print "URI", uri
            return (True, None, {})
        # SearchResultEntry has APPLICATION IMPLICIT tag [4] for constructed type (SEQUENCE)
        data = parsetlv('\x64', data)

        attributes = {}
        objectName, data = parseoctstr(data, True)
        attributelist = parseseq(data)
        #import pdb; pdb.set_trace()
        while attributelist:
            # Payload of a PartialAttribute
            partattr, attributelist = parseseq(attributelist, True)
            # Attribute name
            attrtype, attributesdata = parseoctstr(partattr, True)
            attributes[attrtype] = []
            # Attribute values
            attrvalues = parseset(attributesdata)
            while attrvalues:
                value, attrvalues = parseoctstr(attrvalues, True)
                attributes[attrtype].append(value)
        return (False, objectName, attributes)

class NTLM_AD_Proxy(NTLM_Proxy):
    """This is a class that handles one single NTLM authentication request like it was
    a domain controller. However, it is just a proxy for the real, remote DC.
    """
    _portad = 389

    def __init__(self, ipad, domain, socketFactory=socket, ldapFactory=None):
        print "OOO", ipad
        NTLM_Proxy.__init__(self, ipad, self._portad, domain, lambda: LDAP_Context(), socketFactory)
        #self.smbFactory =  smbFactory or (lambda: SMB_Context())

    def check_membership(self, user, group, base):
        """Check if the given user belong to the given group.

        @user   The sAMAccountName attribute of the user
        @group  The sAMAccountName attribute of the group
        @base   The basis DN for the search
        @return True if the user belongs to the group, False otherwise.
        """

        if (user==group):
            return True
        result = {}
        msg = self.proto.make_search_req(base, { 'sAMAccountName':user }, ['sAMAccountName','memberOf'])
        msg = self._transaction(msg)
        while True:
            resp = self.proto.parse_search_resp(msg)
            if resp[0]:
                break
            if resp[1]:
                result[resp[1]] = resp[2]
            msg = self._transaction('')
        print result

