#!/usr/bin/env python
#
# PyAuthenNTLM2: A mod-python module for Apache that carries out NTLM authentication
#
# ntlm_ad_proxy.py
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

import socket
from gssapi import *
from ntlm_proxy import NTLM_Proxy, NTLM_Proxy_Exception

class LDAP_Parse_Exception(Exception):
    pass

class LDAP_Context:
    # resultCode
    LDAP_Result_success             = 0
    LDAP_Result_saslBindInProgress  = 14

    result_description = {
        0 : 'success',
        1 : 'operationsError',
        2 : 'protocolError',
        3 : 'timeLimitExceeded',
        4 : 'sizeLimitExceeded',
        5 : 'compareFalse',
        6 : 'compareTrue',
        7 : 'authMethodNotSupported',
        8 : 'strongerAuthRequired',
        10 : 'referral - wrong base DN?',
        11 : 'adminLimitExceeded',
        12 : 'unavailableCriticalExtension',
        13 : 'confidentialityRequired',
        14 : 'saslBindInProgress',
        16 : 'noSuchAttribute',
        17 : 'undefinedAttributeType',
        18 : 'inappropriateMatching',
        19 : 'constraintViolation',
        20 : 'attributeOrValueExists',
        21 : 'invalidAttributeSyntax',
        32 : 'noSuchObject',
        33 : 'aliasProblem',
        34 : 'invalidDNSSyntax',
        36 : 'aliasDereferencingProblem',
        48 : 'inappropriateAuthentication',
        49 : 'invalidCredentials',
        50 : 'insufficientAccessRights',
        51 : 'busy',
        52 : 'unavailable',
        53 : 'unwillingToPerform',
        54 : 'loopDetect',
        64 : 'namingViolation',
        65 : 'objectClassViolation',
        66 : 'notAllowedOnNonLeaf',
        67 : 'notAllowedOnRDN',
        68 : 'entryAlreadyExists',
        69 : 'objectClassProhibited',
        71 : 'affectsMultipleDSAs',
        80 : 'other',
    }

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
        """Create an LDAP bind request that can be sent to the AD server.

        @ntlm_token     The NTLM message
        @type1          True for Type 1, False for Type 3
        @return         The LDAP request
        """

        credentials = makeoctstr(make_token(ntlm_token, type1))
        # authentication has CONTEXT IMPLICIT tag [3] for constructed type (SEQUENCE)
        authentication = maketlv('\xA3', makeoctstr('GSS-SPNEGO') + credentials)
        # BindRequest has APPLICATION IMPLICIT tag [0] for constructed type (SEQUENCE)
        bindRequest = maketlv('\x60', makeint(3) + makeoctstr('') + authentication)
        # LDAPMessage
        self.messageID += 1
        return makeseq(makeint(self.messageID) + bindRequest)

    def parse_session_setup_resp(self, response):
        """Parse the LDAP bind response, as received from the AD.
        
        @response       The LDAP response received from the AD
        @return         A tuple where:
                          - the 1st item is a boolean. If False the user
                            is not authenticated
                          - the 2nd item is the NTLM Message2 (1st respone)
                            or is empty (2nd response)
        """

        # LDAPMessage
        data = parseseq(response)
        messageID, data = parseint(data, True)
        if messageID!=self.messageID:
            raise LDAP_Parse_Exception("Unexpected MessageID: %d instead of %d" % (messageID, self.messageID))
        # BindResponse has APPLICATION IMPLICIT tag [1] for constructed type (SEQUENCE)
        data, controls = parsetlv('\x61', data, True)
        # LDAPResult components
        resultCode, data = parseenum(data, True)
        matchedDN, data = parseoctstr(data, True)
        diagnosticMessage, data = parseoctstr(data, True)
        # Assume no referral !
        if resultCode==self.LDAP_Result_success:
            return (True, '')
        if resultCode!=self.LDAP_Result_saslBindInProgress:
            return (False, '')
        # SASL credentials has CONTEXT IMPLICIT tag [7] for primitive type (OCTET STRING)
        serverSaslCreds = parsetlv('\x87', data)
        return (True, extract_token(serverSaslCreds))

    def make_search_req(self, base, criteria, attributes):
        """Create an LDAP search request that can be sent to the AD server.
         
         @base          The DN to start the search from.
         @criteria      A dictionary with the attributes to look for (zero or one object for now)
         @attributes    A list of attributes to return.
         @return        The LDAP request to send to the AD server.
        """

        assert(len(criteria)<=1)

        # AttributeSelection
        ldapattributes = makeseq(''.join([makeoctstr(x) for x in attributes]))
        # Filter is a choice with CONTEXT IMPLICIT tags
        if criteria:
            # equalityMatch has tag [3] for constructured type (SEQUENCE)
            ldapfilter = maketlv('\xA3', makeoctstr(criteria.keys()[0]) + makeoctstr(criteria.values()[0]))
        else:
            # present has tag [7] for primitive type (OCTET STRING)
            ldapfilter = maketlv('\x87', 'objectClass')
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
            raise LDAP_Parse_Exception("Unexpected MessageID: %d instead of %d" % (messageID, self.messageID))
        # SearchResultDone has APPLICATION IMPLICIT tag [5] for primitive type (OCTET STRING)
        if data[0]=='\x65':
            data, controls = parsetlv('\x65', data, True)
            resultCode, data = parseenum(data, True)
            matchedDN, data = parseoctstr(data, True)
            diagnosticMessage, data = parseoctstr(data, True)
            if resultCode:
                import re
                rd = self.result_description.get(resultCode, "unknown")
                raise NTLM_Proxy_Exception("Failed search. Code %d (%s). Message: %s." %
                    (resultCode, rd, re.sub(r'[\x00-\x1F]','',diagnosticMessage)))
            return (True, diagnosticMessage)
        # SearchResultReference has APPLICATION IMPLICIT tag [19] for constructed type (SEQUENCE)
        if data[0]=='\x73':
            return (False, None, {})
        # SearchResultEntry has APPLICATION IMPLICIT tag [4] for constructed type (SEQUENCE)
        data, controls = parsetlv('\x64', data, True)

        attributes = {}
        objectName, data = parseoctstr(data, True)
        attributelist = parseseq(data)
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

    def __init__(self, ipad, domain, socketFactory=socket, ldapFactory=None, base='', verbose=False):
        global debug
        NTLM_Proxy.__init__(self, ipad, self._portad, domain, lambda: LDAP_Context(), socketFactory)
        self.base = base
        self.debug = verbose
        #self.smbFactory =  smbFactory or (lambda: SMB_Context())

    def check_membership(self, user, groups, base=None, tabs=0):
        """Check if the given user belong to ANY of the given groups.

        @user   The sAMAccountName attribute of the user
        @group  A list of sAMAccountName attributes (one per group)
        @base   The basis DN for the search (if not specificed, the default one is used)
        @return True if the user belongs to the group, False otherwise.
        """

        dn = base or self.base
        if user:
            if self.debug: print '\t'*tabs + "Checking if user %s belongs to group %s (base=%s)" % (user,groups,base)
            msg = self.proto.make_search_req(dn, { 'sAMAccountName':user }, ['memberOf','sAMAccountName'])
        else:
            if self.debug: print '\t'*tabs + "Checking if group %s is a sub-group of %s" % (groups,base)
            msg = self.proto.make_search_req(dn, {}, ['memberOf','sAMAccountName'])
        msg = self._transaction(msg)
        
        result = {}
        while True:
            resp = self.proto.parse_search_resp(msg)
            # Search is complete
            if resp[0]:
                break
            # Partial result, search is still ongoing
            if resp[1]:
                result[resp[1]] = resp[2]
            msg = self._transaction('')
        
        if result:
            assert(len(result)==1)
            if self.debug: print '\t'*tabs + "Found entry sAMAccountName:", result.values()[0]['sAMAccountName']
            for g in groups:
                if g in result.values()[0]['sAMAccountName']:
                 return True
            # Cycle through all the DNs of the groups this user/group belongs to
            topgroups = result.values()[0].get('memberOf', {})
            for x in topgroups:
                if self.check_membership(None,groups,x, tabs+1):
                    if self.debug: print '\t'*tabs + "sAMAccountName:", result.values()[0]['sAMAccountName'],"yield a match."
                    return True

        if self.debug: print '\t'*tabs + "sAMAccountName:", result.values()[0]['sAMAccountName'],"did not  yield any match."
        return False
