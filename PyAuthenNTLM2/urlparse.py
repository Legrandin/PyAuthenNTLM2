#!/usr/bin/env python
#
# PyAuthenNTLM2: A mod-python module for Apache that carries out NTLM authentication
#
# urlparse.py
#
# Copyright 2012 Legrandin <gooksankoo@hoiptorrow.mailexpire.com>
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

import re

def urlparse(url):
    """Split the given url in components.

    The 1st item in the returned list is the scheme (e.g. 'https'). It is optional.
    The 2nd item is the hostname (e.g. 'www.google.com'). It is mandatory.
    The 2nd item is the port (e.g. 8080). It is optional.
    The 3rd item is the path and search components (E.g. '/index.htlm'). It is optional.

    >>> urlparse("www.google.com")
    [None, 'www.google.com', None, '']

    >>> urlparse("www.google.com:80")
    [None, 'www.google.com', 80, '']

    >>> urlparse("ftp://www.google.com:8080")
    ['ftp', 'www.google.com', 8080, '']

    >>> urlparse("www.google.com/index.html")
    [None, 'www.google.com', None, '/index.html']

    >>> urlparse("www.google.com/in%20-dex.html?client=x&channel=4")
    [None, 'www.google.com', None, '/in%20-dex.html?client=x&channel=4']
    """

    sobj = re.search(r"((\w+):\/\/)?([^:\/\s]+)(:(\d+))?((\/[\w?&=$_@\.,%+-]+)*)?", url)
    if not sobj:
        return None
    ret = [sobj.group(i) for i in [2,3,5,6]]
    if ret[2]:
        ret[2] = int(ret[2])
    return ret

if __name__ == '__main__':
    import doctest
    doctest.testmod()

