# -*- coding: utf-8 -*-#
#
# Copyright (c) 2015 by Christian E. Hopps.
# All rights reserved.
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
#
from __future__ import absolute_import, division, unicode_literals, print_function, nested_scopes
from pexpect.fdpexpect import fdspawn

__author__ = 'Christian Hopps'
__version__ = '1.0'
__docformat__ = "restructuredtext en"


class sshspawn (fdspawn):
    '''This is like pexpect.spawn but allows you to supply your own open file
    descriptor. For example, you could use it to read through a file looking
    for patterns, or to control a modem or serial device. '''

    def __init__ (self, channel, args=[], timeout=30, maxread=2000, searchwindowsize=None, logfile=None):
        '''This takes an ssh channel. All Python file-like objects support fileno(). '''
        self.channel = channel
        fdspawn.__init__(self, channel, args, timeout, maxread, searchwindowsize, logfile)

    def close (self):
        """Close the file descriptor.

        Calling this method a second time does nothing, but if the file
        descriptor was closed elsewhere, :class:`OSError` will be raised.
        """
        if self.channel is None:
            return
        self.flush()
        self.channel.close()
        self.channel = None
        self.child_fd = -1
        self.closed = True

    def isalive (self):
        '''This checks if the file descriptor is still valid. If :func:`os.fstat`
        does not raise an exception then we assume it is alive. '''

        if self.channel is None:
            return False
        return self.channel.is_active()

