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
import time
import logbook
from chpyu.timers import Timer, TimerHeap

logbook.StderrHandler().push_application()
logger = logbook.Logger(__name__)

timer_heap = TimerHeap("Testing Timer Heap")


def test_simple_timer ():
    """Simple timer test"""
    test_dict = {}

    def expired (arg):
        test_dict[arg] = 1

    timer = Timer(timer_heap, 0, expired, "key1")
    timer.start(.1)
    time.sleep(.2)
    assert test_dict["key1"] == 1


def test_many_timers ():
    """Test more timers than standard thread based timer could handle"""
    test_dict = {}

    def expired (arg):
        test_dict[arg] = timer_heap.expire_gen

    #--------------------------------------------------
    # Create and start a lot of timers with 25% jitter
    #--------------------------------------------------

    NTIMERS = 100000
    for idx in range(0, NTIMERS):
        Timer(timer_heap, .25, expired, idx).start(1)

    time.sleep(2)

    #-----------------------------------------------------------
    # Verify results print info on number of actual expirations
    #-----------------------------------------------------------

    firecount = 0
    prevgen = -1
    for idx in range(0, NTIMERS):
        assert idx in test_dict
        if test_dict[idx] != prevgen:
            prevgen = test_dict[idx]
            firecount += 1

    logger.info("Expired {} times for {} timers".format(firecount, NTIMERS))


__author__ = 'Christian Hopps'
__date__ = 'September 26 2015'
__version__ = '1.0'
__docformat__ = "restructuredtext en"
