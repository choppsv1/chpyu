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
from chpyu.timers import Timer, TimerHeap

timer_heap = TimerHeap("Testing Timer Heap")


def test_simple_timer ():
    test_dict = {}

    def expired (arg):
        test_dict[arg] = 1

    timer = Timer(timer_heap, 0, expired, "key1")
    timer.start(.1)
    time.sleep(.2)
    assert test_dict["key1"] == 1


def test_many_timers ():
    test_dict = {}

    def expired (arg):
        test_dict[arg] = 1

    #----------------------------------
    # Create and start a lot of timers
    #----------------------------------

    NTIMERS = 100000
    for idx in range(0, NTIMERS):
        Timer(timer_heap, 0, expired, idx).start(.2)

    time.sleep(.4)

    #----------------
    # Verify results
    #----------------

    for idx in range(0, NTIMERS):
        assert test_dict[idx] == 1





__author__ = 'Christian Hopps'
__date__ = 'September 26 2015'
__version__ = '1.0'
__docformat__ = "restructuredtext en"
