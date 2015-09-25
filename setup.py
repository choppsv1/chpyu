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
from __future__ import absolute_import, division, unicode_literals, print_function, nested_scopes
from setuptools import setup

with open('requirements.txt') as f:
    required = f.read().splitlines()

setup (name='chpyu',
       version='1.0.0',
       description='chopps python util library',
       author='Christian E. Hopps',
       author_email='chopps@gmail.com',
       url='https://github.com/choppsv1/chpyu',
       install_requires=required,
       packages=['chpyu'])
