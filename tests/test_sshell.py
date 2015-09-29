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
import os
import logbook
import paramiko as ssh
from chpyu.sshell import ShellCommand

__author__ = 'Christian Hopps'
__date__ = 'September 26 2015'
__docformat__ = "restructuredtext en"

logbook.StderrHandler().push_application()
logger = logbook.Logger(__name__)


def setup_module (unused):
    ssh_dir = "{}/.ssh".format(os.environ['HOME'])
    if os.path.exists(ssh_dir):
        logger.error("Found ssh dir")
        logger.error("{}", ShellCommand("ls -al " + ssh_dir).run())
    else:
        logger.error("Creating ssh dir " + ssh_dir)
        ShellCommand("mkdir -p {}".format(ssh_dir)).run()
        priv = ssh.RSAKey.generate(bits=1024)
        priv_filename = os.path.join(ssh_dir, "id_rsa")
        logger.error("Generating private keyfile " + priv_filename)
        priv.write_private_key_file(filename=priv_filename)

        pub = ssh.RSAKey(filename=priv_filename)
        auth_filename = os.path.join(ssh_dir, "authorized_keys")
        logger.error("Generating authorized_keys file " + auth_filename)
        with open(auth_filename, "w") as authfile:
            authfile.write("{} {}\n".format(pub.get_name(), pub.get_base64()))
        logger.error("Done generating keys")
