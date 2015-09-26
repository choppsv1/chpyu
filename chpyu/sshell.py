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
"""
>>> setup_module("testing")
"""
from __future__ import absolute_import, division, unicode_literals, print_function, nested_scopes
import functools
import logbook
# import logging
import os
import socket
import subprocess
import threading
import traceback
from nose.tools import set_trace                            # pylint: disable=W0611

__author__ = 'Christian Hopps'
__version__ = '1.0'
__docformat__ = "restructuredtext en"


class CalledProcessError (subprocess.CalledProcessError):
    pass

import paramiko as ssh

MAXSSHBUF = 16 * 1024
MAXCHANNELS = 8

logger = logbook.Logger(__name__)
# logger = logging.getLogger(__name__)


def read_to_eof (recvmethod):
    buf = recvmethod(MAXSSHBUF)
    while buf:
        yield buf
        buf = recvmethod(MAXSSHBUF)


def terminal_size():
    import fcntl
    import termios
    import struct
    h, w, unused, unused = struct.unpack('HHHH', fcntl.ioctl(0, termios.TIOCGWINSZ, struct.pack('HHHH', 0, 0, 0, 0)))
    return w, h


def shell_escape_single_quote (command):
    """Escape single quotes for use in a shell single quoted string
    Explanation:

    (1) End first quotation which uses single quotes.
    (2) Start second quotation, using double-quotes.
    (3) Quoted character.
    (4) End second quotation, using double-quotes.
    (5) Start third quotation, using single quotes.

    If you do not place any whitespaces between (1) and (2), or between
    (4) and (5), the shell will interpret that string as a one long word
    """
    return command.replace("'", "'\"'\"'")


class SSHConnection (object):
    """A connection to an SSH server"""
    ssh_sockets = {}
    ssh_socket_keys = {}
    ssh_socket_timeout = {}
    ssh_sockets_lock = threading.Lock()

    def __init__ (self, host, port=22, username=None, password=None, debug=False):
        self.host = host
        self.port = port
        self.debug = debug
        self.host_key = None
        self.chan = None
        self.ssh = None

        if not username:
            import getpass
            username = getpass.getuser()

        self.username = username
        self.password = password
        self.ssh = self.get_ssh_socket(host, port, username, password, debug)

        # Open a session.
        try:
            if self.debug:
                logger.debug("Opening SSH channel on socket ({}:{})", self.host, self.port)
            self.chan = self.ssh.open_session()
        except:
            self.close()
            raise

    def __del__ (self):
        # Make sure we get rid of the cached reference to the open ssh socket
        self.close()

    def close (self):
        if hasattr(self, "chan") and self.chan:
            if self.debug:
                logger.debug("Closing SSH channel on socket ({}:{})", self.host, self.port)
            self.chan.close()
            self.chan = None
        if hasattr(self, "ssh") and self.ssh:
            tmp = self.ssh
            self.ssh = None
            self.release_ssh_socket(tmp, self.debug)

    def is_active (self):
        return self.chan and self.ssh and self.ssh.is_active()

    @classmethod
    def get_ssh_socket (cls, host, port, username, password, debug):
        # Return an open ssh socket if we have one.
        key = "{}:{}:{}".format(host, port, username)
        with cls.ssh_sockets_lock:
            if key in cls.ssh_sockets:
                for entry in cls.ssh_sockets[key]:
                    if entry[2] < MAXCHANNELS:
                        sshsock = entry[1]
                        entry[2] += 1
                        if debug:
                            logger.debug("Incremented SSH socket use to {}", entry[2])

                        # Cancel any timeout for closing, only really need to do this on count == 1.
                        cls.cancel_close_socket_expire(sshsock, debug)

                        return sshsock
                # This means there are no entries with free channels

            attempt = 0

            try:
                error = None
                for addrinfo in socket.getaddrinfo(host,
                                                   port,
                                                   socket.AF_UNSPEC,
                                                   socket.SOCK_STREAM):
                    af, socktype, proto, unused_name, sa = addrinfo
                    try:
                        ossock = socket.socket(af, socktype, proto)
                        ossock.connect(sa)
                        if attempt:
                            logger.debug("Succeeded after {} attempts to : {}", attempt, addrinfo)
                        break
                    except socket.error as ex:
                        ossock = None
                        logger.debug("Got socket error connecting to: {}: {}", addrinfo, ex)
                        attempt += 1
                        error = ex
                        continue
                else:
                    if error is not None:
                        logger.debug("Got error connecting to: {}: {} (no addr)", addrinfo, error)
                        raise error                             # pylint: disable=E0702
                    raise Exception("Couldn't connect to any resolution for {}:{}".format(host, port))
            except Exception as ex:
                logger.error("Got unexpected socket error connecting to: {}:{}: {}", host, port, ex)
                raise

            try:
                if debug:
                    logger.debug("Opening SSH socket to {}:{}", host, port)

                sshsock = ssh.Transport(ossock)
                # self.ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())

                # XXX this takes an event so we could yield here to wait for event.
                event = None
                sshsock.start_client(event)

                # XXX save this if we actually need it.
                sshsock.get_remote_server_key()

                # try:
                #     sshsock.auth_none(username)
                # except (ssh.AuthenticationException, ssh.BadAuthenticationType):
                #     pass

                if not sshsock.is_authenticated() and password is not None:
                    try:
                        sshsock.auth_password(username, password, event, False)
                    except (ssh.AuthenticationException, ssh.BadAuthenticationType):
                        pass

                if not sshsock.is_authenticated():
                    ssh_keys = ssh.Agent().get_keys()
                    lastkey = len(ssh_keys) - 1
                    for idx, ssh_key in enumerate(ssh_keys):
                        if sshsock.is_authenticated():
                            break
                        try:
                            sshsock.auth_publickey(username, ssh_key, event)
                        except ssh.AuthenticationException:
                            if idx == lastkey:
                                raise
                            # Try next key
                assert sshsock.is_authenticated()

                # nextauth (rval from above) would be a secondary authentication e.g., google authenticator.

                # XXX using the below instead of the breakout above fails threaded.
                # sshsock.connect(hostkey=None,
                #                 username=self.username,
                #                 password=self.password)

                if key not in cls.ssh_sockets:
                    cls.ssh_sockets[key] = []
                # Add this socket to the list of sockets for this key
                cls.ssh_sockets[key].append([ossock, sshsock, 1])
                cls.ssh_socket_keys[sshsock] = key
                return sshsock
            except ssh.AuthenticationException as error:
                ossock.close()
                logger.error("Authentication failed: {}", error)
                raise

    @classmethod
    def cancel_close_socket_expire (cls, ssh_socket, debug):
        """Must enter locked"""
        if not ssh_socket:
            return
        if ssh_socket not in cls.ssh_socket_timeout:
            return
        if debug:
            logger.debug("Canceling timer to release ssh socket: {}", ssh_socket)
        timer = cls.ssh_socket_timeout[ssh_socket]
        del cls.ssh_socket_timeout[ssh_socket]
        timer.cancel()

    @classmethod
    def _close_socket_expire (cls, ssh_socket, debug):
        if not ssh_socket:
            return

        with cls.ssh_sockets_lock:
            # If we aren't present anymore must have been canceled
            if ssh_socket not in cls.ssh_socket_timeout:
                return

            if debug:
                logger.debug("Timer expired, releasing ssh socket: {}", ssh_socket)

            # Remove any timeout
            del cls.ssh_socket_timeout[ssh_socket]
            cls._close_socket(ssh_socket, debug)

    @classmethod
    def release_ssh_socket (cls, ssh_socket, debug):
        if not ssh_socket:
            return

        with cls.ssh_sockets_lock:
            key = cls.ssh_socket_keys[ssh_socket]

            assert key in cls.ssh_sockets
            entry = None
            for entry in cls.ssh_sockets[key]:
                if entry[1] == ssh_socket:
                    break
            else:
                raise KeyError("Can't find {} in list of entries".format(key))

            entry[2] -= 1
            if entry[2]:
                if debug:
                    logger.debug("Decremented SSH socket use to {}", entry[2])
                return

            # We are all done with this socket
            # Setup a timer to actually close the socket.
            if ssh_socket not in cls.ssh_socket_timeout:
                if debug:
                    logger.debug("Setting up timer to release ssh socket: {}", ssh_socket)
                cls.ssh_socket_timeout[ssh_socket] = threading.Timer(1, cls._close_socket_expire, [ssh_socket, debug])
                cls.ssh_socket_timeout[ssh_socket].start()

    @classmethod
    def _close_socket (cls, ssh_socket, debug):
        entry = None
        try:
            key = cls.ssh_socket_keys[ssh_socket]
            for entry in cls.ssh_sockets[key]:
                if entry[1] == ssh_socket:
                    break
            else:
                assert False

            if debug:
                logger.debug("Closing SSH socket to {}", key)
            if entry[1]:
                entry[1].close()
                entry[1] = None

            if entry[0]:
                entry[0].close()
                entry[0] = None
        except Exception as error:
            logger.info("{}: Unexpected exception: {}: {}", cls, error, traceback.format_exc())
            logger.error("{}: Unexpected error closing socket:  {}", cls, error)
        finally:
            del cls.ssh_socket_keys[ssh_socket]
            if entry:
                cls.ssh_sockets[key].remove(entry)


class SSHClientSession (SSHConnection):
    """A client session to a host using a subsystem"""

    #---------------------------+
    # Overriding parent methods
    #---------------------------+

    def __init__ (self, host, port, subsystem, username=None, password=None, debug=False):
        super(SSHClientSession, self).__init__(host, port, username, password, debug)
        try:
            self.chan.invoke_subsystem(subsystem)
        except:
            self.close()
            raise

    #-------------+
    # New methods
    #-------------+

    def send (self, chunk):
        assert self.chan is not None
        self.chan.send(chunk)

    def sendall (self, chunk):
        assert self.chan is not None
        self.chan.sendall(chunk)

    def recv (self, size=MAXSSHBUF):
        assert self.chan is not None
        return self.chan.recv(size)


class SSHCommand (SSHConnection):

    def __init__ (self, command, host, port=22, username=None, password=None, debug=False):
        self.command = command
        self.exit_code = None
        self.output = ""
        self.error_output = ""

        super(SSHCommand, self).__init__(host, port, username, password, debug)

    def run_status_stderr (self):
        """
        Run a command over an ssh channel, return exit code, stdout and stderr.

        >>> status, output, error = SSHCommand("ls -d /etc", "localhost").run_status_stderr()
        >>> status
        0
        >>> print(output, end="")
        /etc
        >>> print(error, end="")
        >>> status, output, error = SSHCommand("grep foobar doesnt-exist", "localhost").run_status_stderr()
        >>> status
        2
        >>> print(output, end="")
        >>>
        >>> print(error, end="")
        grep: doesnt-exist: No such file or directory
        """
        try:
            self.chan.exec_command(self.command)
            self.exit_code = self.chan.recv_exit_status()

            self.output = "".join([x.decode('utf-8') for x in read_to_eof(self.chan.recv)])
            self.error_output = "".join([x.decode('utf-8')
                                         for x in read_to_eof(self.chan.recv_stderr)])

            return (self.exit_code, self.output, self.error_output)
        finally:
            self.close()

    def run_stderr (self):
        """
        Run a command over an ssh channel, return stdout and stderr,
        Raise CalledProcessError on failure

        >>> cmd = SSHCommand("ls -d /etc", "localhost")
        >>> output, error = cmd.run_stderr()
        >>> print(output, end="")
        /etc
        >>> print(error, end="")
        >>> cmd = SSHCommand("grep foobar doesnt-exist", "localhost")
        >>> cmd.run_stderr()                                    # doctest: +IGNORE_EXCEPTION_DETAIL
        Traceback (most recent call last):
            ...
        CalledProcessError: Command 'grep foobar doesnt-exist' returned non-zero exit status 2
        """
        status, unused, unused = self.run_status_stderr()
        if status != 0:
            raise CalledProcessError(self.exit_code, self.command,
                                     self.error_output if self.error_output else self.output)
        return self.output, self.error_output

    def run_status (self):
        """
        Run a command over an ssh channel, return exitcode and stdout.

        >>> status, output = SSHCommand("ls -d /etc", "localhost").run_status()
        >>> status
        0
        >>> print(output, end="")
        /etc
        >>> status, output = SSHCommand("grep foobar doesnt-exist", "localhost").run_status()
        >>> status
        2
        >>> print(output, end="")
        """
        return self.run_status_stderr()[0:2]

    def run (self):
        """
        Run a command over an ssh channel, return stdout.
        Raise CalledProcessError on failure.

        >>> cmd = SSHCommand("ls -d /etc", "localhost")
        >>> print(cmd.run(), end="")
        /etc
        >>> cmd = SSHCommand("grep foobar doesnt-exist", "localhost")
        >>> cmd.run()                                   # doctest: +IGNORE_EXCEPTION_DETAIL
        Traceback (most recent call last):
            ...
        CalledProcessError: Command 'grep foobar doesnt-exist' returned non-zero exit status 2
        """
        return self.run_stderr()[0]


class SSHPTYCommand (SSHCommand):

    def __init__ (self, command, host, port=22, username=None, password=None, debug=False):
        self.command = command
        self.exit_code = None
        self.output = ""
        self.error_output = ""

        super(SSHPTYCommand, self).__init__(host, port, username, password, debug)

    def _get_pty (self):
        width, height = terminal_size()
        return self.chan.get_pty(term=os.environ['TERM'], width=width, height=height)

    def run_status (self):
        """
        Run a command over an ssh channel, return exitcode and stdout.

        >>> status, output = SSHCommand("ls -d /etc", "localhost").run_status()
        >>> status
        0
        >>> print(output, end="")
        /etc
        >>> status, output = SSHCommand("grep foobar doesnt-exist", "localhost").run_status()
        >>> status
        2
        >>> print(output, end="")
        """
        try:
            self._get_pty()
            self.chan.exec_command(self.command)
            self.exit_code = self.chan.recv_exit_status()

            self.output = "".join([x.decode('utf-8') for x in read_to_eof(self.chan.recv)])

            return (self.exit_code, self.output)
        finally:
            self.close()

    def run (self):
        """
        Run a command over an ssh channel, return stdout.
        Raise CalledProcessError on failure.

        >>> cmd = SSHCommand("ls -d /etc", "localhost")
        >>> print(cmd.run(), end="")
        /etc
        >>> cmd = SSHCommand("grep foobar doesnt-exist", "localhost")
        >>> cmd.run()                                   # doctest: +IGNORE_EXCEPTION_DETAIL
        Traceback (most recent call last):
            ...
        CalledProcessError: Command 'grep foobar doesnt-exist' returned non-zero exit status 2
        """
        status, unused, unused = self.run_status_stderr()
        if status != 0:
            raise CalledProcessError(self.exit_code, self.command,
                                     self.error_output if self.error_output else self.output)
        return self.output


class ShellCommand (object):

    def __init__ (self, command, debug=False):
        self.command_list = ["/bin/sh", "-c", command]
        self.debug = debug
        self.exit_code = None
        self.output = ""
        self.error_output = ""

    def run_status_stderr (self):
        """
        Run a command over an ssh channel, return exit code, stdout and stderr.

        >>> cmd = ShellCommand("ls -d /etc")
        >>> status, output, error = cmd.run_status_stderr()
        >>> status
        0
        >>> print(output, end="")
        /etc
        >>> print(error, end="")
        """
        """
        >>> status, output, error = ShellCommand("grep foobar doesnt-exist").run_status_stderr()
        >>> status
        2
        >>> print(output, end="")
        >>>
        >>> print(error, end="")
        grep: doesnt-exist: No such file or directory
        """
        try:
            pipe = subprocess.Popen(self.command_list,
                                    stdout=subprocess.PIPE,
                                    stderr=subprocess.PIPE,
                                    close_fds=True)
            self.output, self.error_output = pipe.communicate()
            self.exit_code = pipe.returncode
        except OSError:
            self.exit_code = 1

        return (self.exit_code, self.output, self.error_output)

    def run_stderr (self):
        """
        Run a command over an ssh channel, return stdout and stderr,
        Raise CalledProcessError on failure

        >>> cmd = ShellCommand("ls -d /etc")
        >>> output, error = cmd.run_stderr()
        >>> print(output, end="")
        /etc
        >>> print(error, end="")
        >>> cmd = ShellCommand("grep foobar doesnt-exist")
        >>> cmd.run_stderr()                                    # doctest: +IGNORE_EXCEPTION_DETAIL
        Traceback (most recent call last):
            ...
        CalledProcessError: Command 'grep foobar doesnt-exist' returned non-zero exit status 2
        """
        status, unused, unused = self.run_status_stderr()
        if status != 0:
            raise CalledProcessError(self.exit_code, self.command_list,
                                     self.error_output if self.error_output else self.output)
        return self.output, self.error_output

    def run_status (self):
        """
        Run a command over an ssh channel, return exitcode and stdout.

        >>> status, output = ShellCommand("ls -d /etc").run_status()
        >>> status
        0
        >>> print(output, end="")
        /etc
        >>> status, output = ShellCommand("grep foobar doesnt-exist").run_status()
        >>> status
        2
        >>> print(output, end="")
        """
        return self.run_status_stderr()[0:2]

    def run (self):
        """
        Run a command over an ssh channel, return stdout.
        Raise CalledProcessError on failure.

        >>> cmd = ShellCommand("ls -d /etc", False)
        >>> print(cmd.run(), end="")
        /etc
        >>> cmd = ShellCommand("grep foobar doesnt-exist", False)
        >>> cmd.run()                                   # doctest: +IGNORE_EXCEPTION_DETAIL
        Traceback (most recent call last):
            ...
        CalledProcessError: Command 'grep foobar doesnt-exist' returned non-zero exit status 2
        """
        return self.run_stderr()[0]


class Host (object):
    def __init__ (self, server=None, port=22, cwd=None, username=None, password=None, debug=False):
        """
        A host object is either local or remote and provides easy access
        to the given local or remote host
        """
        self.cwd = cwd
        if server:
            self.cmd_class = functools.partial(SSHCommand,
                                               host=server,
                                               port=port,
                                               username=username,
                                               password=password,
                                               debug=debug)
        else:
            self.cmd_class = functools.partial(ShellCommand, debug=debug)

        if not self.cwd:
            self.cwd = self.cmd_class("pwd").run().strip()

    def get_cmd (self, command):
        return "bash -c 'cd {} && {}'".format(self.cwd, shell_escape_single_quote(command))

    def run_status_stderr (self, command):
        """
        Run a command return exit code, stdout and stderr.
        >>> host = Host()
        >>> status, output, error = host.run_status_stderr("ls -d /etc")
        >>> status
        0
        >>> print(output, end="")
        /etc
        >>> print(error, end="")
        >>> status, output, error = host.run_status_stderr("grep foobar doesnt-exist")
        >>> status
        2
        >>> print(output, end="")
        >>>
        >>> print(error, end="")
        grep: doesnt-exist: No such file or directory
        """
        return self.cmd_class(self.get_cmd(command)).run_status_stderr()

    def run_status (self, command):
        return self.cmd_class(self.get_cmd(command)).run_status()

    def run_stderr (self, command):
        return self.cmd_class(self.get_cmd(command)).run_stderr()

    def run (self, command):
        return self.cmd_class(self.get_cmd(command)).run()


def setup_module (unused):
    print("Setup called.")
    if os.environ['USER'] != "travis":
        return

    print("Executing under Travis-CI")
    ssh_dir = "{}/.ssh".format(os.environ['HOME'])
    priv_filename = os.path.join(ssh_dir, "id_rsa")
    if os.path.exists(priv_filename):
        logger.error("Found private keyfile")
        print("Found private keyfile")
        return
    else:
        logger.error("Creating ssh dir " + ssh_dir)
        print("Creating ssh dir " + ssh_dir)
        ShellCommand("mkdir -p {}".format(ssh_dir)).run()
        priv = ssh.RSAKey.generate(bits=1024)
        logger.error("Generating private keyfile " + priv_filename)
        print("Generating private keyfile " + priv_filename)
        priv.write_private_key_file(filename=priv_filename)

        pub = ssh.RSAKey(filename=priv_filename)
        auth_filename = os.path.join(ssh_dir, "authorized_keys")
        logger.error("Adding keys to authorized_keys file " + auth_filename)
        print("Adding keys to authorized_keys file " + auth_filename)
        with open(auth_filename, "a") as authfile:
            authfile.write("{} {}\n".format(pub.get_name(), pub.get_base64()))
        logger.error("Done generating keys")
        print("Done generating keys")


if __name__ == "__main__":
    import time
    import gc

    cmd = SSHCommand("ls -d /etc", "localhost", debug=True)
    print(cmd.run())
    gc.collect()

    print(SSHCommand("ls -d /etc", "localhost", debug=True).run())
    gc.collect()

    print("Going to sleep for 2")
    time.sleep(2)
    gc.collect()

    print("Waking up")
    print(SSHCommand("ls -d /etc", "localhost", debug=True).run())
    gc.collect()
    print("Exiting")
