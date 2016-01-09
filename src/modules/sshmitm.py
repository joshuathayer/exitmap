#!/usr/bin/env python

# Copyright 2013-2015 Philipp Winter <phw@nymity.ch>
#
# This file is part of exitmap.
#
# exitmap is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# exitmap is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with exitmap.  If not, see <http://www.gnu.org/licenses/>.

"""
Module to try to detect ssh mitm attacks.
"""

import select
import socket
import sys
import time
import traceback
from paramiko.py3compat import input
import log
from util import exiturl
import stem.descriptor.server_descriptor as descriptor
import paramiko
import torsocks


logger = log.get_logger()

# exitmap needs this variable to figure out which relays can exit to the given
# destination(s).
destinations = [("198.211.103.66", 22)]

hostname = "198.211.103.66"
port = 22

keys = paramiko.util.load_host_keys("src/modules/known_hosts_sshmitm")

def get_cert(exit_desc):
    exit_url = exiturl(exit_desc.fingerprint)
    
    try:
        sock = torsocks.torsocket()
        logger.debug("got sock")
        sock.connect((hostname, port))
        
    except Exception as e:
        logger.debug("hostname {} port {}".format(hostname, port))
        logger.debug('*** Connect failed: ' + str(e))
        return

    t = paramiko.Transport(sock)

    try:
        t.start_client()
    except paramiko.SSHException:
        logger.debug('*** SSH negotiation failed.')
        return
    
    key = t.get_remote_server_key()
    
    def log_err(m):
        logger.error("Error from exit {}: {}".format(exit_url, m))
    
    if hostname not in keys:
        log_err("Configured hostname is not in known keys")
        return
    elif key.get_name() not in keys[hostname]:
        log_err("Unknown host key")
        return
    elif keys[hostname][key.get_name()] != key:
        log_err("Mismatched host key")
        return

    logger.info("Host key OK from {}".format(exit_url))

def probe(exit_desc, run_python_over_tor, run_cmd_over_tor):
    """
    Probe the given exit relay and look for check.tp.o false negatives.
    """

    run_python_over_tor(get_cert, exit_desc)


def main():
    """
    Entry point when invoked over the command line.
    """

    return 0


if __name__ == "__main__":
    sys.exit(main())
