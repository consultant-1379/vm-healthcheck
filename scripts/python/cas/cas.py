#!/usr/bin/env python3

##############################################################################
# COPYRIGHT Ericsson 2018
#
# The copyright to the computer program(s) herein is the property of
# Ericsson Inc. The programs may be used and/or copied only with written
# permission from Ericsson Inc. or in accordance with the terms and
# conditions stipulated in the agreement/contract under which the
# program(s) have been supplied.
##############################################################################

import argparse
import logging
import sys
import time

import pexpect


def configure_logger():
    """
    Configures logging for this script.
    """
    global logger
    logging.basicConfig()
    logger = logging.getLogger("cas-gateway-connection")
    logger.setLevel(logging.DEBUG)
    ch = logging.StreamHandler()
    ch.setLevel(logging.DEBUG)
    formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
    ch.setFormatter(formatter)


configure_logger()

HOST = "138.85.107.105"
PORT = "10922"
CAS = "at1-nmaas1-cas"
CAS_PWD = "er1c550n"
args = []

if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument("login_id", help="Provide your signum here.")
    parser.add_argument("safe_pass", help="Provide your SoftToken password here.")
    parser.add_argument("cas_to_use", nargs="?", default="2", help="Select CAS server to use. Options: [1,2].")
    args = parser.parse_args()


def login(login_id, safe_pass):
    """
    Interactive script that opens SSH connection yo Jump Server that is configured as HOST attribute on PORT.
    Ericsson signum is used as username. SoftToken generated code is used as SafeWord password.

    Next it will SSH from JumpServer to CAS Atlanta server.
    By default it will SSH to CAS2, but this can be overridden by user provided attribute.

    :param login_id: Ericsson signum to use for
    :param safe_pass: SoftToken generated code.
    """
    child = pexpect.spawn("ssh -C -D {} {}@{}".format(PORT, login_id, HOST))
    child.expect("Enter SafeWord Password:")
    child.sendline(safe_pass)
    try:
        child.expect("eusecgw >", timeout=10)
    except pexpect.exceptions.TIMEOUT:
        logger.error("Can't establish connection to CAS JumpServer. Check SafeToken ID and pwd.")
        sys.exit()
    logger.debug("Connected to CAS JumpServer.")
    child.sendline("ssh {}".format(CAS + args.cas_to_use))
    child.expect("Password:")
    child.sendline(CAS_PWD)
    child.expect("at1-nmaas1-cas")
    logger.debug("Connected to %s.", CAS + args.cas_to_use)
    logger.debug("Now you can 'tsocks ssh ...' to Openstack VMs, etc.")
    time.sleep(86400)
    child.interact()
    child.sendeof()
    return


login(args.login_id, args.safe_pass)
