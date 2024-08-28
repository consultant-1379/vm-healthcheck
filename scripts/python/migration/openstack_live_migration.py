#!/usr/bin/env python2.7
# ********************************************************************
# Ericsson LMI               Utility Script
# ********************************************************************
#
# (c) Ericsson LMI 2019 - All rights reserved.
#
# The copyright to the computer program(s) herein is the property of Ericsson LMI.
# The programs may be used and/or copied only with the written permission from Ericsson LMI or
# in accordance with the terms and conditions stipulated in the agreement/contract under which
# the program(s) have been supplied.
#
# ********************************************************************
# Name    : Colin Bennett
# Purpose : Live-migrating of virtual machines to specified compute nodes using Nova Client
# Team    : Nemesis
# ********************************************************************
import os
import argparse
import time
import json
from pprint import pformat
from datetime import datetime

import logging
from logging.handlers import RotatingFileHandler

from requests.packages.urllib3 import disable_warnings

from keystoneauth1 import loading
from keystoneauth1 import session
from keystoneauth1.exceptions.auth import AuthorizationFailure
from keystoneauth1.exceptions.auth_plugins import MissingRequiredOptions

from novaclient import client as nova_client
from novaclient import exceptions as nova_exceptions

# Disable the insecure request warning, because TLS isn't set up for this
# Openstack API on our local host.
disable_warnings()

SEP = "====================================================================================="


class NovaClient(object):
    """
    This class creates and authenticates the Nova Client.
    """
    def __init__(self):
        self.client = None

    def authenticate(self):
        """
        Authenticate the Nova Client.

        :raises keystoneauth1.exceptions.auth.AuthorizationFailure: if unable to
            authenticate or validate the existing authorization token.
        :raises keystoneauth1.exceptions.auth_plugins.MissingRequiredOptions: if authentication
            fails due to missing required options.
        """
        credentials = {
            "username": os.environ.get('OS_USERNAME'),
            "password": os.environ.get('OS_PASSWORD'),
            "auth_url": os.environ.get('OS_AUTH_URL'),
            "project_domain_id": os.environ.get('OS_PROJECT_DOMAIN_ID'),
            "project_domain_name": os.environ.get('OS_PROJECT_DOMAIN_NAME'),
            "project_id": os.environ.get('OS_PROJECT_ID'),
            "project_name": os.environ.get('OS_PROJECT_NAME'),
            "tenant_name": os.environ.get('OS_TENANT_NAME'),
            "tenant_id": os.environ.get("OS_TENANT_ID"),
            "user_domain_id": os.environ.get('OS_USER_DOMAIN_ID'),
            "user_domain_name": os.environ.get('OS_USER_DOMAIN_NAME')
        }

        try:
            loader = loading.get_plugin_loader('password')
            auth = loader.load_from_options(**credentials)
            sess = session.Session(auth=auth, verify=False)

            self.client = nova_client.Client('2.1', session=sess)
            return self

        except (AuthorizationFailure, MissingRequiredOptions) as err:
            raise EnvironmentError(str(err))

    @staticmethod
    def is_admin():
        """
        Evaluates whether this user has admin privileges.

        :return: True or False.
        """
        if os.environ.get('OS_USERNAME').lower() == 'admin':
            return True
        return False

    def get_hypervisor_list(self):
        """
        Get the list of hypervisors.

        :return: the list of hypervisors.
        """
        return self.client.hypervisors.list()

    def get_hypervisor_with_server(self, hostname):
        """
        Get the hypervisor from its hostname.

        :param hostname: The hypervisor hostname.

        :return: the hypervisor object with servers in list.
        """
        return self.client.hypervisors.search(
            hypervisor_match=hostname, servers=True)

    def get_server(self, server_id):
        """
        Get the server from its name.

        :param server_id: The server id.

        :return: the server object.
        """
        return self.client.servers.get(server_id)

    def get_server_list(self, all_tenants=False):
        """
        Get the list of servers.

        :param all_tenants: Get servers from all tenants flag (default = False).

        :return: the list of servers.
        """
        search_opts = {}
        if all_tenants:
            search_opts['all_tenants'] = True

        return self.client.servers.list(
            detailed=True, search_opts=search_opts)


class NovaInstance(object):
    """
    This is a class for interacting with the Nova Instance.
    """

    def __init__(self, client, instance_details, timeout, user_prompt=True):
        """
        The constructor for NovaInstance class.

        :param client: The Nova client.
        :param instance_name: The instance name of the server.
        :param instance_id: The instance id of the server.
        :param timeout: The migration timeout in seconds.
        :param user_prompt: The user prompt variable (default = True).
        """
        self.nova_client = client
        self.instance_name = instance_details[0]
        self.instance_id = instance_details[1]
        self.timeout = timeout
        self.user_prompt = user_prompt
        self.refresh_instance()

    def refresh_instance(self):
        """
        Refreshes the server instance.
        """
        self.instance = self.nova_client.get_server(self.instance_id)

    def wait_for_status(self, desired_status):
        """
        Waits for the desired instance status.

        :param desired_status: The desired instance status.
        """
        old_status = ""

        # Timeout to wait on server (default 10 minutes).
        timeout_start = time.time()

        while self.instance.status != desired_status:

            if self.instance.status != old_status:
                old_status = self.instance.status
                LOGGER.info("Current status is '%s'; waiting for it to change to '%s'.",
                            self.instance.status, desired_status)

            if time.time() > timeout_start + self.timeout:
                LOGGER.error(
                    "Instance '%s' status could not be change to desired state '%s' within time limit of '%d' seconds..",
                    self.instance_name, desired_status, self.timeout)
                break

            time.sleep(5)
            self.refresh_instance()

    def migrate(self, destination):
        """
        Migrate the instance to a new host.

        :param destination: The target host.
        """
        source = self.instance.__dict__['OS-EXT-SRV-ATTR:host']
        LOGGER.info("Instance '%s' is now on host '%s' with state '%s'",
                    self.instance_name, source, self.instance.status)

        if source == destination:
            LOGGER.info(
                "Source and destination host are the same. Nothing to do.")
            return

        LOGGER.info("Launching the migration of instance '%s' to destination host '%s'",
                    self.instance_name, destination)

        if self.user_prompt:
            confirm = str(raw_input("\n\t Are you sure you would like to proceed? [y/n] : "))
            if "y" not in confirm and "Y" not in confirm:
                LOGGER.info("Instance '%s' migration has been manually rejected. Skipping.",
                            self.instance_name)
                return

        LOGGER.info("Migrating instance to new host.")
        try:
            self.instance.live_migrate(destination, False)
        except nova_exceptions.ClientException as err:
            LOGGER.error(
                "Failed to migrate instance '%s'. Error: %s", self.instance_name, err)
            return

        self.wait_for_status('MIGRATING')
        self.wait_for_status('ACTIVE')

        if self.instance.status != 'ACTIVE':
            LOGGER.error(
                "Failed to migrate instance '%s'. Please inspect the nova-compute log file for more information.",
                self.instance_name)
            return

        LOGGER.info("Instance has migrated.")
        LOGGER.info("Instance '%s' is now on host '%s' with state '%s'",
                    self.instance_name,
                    self.instance.__dict__['OS-EXT-SRV-ATTR:host'],
                    self.instance.status)


def configure_logger():
    """
    Configures logging for this script.
    """
    global LOGGER
    LOGGER = logging.getLogger(__name__)
    LOGGER.setLevel(logging.INFO)

    # Create file handler which logs even debug messages
    filename = datetime.now().strftime('live_migration.log')
    file_handler = RotatingFileHandler(filename, maxBytes=5 * 1024 * 1024, backupCount=3)
    file_handler.setLevel(logging.DEBUG)
    # Create console handler with a higher log level
    console = logging.StreamHandler()
    console.setLevel(logging.INFO)
    # Create formatter and add it to the handlers
    formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s- %(message)s')
    file_handler.setFormatter(formatter)
    console.setFormatter(formatter)
    # Add the handlers to the logger
    LOGGER.addHandler(file_handler)
    LOGGER.addHandler(console)


def create_host_map_layout(client):
    """
    Get the host map layout.

    :param client: The Nova client.

    :return: The current host map layout.
    """
    current_host_map = {}

    os_hypervisor_list = client.get_hypervisor_list()
    for hypervisor in os_hypervisor_list:
        current_host_map[hypervisor.hypervisor_hostname] = []

    # If the admin user get servers with all tenants.
    if client.is_admin():
        os_server_list = client.get_server_list(all_tenants=True)
    else:
        os_server_list = client.get_server_list()

    for server in os_server_list:
        server_host = server.__dict__['OS-EXT-SRV-ATTR:host']
        if server_host in current_host_map.keys():
            current_host_map[server_host].append(server.name)

    LOGGER.info(SEP)
    LOGGER.info("Current host map layout: ")
    for line in pformat(current_host_map).split('\n'):
        LOGGER.info(line)
    LOGGER.info(SEP)

    return current_host_map


def compare_layouts(client, current_host_map, new_host_map):
    """
    Compares the current and new host map layout.

    :param client: The Nova client.
    :param current_host_map: The current host map layout.
    :param new_host_map: The new host map layout.

    :return: The difference between the two host map layouts.
    """
    compared_host_map = {}

    for host, servers in current_host_map.items():
        if host in new_host_map and new_host_map[host]:

            compared_servers = [s for s in new_host_map[host] if s not in servers]
            if compared_servers:
                compared_host_map[host] = compared_servers

    host_map = validate_layout(client, compared_host_map)

    LOGGER.info(SEP)
    LOGGER.info("New host map changes to apply: ")
    for line in pformat(host_map).split('\n'):
        LOGGER.info(line)
    LOGGER.info(SEP)

    return host_map


def validate_layout(client, compared_host_map):
    """
    Validates the compared host map layout.

    :param client: The Nova client.
    :param compared_host_map: The compared host map layout.

    :return: The validated host map layout.
    """
    # If the admin user get servers with all tenants.
    if client.is_admin():
        os_server_list = client.get_server_list(all_tenants=True)
    else:
        os_server_list = client.get_server_list()

    host_map = {}

    for host, servers in compared_host_map.items():

        validated_servers = [(s.name, s.id) for s in os_server_list if s.name in servers]
        if validated_servers:
            host_map[host] = validated_servers

    return host_map


def main():
    """
    Entry point for starting Live-migrating application.
    """
    configure_logger()
    LOGGER.info("Starting...")

    # JSON host map get passed in at the command line.
    parser = argparse.ArgumentParser()
    parser.add_argument('--host_map', help='Host map configuration file (JSON)')
    parser.add_argument(
        '--timeout',
        default=600,
        type=int,
        help='Timeout in seconds for a single instance status check after launching migration.')
    parser.add_argument(
        "--yes",
        "-y",
        dest="user_prompt",
        action="store_false",
        default=True,
        help="Do not prompt before server migration.")
    args = parser.parse_args()

    host_map_file = vars(args)["host_map"]
    timeout = vars(args)["timeout"]

    # Setup the NovaClient.
    nova = NovaClient()
    try:
        nova.authenticate()
    except EnvironmentError as err:
        LOGGER.error("Keystone Authorization failure. Error: %s", err)
        return

    # Current host configuration layout.
    current_host_map = create_host_map_layout(nova)
    if not current_host_map:
        LOGGER.error("No existing host configuration found.")
        return

    # Load in the new host configuration layout.
    with open(host_map_file, "r") as hm_file:
        try:
            new_host_map = json.load(hm_file)
        except ValueError as err:
            LOGGER.error(
                "Invalid JSON file. Error: %s", err)
            return

    # Updated host configuration layout to apply.
    updated_host_map = compare_layouts(nova, current_host_map, new_host_map)

    # Loop and process servers.
    for hostname, server_list in updated_host_map.items():
        for server in server_list:
            # Create the Nova Instance class and launch migration.
            instance = NovaInstance(
                nova, server, timeout, user_prompt=args.user_prompt)
            instance.migrate(hostname)

    LOGGER.info("Completed script.")


if __name__ == "__main__":
    main()
