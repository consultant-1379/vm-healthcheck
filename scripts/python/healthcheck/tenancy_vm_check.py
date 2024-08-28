#!/usr/bin/env python

##############################################################################
# COPYRIGHT Ericsson 2018
#
# The copyright to the computer program(s) herein is the property of
# Ericsson Inc. The programs may be used and/or copied only with written
# permission from Ericsson Inc. or in accordance with the terms and
# conditions stipulated in the agreement/contract under which the
# program(s) have been supplied.
##############################################################################

import ConfigParser
import argparse
import datetime
import json
import logging
import os.path
import socket
import sys
import urllib2
from logging.handlers import RotatingFileHandler
from subprocess import PIPE, Popen

if __name__ == '__main__':
    global args
    parser = argparse.ArgumentParser()
    parser.add_argument("log_file", default="tenancy_vm_check.py", nargs="?", help="Provide log file name.")
    parser.add_argument("--usage", help="Display help.", action="store_true")
    args = parser.parse_args()

SEP1 = "-------------------------------------------------------------------------------------"
SEP2 = "====================================================================================="
LOG = args.log_file + ".log"
DIR = os.path.dirname(LOG)

CONF_FILE = "tenancy_vm_check_py.cfg"
CONF_URL = os.path.join(DIR, CONF_FILE)
ENMAAS_CONFS = []

TIMEOUT = "ConnectTimeout=10"
KEYCHECK = "StrictHostKeyChecking=no"
LOGLEVEL = "LogLevel=ERROR"

SSH_USER = "cloud-user"


def configure_logger():
    """
    Configures logging for this script.
    """
    global logger
    logger = logging.getLogger("tenancy-vm-check")
    logger.setLevel(logging.DEBUG)
    formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
    # Will configure Log file size limit as 5MB with 3 backups.
    rfh = RotatingFileHandler(LOG, maxBytes=5 * 1024 * 1024, backupCount=3)
    rfh.setLevel(logging.INFO)
    rfh.setFormatter(formatter)
    sh = logging.StreamHandler()
    sh.setLevel(logging.DEBUG)
    sh.setFormatter(formatter)
    logger.addHandler(sh)
    logger.addHandler(rfh)


configure_logger()


def usage(exit_code=0):
    """
    Display this usage help message whenever the script is run with '--usage' argument.

    :param exit_code: exit code to quit this application with after running this method.
    """
    logger.info("""
        Usage of: '{}'

        This message is displayed when script is run with '--usage' argument.
        ==============================================================================================================================================
                                                                     Overview:
        ==============================================================================================================================================

        This script will connect over SSH to each configured Deployment using the private key.
        Every step of the script is logged on screen and in the configured LOG file.
        LOG file is configured to be up to 5 MB of size and rotate with 3 backups.
        If there are problems with any of the Deployments - an email is sent to the configured email address.

        ==============================================================================================================================================
                                                                     Configuration Validation:
        ==============================================================================================================================================

        ----------------------------------------------------------------------------------------------------------------------------------------------
        ## Script Validation steps:
        ----------------------------------------------------------------------------------------------------------------------------------------------
        1. Read the config file (defined in CONF_FILE variable as tenancy_vm_check_py.cfg).
        2. Source Default configuration.
        3. Source Deployments configurations.
        4. For each sourced Deployment verify:
            4.1. Configured key is accessible
            4.2. Configured key is Private Key file.
            4.3. Each configured IP is valid IP.
            4.4. Each provided IP is accessible via ping operation.

        ----------------------------------------------------------------------------------------------------------------------------------------------
        ## Every step must succeed, otherwise the script will log ERROR and send appropriate email; or at some stage it might exit.
        ----------------------------------------------------------------------------------------------------------------------------------------------
        1. If failed to read cfg file - log error and and exit script with outlined exit code: 1 (no READ access) or 2 (other problem with file).
            Can't send email if configuration can't be read.

        2. If no Email configuration found - log error and exit script with outlined exit code: 3 ('EMAIL_URL' not found) or 4 ('EMAIL_TO' not found).
            Can't send email if one of the required fields is not present.

        3. If no Deployments found - log error and send email with outlined exit code: 5.
            Also exit script with exit code.

        4.
            4.1 If key is not accessible (i.e. doesn't exist or can't be read) - log error and send email with outlined exit code: 6.
                Continue other Deployment's verification.

            4.2 If key is not a private key (i.e. doesn't contain "PRIVATE KEY") - log error and send email with exit code: 7.
                Continue other Deployment's verification.

            4.3 If IP is invalid - log error and send email with exit code: 8.
                Continue Deployment's verification.

            4.4 If IP is invalid - log error and send email with exit code: 9.
                Continue Deployment's verification.

        ==============================================================================================================================================
                                                                     Verifies Deployment's health check:
        ==============================================================================================================================================

        ----------------------------------------------------------------------------------------------------------------------------------------------
        ## Health Check Flow:
        ----------------------------------------------------------------------------------------------------------------------------------------------

        1. Check if Consul is available. Else return "no_consul_on_host" error code.
        2. Check if deployment name property can be read from consul. Else return "missing_kv_host_system_identifier" error code.
        3. Check if number of installed instances property can be read from consul. Else return "missing_kv_consul_install_instances" error code.
        4. Check if consul members can be read from consul. Else return "failed_to_get_consul_members" error code.
        5. Check if returned consul members are healthy.

        ----------------------------------------------------------------------------------------------------------------------------------------------
        ## Every response is validated and if one of error codes is returned, then:
        ----------------------------------------------------------------------------------------------------------------------------------------------

        1. no_consul_on_host - raise ValueError. Skip verification for current Deployment IP and try next in the list.
        2. missing_kv_host_system_identifier - fallback to Deployment name from config.
        3. missing_kv_consul_install_instances - appropriate email message will be sent to configured EMAIL_TO address with error code: 21.
        4. failed_to_get_consul_members - appropriate email message will be sent to configured EMAIL_TO address with error code: 22.
        5. If no errors are reported - verify count of alive, failed and left consul members. If there are failed or left consul members,
            or alive consul members are not equal to expected consul members - appropriate email message will be sent to configured EMAIL_TO address.

        ==============================================================================================================================================
                                                                     Configuration file (tenancy_vm_check_py.cfg):
        ==============================================================================================================================================

        The script depends on a configuration file '{}'.

        ----------------------------------------------------------------------------------------------------------------------------------------------
        It must contain the following email variables:

        [DEFAULT]
        EMAIL_TO       Email address to send failure notifications.
        EMAIL_URL      URL of the email service

        For example:
        [DEFAULT]
        EMAIL_TO=fo-enmaas@ericsson.com
        EMAIL_URL=https://172.31.2.5/v1/emailservice/send

        The DEFAULT section can have the following optional variable:
        EXCLUDE_STRS   Comma separated list to exclude from the consul members output
                       (typically used to exclude the temp repo and Neo4j consistency check VM)

        For example:
        EXCLUDE_STRS=-neo4j-cc,temp-repo-0
        ----------------------------------------------------------------------------------------------------------------------------------------------

        ----------------------------------------------------------------------------------------------------------------------------------------------
        Each customer should have a new entry in this configuration file as below:
        [CUSTOMER_NAME]
        key=PATH_TO_PRIVATE_KEY, IP_ADDR1, [IP_ADDR2...]
        ips=IP_ADDR1, IP_ADDR2
        etc...

        For example:
        [Cellcom]
        key=~/keys/cellcom.pem
        ips=10.9.20.17, 10.9.20.30, 10.9.20.31, 10.9.20.10

        The IPs are typically the external IPs for the LAF, EMP and SCP nodes.
        ----------------------------------------------------------------------------------------------------------------------------------------------
        """.format(__file__, CONF_FILE))
    sys.exit(exit_code)


def read_cfg():
    """
    Reads the config file (defined in CONF_FILE variable) and sources e-mail and deployment(s) information.

    Validates that the deployment(s) information is valid.
    """
    log_header("VALIDATING CONFIGURATION FILE: '{}'.".format(CONF_FILE))
    check_config_file_accessible()
    source_config_file()

    for_each_deployment_run("VALIDATING '{}' DEPLOYMENT KEY AND IPs.", validate_deployment_from_config)

    logger.info("Configuration file '%s' has been Verified. Check logs for more information.", CONF_FILE)
    logger.info(SEP1)


def check_config_file_accessible():
    """
    Validates the config file (defined in CONF_FILE variable) exists and is accessible (i.e. has valid read-access).

    If fails - log error and send email. Also exit script with exit code: 1.
    """
    try:
        if not os.access(CONF_URL, os.R_OK):
            log_error("Please verify that the configuration file '{}' exists and has valid read access.".format(CONF_FILE), 1)
    except IOError as e:
        logger.error(e)
        log_error("Please verify that the configuration file '{}' exists and has valid read access.".format(CONF_FILE), 1)


def source_config_file():
    """
    Read the config file (defined in CONF_FILE variable) and source the e-mail and deployment(s) information.
    """
    config = ConfigParser.ConfigParser()
    config.readfp(open(CONF_FILE))

    source_default_config(config)
    source_enmaas_deployments_configuration(config)


class EnmConfig:
    """
    Class used to store sourced definition information.
    name == Deployment name from configuration section.
    key == private key that is used to connect to deployments where consul is accessible.
    ips == list of candidate ips used to validate deployment's health. The external addresses can be i.e. SCP, LAF, and EMP nodes.
    """

    def __init__(self, name, key, ips):
        self.name = name
        self.key = os.path.expanduser(key)
        self.ips = map(str.strip, ips.split(","))

    def __str__(self):
        return self.name

    def __repr__(self):
        return self.__str__()


def source_default_config(config):
    """
    Source default configurations for email and exclude string
    and store them as global variables.

    If EMAIL_URL config not found - log error and exit script with exit code: 3.
    If EMAIL_TO config not found - log error and exit script with exit code: 4.
    If EXCLUDE_STRS is not found then the EXLUDE_STRS is set to None.

    :param config: config file to read e-mail data from.
    """
    if not config.has_option("DEFAULT", "EMAIL_URL"):
        log_error("There was a problem reading configuration file '{}'. Variable '{}' is not set.".format(CONF_FILE, "EMAIL_URL"), 3)
    else:
        global EMAIL_URL
        EMAIL_URL = config.get("DEFAULT", "EMAIL_URL")

    if not config.has_option("DEFAULT", "EMAIL_TO"):
        log_error("There was a problem reading configuration file '{}'. Variable '{}' is not set.".format(CONF_FILE, "EMAIL_TO"), 4)
    else:
        global EMAIL_TO
        EMAIL_TO = config.get("DEFAULT", "EMAIL_TO")

    global EXCLUDE_STRS
    if config.has_option("DEFAULT", "EXCLUDE_STRS"):
        EXCLUDE_STRS = config.get("DEFAULT", "EXCLUDE_STRS").split(',')
    else:
        EXCLUDE_STRS = []


def source_enmaas_deployments_configuration(config):
    """
    Source Deployment(s) configurations and store them as a list of EnmConfig objects.

    If there is a problem with Deployment(s)- log error and send email with exit code: 2
    .
    If no Deployments found - log error and send email. Also exit script with exit code: 5.

    :param config: config file to read Deployment(s) configuration from.
    """
    sections = config.sections()
    logger.info("The following deployments are defined: %s.", sections)
    for section in sections:
        try:
            key = config.get(section, "key")
            ENMAAS_CONFS.append(EnmConfig(section, key, config.get(section, "ips")))
        except Exception as e:
            send_deployment_validation_failed_email("Problem with configuration file: '{}'.".format(CONF_FILE),
                                                    "There was a problem reading configuration file '{}'. {}. Exit code: {}.".format(CONF_FILE, e, 2))
    if len(ENMAAS_CONFS) == 0:
        send_deployment_validation_failed_email("Problem with configuration file: '{}'.".format(CONF_FILE),
                                                "There was a problem reading configuration file '{}'. No configured ENMaaS Deployments found. "
                                                "Exit code: {}.".format(CONF_FILE, 5))
        sys.exit(5)


def for_each_deployment_run(log_message, function_to_run):
    """
    Helper function that invokes provided function on each sourced Deployment.

    :param log_message: custom log message to output the execution state/flow.
    :param function_to_run: provided function to be run on each sourced Deployment.
    """
    logger.info("Running '%s' on each deployment: '%s'.", function_to_run.__name__, ENMAAS_CONFS)
    for enmaas_conf in ENMAAS_CONFS:
        log_header(log_message.format(enmaas_conf.name))
        function_to_run(enmaas_conf.name, enmaas_conf.key, enmaas_conf.ips)


def validate_deployment_from_config(deployment_name, key, ips):
    """
    Validates that sourced deployment(s) information is valid:
    1. Provided private key is verified to be accessible and to be Private Key.
    2. Each provided IP is verified to be valid IP.
    3. Each provided IP is verified to be accessible via ping operation.

    :param deployment_name: name of Deployment whose configs are being validated.
    :param key: path to Deployment's private key
    :param ips: list of Deployment's service IPs
    """
    logger.info("'%s' has key of '%s' and ips of '%s' configured.", deployment_name, key, ips)
    try:
        validate_private_key(key)
    except ValueError as e:
        send_deployment_validation_failed_email(e.args[0], e.args[1])
    else:
        for ip in ips:
            try:
                validate_is_ip(deployment_name, ip)
                validate_host_is_accessible(deployment_name, ip)
            except ValueError as e:
                send_deployment_validation_failed_email(e.args[0], e.args[1])


def validate_private_key(key):
    """
    Validates provided key file to exist and be in read-access mode;
    Also validates the content of the file to contain "PRIVATE KEY" which implies that this file is a private key file.

    If key is not accessible (i.e. doesn't exist or can't be read) - log error and send email with exit code: 6.
    If key is not a private key (i.e. doesn't contain "PRIVATE KEY") - log error and send email with exit code: 7.

    :param key: path to private key.
    """
    try:
        if os.access(key, os.R_OK):
            logger.info("'%s' has read-access - OK.", key)
        else:
            raise ValueError("Problem with private key file: '{}'.".format(key),
                             "Please verify that the private key file '{}' exists and has valid read access. Exit code: {}.".format(key, 6))
    except IOError as e:
        logger.error(e)
        raise ValueError("Problem with private key file: '{}'.".format(key),
                         "Please verify that the private key file '{}' exists and has valid read access. Exit code: {}.".format(key, 6))
    if not "PRIVATE KEY" in open(key).read():
        raise ValueError("Problem with private key file: '{}'.".format(key),
                         "Please verify that the private key file '{}' is a valid private key file. Exit code: {}.".format(key, 7))
    else:
        logger.info("'%s' is a private key file.", key)


def validate_is_ip(deployment_name, ip):
    """
    Validates provided IP to be valid IP.

    If IP is invalid - log error and send email with exit code: 8.

    :param deployment_name: name of Deployment.
    :param ip: IP in string format to be validated.
    """
    try:
        socket.inet_aton(ip)
    except socket.error:
        raise ValueError(deployment_name,
                         "Problem with '{}' Deployment's IP: '{}'.".format(deployment_name, ip),
                         "This '{}' is invalid IP address. Exit code: {}.".format(ip, 8))


def validate_host_is_accessible(deployment_name, ip):
    """
    Validates IP is accessible.

    If IP is not accessible - log error and send email with exit code: 9.

    :param deployment_name: name of Deployment.
    :param ip: IP in string format to be validated.
    """
    if not os.system("ping -c 1 {} &>/dev/null".format(ip)) is 0:
        raise ValueError("Problem with '{}' Deployment's IP: '{}'.".format(deployment_name, ip),
                         "This '{}' IP hostname can't be reached. Exit code: {}.".format(ip, 9))
    else:
        logger.info("Host '%s' is accessible.", ip)


def log_header(log_content):
    """
    Logs message surrounded with SEP2 characters.

    :param log_content: content of log message.
    """
    logger.info(SEP2)
    logger.info(log_content)
    logger.info(SEP2)


def log_error(log_content, exit_code):
    """
    Logs message with ERROR level.
    Then exits application with provided exit code.

    :param log_content: content of log message.
    :param exit_code: exit code to exit the application with.
    """
    logger.error(log_content)
    logger.error("Exiting (exit code: %s).", exit_code)
    sys.exit(exit_code)


class DeploymentException(Exception):
    """
    Base class for exceptions in this module.
    """
    pass


class DeploymentVerificationException(DeploymentException):
    """
    Exception raised for errors when the deployment verification fails.

    :param deployment_name: Deployment's name.
    :param ip: Deployment's service IP to perform health check on.
    :param error_code: error code if consul failed to return response for some query.
    :param consul_query_command: part of log message to outline failed reason.
    """

    def __init__(self, deployment_name, ip, error_code, consul_query_command):
        self.deployment_name = deployment_name
        self.ip = ip
        self.error_code = error_code
        self.consul_query_command = consul_query_command


def check_health_of_deployment(deployment_name, key, ips):
    """
    Main method that starts Deployment health check:

    1. Establishes SSH connection to one of Deployment's service IP.
    2. Verify Deployment Health by querying consul status.

    If Deployment Health is not OK - appropriate email message will be sent to configured EMAIL_TO address.
    If ValueError is received - mark Deployment's service IP as bad_ip.
    If all provided Deployment's service IPs are marked as bad_ips - appropriate email message will be sent to configured EMAIL_TO address.

    :param deployment_name: name of Deployment to check health.
    :param key: path to Deployment's private key.
    :param ips: list of Deployment's service IPs.
    """
    bad_ips = []

    for ip in ips:
        ssh_user_and_host = '{}@{}'.format(SSH_USER, ip)
        logger.debug("Will try to SSH to %s.", ssh_user_and_host)
        ssh = Popen(['ssh', '-o', TIMEOUT, '-o', KEYCHECK, '-o', LOGLEVEL, '-i', key, ssh_user_and_host, 'bash'],
                    stdin=PIPE, stdout=PIPE, stderr=PIPE)

        logger.info("Checking connection to [Deployment: '%s'; Host: '%s'].", deployment_name, ip)
        try:
            logger.info("Checking VM status on Deployment '%s' hosts.", deployment_name)
            verify_consul_members_on_hosts_or_send_email(deployment_name, ip, ssh)
            logger.info("Finished Checking VM Status on Deployment '%s'.", deployment_name)
            logger.info(SEP2)
            break
        except ValueError:
            bad_ips.append(ip)
            logger.info(SEP1)
        except DeploymentVerificationException as e:
            send_consul_query_failed_mail(e.deployment_name, e.ip, e.error_code, e.consul_query_command)
            break

    if bad_ips == ips:
        send_mail_no_good_ips(deployment_name, bad_ips)
        return
    logger.info(SEP2)


CONSUL_HOST_SYSTEM_IDENTIFIER = "enm/deprecated/global_properties/host_system_identifier"
CONSUL_INSTALL_INSTANCES = "enm/systemconfiguration/numberofinstalledinstances"


def verify_consul_members_on_hosts_or_send_email(deployment_name_from_config, ip, ssh):
    """
    Verifies Deployment's health check:

    1. Check if Consul is available. Else return "no_consul_on_host" error code.
    2. Check if deployment name property can be read from consul. Else return "missing_kv_host_system_identifier" error code.
    3. Check if number of installed instances property can be read from consul. Else return "missing_kv_consul_install_instances" error code.
    4. Check if consul members can be read from consul. Else return "failed_to_get_consul_members" error code.
    5. Check if returned consul members are healthy.

    Every response is validated and if one of error codes is returned, then:

    1. no_consul_on_host - raise ValueError.
    2. missing_kv_host_system_identifier - fallback to Deployment name from config.
    3. missing_kv_consul_install_instances - appropriate email message will be sent to configured EMAIL_TO address with error code: 21.
    4. failed_to_get_consul_members - appropriate email message will be sent to configured EMAIL_TO address with error code: 22.
    5. If no errors are reported - verify count of alive, failed and left consul members. If there are failed or left consul members,
        or alive consul members are not equal to expected consul members - appropriate email message will be sent to configured EMAIL_TO address.

    :param deployment_name_from_config: name of Deployment that was sourced from the configuration file.
    :param ip: Deployment's service IP to perform health check on.
    :param ssh: SSH connection to Deployment's service IP.
    """
    ssh_commands = """
    consul version 2>/dev/null || echo no_consul_on_host\n
    echo END-OF-CONSUL-COMMAND\n
    consul kv get '{}' 2>/dev/null || echo missing_kv_host_system_identifier\n
    echo END-OF-CONSUL-COMMAND\n
    consul kv get '{}' 2>/dev/null || echo missing_kv_consul_install_instances\n
    echo END-OF-CONSUL-COMMAND\n
    consul members || echo failed_to_get_total_consul_members\n
    echo END-OF-CONSUL-COMMAND\n
    """.format(CONSUL_HOST_SYSTEM_IDENTIFIER, CONSUL_INSTALL_INSTANCES)
    stdout, stderr = ssh.communicate(ssh_commands)

    if not stderr:
        logger.info("SSH OK on [Deployment: '%s'; Host: '%s'].", deployment_name_from_config, ip)
        split_stdout = stdout.strip().split("END-OF-CONSUL-COMMAND")

        verify_consul_is_available(deployment_name_from_config, ip, is_consul_available=split_stdout[0].strip())

        deployment_name_from_consul = get_deployment_name(deployment_name_from_config, deployment_name_from_consul=split_stdout[1].strip())
        now = datetime.datetime.now()
        log_header("'{}' ENM VIRTUAL MACHINE HEALTHCHECK STARTED AT: [{}]".format(deployment_name_from_consul, now.strftime("%Y-%m-%d %H:%M:%S")))

        expected_consul_members_count = get_expected_consul_members_count(deployment_name_from_consul,
                                                                          ip, number_of_installed_instances=split_stdout[2].strip())

        # Count members in different states
        total_consul_members_count, alive_consul_members_count, failed_consul_members, failed_consul_members_count,\
            left_consul_members, left_consul_members_count = get_consul_members(deployment_name_from_consul,
                                                                                ip, consul_members=split_stdout[3].strip())

        verify_consul_result(deployment_name_from_consul, int(expected_consul_members_count), int(total_consul_members_count),
                             int(alive_consul_members_count), failed_consul_members, int(failed_consul_members_count),
                             left_consul_members, int(left_consul_members_count))
    else:
        if "consul: command not found" in stderr:
            logger.error("Consul is not available on [Deployment: '%s'; Consul: '%s'].", deployment_name_from_config, ip)
            raise ValueError("no_consul_on_host")
        else:
            logger.error("Cannot SSH on [Deployment: '%s'; Host: '%s']. Code: %s. (%s)",
                         deployment_name_from_config, ip, ssh.returncode, stderr)
            raise ValueError("no_ssh_available")


def verify_consul_is_available(deployment_name_from_config, ip, is_consul_available):
    """
    Verify if consul is available on the service.

    If no consul available - raise ValueError

    :param deployment_name_from_config: Deployment's name from sourced configuration file.
    :param ip: Deployment's service IP to perform health check on.
    :param is_consul_available: consul status.
    """
    if is_consul_available == "no_consul_on_host":
        logger.error("Consul is not available on [Deployment: '%s'; Consul: '%s'].", deployment_name_from_config, ip)
        raise ValueError("no_consul_on_host")
    else:
        logger.info("Consul is available on [Deployment: '%s'; Consul: '%s'].", deployment_name_from_config, ip)


def get_deployment_name(deployment_name_from_config, deployment_name_from_consul):
    """
    Get Deployment's name from consul.

    If deployment name property can't be read - fallback to use Deployment's name from sourced configuration file.

    :param deployment_name_from_config: Deployment's name from sourced configuration file.
    :param deployment_name_from_consul: Deployment's name from consul or error.
    :return: Deployment name.
    """
    if deployment_name_from_consul == "missing_kv_host_system_identifier":
        logger.warn("Failed to read '%s' from consul. Fallback to configured deployment name: '%s'.", CONSUL_HOST_SYSTEM_IDENTIFIER,
                    deployment_name_from_config)
        return deployment_name_from_config
    else:
        logger.info("Successfully read host system identifier from consul kv: '%s'", CONSUL_HOST_SYSTEM_IDENTIFIER)
        check_deployment_name(deployment_name_from_config, deployment_name_from_consul)
        return deployment_name_from_consul


def check_deployment_name(deployment_name_from_config, deployment_name_from_consul):
    """
    Check if Deployment's name from consul and from config are equal.
    Otherwise log difference as WARNING level.

    :param deployment_name_from_config: Deployment's name from sourced configuration file.
    :param deployment_name_from_consul: Deployment's name from consul.
    """
    if deployment_name_from_config != deployment_name_from_consul:
        logger.warning("Deployment name in config (%s) is different from deployment name in consul (%s).",
                       deployment_name_from_config, deployment_name_from_consul)


def get_expected_consul_members_count(deployment_name, ip, number_of_installed_instances):
    """
    Get number of installed instances from consul.

    If number of installed instances property can't be read - appropriate email message will be sent
    to configured EMAIL_TO address with error code: 21.

    :param deployment_name: Deployment's name.
    :param ip: Deployment's service IP to perform health check on.
    :param number_of_installed_instances: number of installed instances from consul or error.
    """
    if number_of_installed_instances == "missing_kv_consul_install_instances":
        raise DeploymentVerificationException(deployment_name, ip, 21, CONSUL_INSTALL_INSTANCES)
    else:
        logger.info("Successfully read consul install instances from consul kv: '%s'", CONSUL_INSTALL_INSTANCES)
        return number_of_installed_instances


def get_consul_members(deployment_name, ip, consul_members):
    """
    Gets consul members.

    If consul members can't be read - appropriate email message will be sent to configured EMAIL_TO address with error code: 22.

    :param deployment_name: Deployment's name.
    :param ip: Deployment's service IP to perform health check on.
    :param consul_members: consul members with specified status.
    """
    if consul_members == "failed_to_get_consul_members":
        raise DeploymentVerificationException(deployment_name, ip, 22, "consul members.")
    else:
        nodes = consul_members.split("\n")

        nodes = [ n for n in nodes if not any (s in n for s in EXCLUDE_STRS)]
        nodes.pop(0)
        total_consul_members = map(lambda consul_member: consul_member.split(), nodes)
        alive_consul_members = filter(lambda consul_member: consul_member[2] == 'alive', total_consul_members)
        # Will retrieve only names of failed consul members
        failed_consul_members = map(lambda consul_member: consul_member[0],
                                    filter(lambda consul_member: consul_member[2] == 'failed', total_consul_members))
        # Will retrieve only names of left consul members
        left_consul_members = map(lambda consul_member: consul_member[0],
                                  filter(lambda consul_member: consul_member[2] == 'left', total_consul_members))
        return len(total_consul_members), len(alive_consul_members), failed_consul_members,\
            len(failed_consul_members), left_consul_members, len(left_consul_members)


def send_consul_query_failed_mail(deployment_name, ip, error_code, consul_query_command):
    """
    Prepare and send mail that health check failed as consul failed to return expected response.

    :param deployment_name: Deployment's name.
    :param ip: Deployment's service IP to perform health check on.
    :param error_code: error code if consul failed to return response for some query.
    :param consul_query_command: part of log message to outline failed reason.
    """
    error_subject = "{}: ENM VM Problem, Unable to check consul - Check HA Workflows".format(deployment_name)
    error_message = "Failed to check consul on '{}': ".format(ip)
    if error_code == 21:
        error_message += "Failed to retrieve consul key '{}'.".format(consul_query_command)
    elif error_code == 22:
        error_message += "Failed to get {}.".format(consul_query_command)
    else:
        error_message += "Undefined exit code: '{}'".format(error_code)
    error_message += "\n"
    logger.warn("Deployment '%s' is unhealthy.", deployment_name)
    logger.info(SEP1)
    logger.error(error_subject)
    logger.error(error_message)
    send_mail(deployment_name, error_subject, error_message)


def verify_consul_result(deployment_name, expected_consul_members_count, total_consul_members_count, alive_consul_members_count,
                         failed_consul_members, failed_consul_members_count, left_consul_members, left_consul_members_count):
    """
    Validates response data from consul.

    :param deployment_name: Deployment's name.
    :param expected_consul_members_count: returned count of expected consul members from consul.
    :param total_consul_members_count: returned count of total consul members from consul.
    :param alive_consul_members_count: returned count of alive consul members from consul.
    :param failed_consul_members: returned names of failed consul members from consul.
    :param failed_consul_members_count: returned count of failed consul members from consul.
    :param left_consul_members: returned names of left consul members from consul.
    :param left_consul_members_count: returned count of left consul members from consul.
    """
    vm_check_status, vm_check_exit_code, error_description_msg = verify_consul_members(expected_consul_members_count, total_consul_members_count,
                                                                                       alive_consul_members_count, failed_consul_members,
                                                                                       failed_consul_members_count, left_consul_members,
                                                                                       left_consul_members_count)

    # Compare current state with install
    logger.info("VM Health Summary:")
    logger.info("Expected Members Count: %s", expected_consul_members_count)
    logger.info("Consul Members Count:   %s", total_consul_members_count)
    logger.info("Consul Alive Count:     %s", alive_consul_members_count)
    logger.info("Consul Failed Count:    %s", failed_consul_members_count)
    logger.info("Consul Left Count:      %s", left_consul_members_count)
    logger.info("Overall Status:         %s", vm_check_status)
    logger.info("Exit Code:              %s", vm_check_exit_code)
    logger.info("Exit Code Description:  %s", error_description_msg)
    log_or_send_message(deployment_name, vm_check_status, expected_consul_members_count,
                        total_consul_members_count, alive_consul_members_count, failed_consul_members,
                        failed_consul_members_count, left_consul_members, left_consul_members_count)


def verify_consul_members(expected_consul_members_count, total_consul_members_count, alive_consul_members_count, failed_consul_members,
                          failed_consul_members_count, left_consul_members, left_consul_members_count):
    """
    Alive consul members must be equal to configured expected consul members count.

    Mark health check as failed if:
    1. If there are failed consul members
    2. If there are left consul members
    3. If total consul members are not equal to expected consul members

    :param expected_consul_members_count: returned count of expected consul members from consul.
    :param total_consul_members_count: returned count of total consul members from consul.
    :param alive_consul_members_count: returned count of alive consul members from consul.
    :param failed_consul_members: returned names of failed consul members from consul.
    :param failed_consul_members_count: returned count of failed consul members from consul.
    :param left_consul_members: returned names of left consul members from consul.
    :param left_consul_members_count: returned count of left consul members from consul.
    """
    vm_check_status = "OK"
    vm_check_exit_code = 0
    error_description_msg = ""
    if alive_consul_members_count != expected_consul_members_count:
        if failed_consul_members_count > 0:
            log_members(failed_consul_members_count, "failed", failed_consul_members)
            vm_check_exit_code += 1
            error_description_msg += "FAILED_CONSUL_MEMBERS "
        if left_consul_members_count > 0:
            log_members(left_consul_members_count, "left", left_consul_members)
            vm_check_exit_code += 2
            error_description_msg += "LEFT_CONSUL_MEMBERS "
    if total_consul_members_count != expected_consul_members_count:
        vm_check_exit_code += 4
        error_description_msg += "TOO_FEW_OR_MANY_CONSUL_MEMBERS "
    if vm_check_exit_code != 0:
        vm_check_status = "FAILED"
        logger.warning("Check for ongoing HA workflows.")
        logger.warning(error_description_msg)
    else:
        logger.info("OK")
    return vm_check_status, vm_check_exit_code, error_description_msg


def log_members(consul_members_count, status, consul_members):
    """
    Log count of members of provided status.
    :param consul_members_count: count of consul members.
    :param status: status of consul members.
    :param consul_members: list of consul members with status 'left' or 'failed'.
    """
    logger.warn("There are '%s' consul members with status '%s': '%s'", consul_members_count, status, consul_members)
    logger.info(SEP1)


def log_or_send_message(deployment_name, vm_check_status, expected_consul_members_count, total_consul_members_count, alive_consul_members_count,
                        failed_consul_members, failed_consul_members_count, left_consul_members, left_consul_members_count):
    """
    Log if Deployment's health check is OK.
    Else send email.

    :param deployment_name: Deployment's name.
    :param vm_check_status: Deployment's health check status.
    :param expected_consul_members_count: returned count of expected consul members from consul.
    :param total_consul_members_count: returned count of total consul members from consul.
    :param alive_consul_members_count: returned count of alive consul members from consul.
    :param failed_consul_members: returned names of failed consul members from consul.
    :param failed_consul_members_count: returned count of failed consul members from consul.
    :param left_consul_members: returned names of left consul members from consul.
    :param left_consul_members_count: returned count of left consul members from consul.
    """
    if vm_check_status == "OK":
        logger.info("Deployment '%s' is healthy. '%s' members are up and running.", deployment_name, alive_consul_members_count)
    elif vm_check_status == "FAILED":
        logger.warn("Deployment '%s' is unhealthy.", deployment_name)
        subject = "'{}' ENM VM Problem - Check HA Workflows.".format(deployment_name)
        message = """Expected VMs count: '{}', Total VMs count: '{}', Failed VMs count: '{}', Left VMs count: '{}'.
        """.format(expected_consul_members_count, total_consul_members_count, failed_consul_members_count, left_consul_members_count)
        if failed_consul_members_count > 0:
            message += """Failed consul members: '{}'
            """.format(failed_consul_members)
        if left_consul_members_count > 0:
            message += """Left consul members: '{}'
            """.format(left_consul_members)

        message += "Check HA workflows."
        logger.info(SEP1)
        logger.error(subject)
        logger.error(message)
        send_mail(deployment_name, subject, message)


def send_deployment_validation_failed_email(subject, message):
    """
    Logs and sends appropriate message when Deployment Validation has failed.
    Refer to "Configuration Verification" section in usage for details of validation steps.


    :param subject: email health check subject.
    :param message: email health check message.
    """
    logger.info(SEP1)
    logger.error(subject)
    logger.error(message)
    send_mail("AzureVMnmaasScriptbox", subject, message)


def send_mail(deployment_name, subject, message):
    """
    Prepares and sends email over configured email service via EMAIL_URL configuration property if Deployment's health check has failed.

    :param deployment_name: Deployment's name.
    :param subject: email health check subject.
    :param message: email health check message.
    """
    from_sender = "{}@ericsson.com".format(deployment_name)
    logger.info("Sending mail from '%s' to '%s'.", from_sender, EMAIL_TO)

    json_string = {"personalizations": [{"to": [{"email": EMAIL_TO}], "subject": subject}],
                   "from": {"email": from_sender},
                   "content": [{"type": "text/plain", "value": message}]}
    post_data = json.dumps(json_string).encode("utf8")
    req = urllib2.Request(EMAIL_URL, data=post_data, headers={'cache-control': 'no-cache', 'content-type': 'application/json'})
    try:
        response = urllib2.urlopen(req, timeout=10)
        if response.code == 200:
            logger.info("Sent email to: '%s'.", EMAIL_TO)
        else:
            logger.error("Failed to send email to: '%s'. Bad response: '%s' - '%s'", EMAIL_TO, response.status_code, response)
    except urllib2.URLError as e:
        logger.error("Failed to send email to: '%s'. Exception: %s", EMAIL_TO, e)
    finally:
        logger.info(SEP1)


def send_mail_no_good_ips(deployment_name, bad_ips):
    """
    Prepares and sends email over configured email service via EMAIL_URL configuration property if all Deployment's configured service IPs
    can't be reached.

    :param deployment_name: Deployment's name.
    :param bad_ips: Deployment's configured service IPs.
    """
    subject = "'{}': ENM VM Problem, Unable to SSH to VMs - Check HA Workflows".format(deployment_name)
    message = "Failed to SSH to [Deployment: '{}'; Hosts: {}].".format(deployment_name, bad_ips)
    logger.error("Unable to check consul for Deployment '%s', no IPs are reachable.", deployment_name)
    logger.info(SEP1)
    logger.error(subject)
    logger.error(message)
    send_mail(deployment_name, subject, message)


# Help message is displayed when script is run with '--usage' argument.
if args.usage:
    usage()
logger.debug(SEP2)
logger.debug("Started logging in '%s'.", args.log_file + ".log")
read_cfg()
for_each_deployment_run("CHECKING VM HEALTH ON '{}' DEPLOYMENT.", check_health_of_deployment)
