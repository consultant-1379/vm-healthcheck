#!/usr/bin/env python2.7
##############################################################################
# COPYRIGHT Ericsson 2018
#
# The copyright to the computer program(s) herein is the property of
# Ericsson Inc. The programs may be used and/or copied only with written
# permission from Ericsson Inc. or in accordance with the terms and
# conditions stipulated in the agreement/contract under which the
# program(s) have been supplied.
##############################################################################
#This script is to check the health status of Openstack deployments
import os
import argparse
import ConfigParser
import json
import yaml
import ast
import sys
import time
import logging
from logging.handlers import RotatingFileHandler
from subprocess import PIPE, Popen

from keystoneauth1 import loading
from keystoneauth1 import session
from heatclient import client

from urllib3 import disable_warnings
disable_warnings()

parser = argparse.ArgumentParser()
parser.add_argument("deployment_name", help="Provide deployment name.")
parser.add_argument('--update-inputs', dest='update', action='store_true')
parser.add_argument('--no-update-inputs', dest='update', action='store_false')
parser.set_defaults(update=False)
args = parser.parse_args()

DEPLOYMENT_NAME = args.deployment_name
UPDATE_FLAG = args.update
GENIE_USER = "root"
HOME_DIR = "/home"
KEY_DIR_NAME = "keys"
LOGDIR_NAME = "logs"
CONF_FILE = "stack_monitor.cfg"
SED_EXCEPTION_FILE_NAME = "Sed_Exception_Parameters.txt"

STACK_MONITORING_DIR_NAME = "stack_health_check_local"
STACK_MONITORING_DIR = os.path.join(HOME_DIR, STACK_MONITORING_DIR_NAME)
LOGDIR = os.path.join(STACK_MONITORING_DIR, LOGDIR_NAME)
KEY_DIR = os.path.join(STACK_MONITORING_DIR, KEY_DIR_NAME)
LOCAL_DEPLOYMENT_DIRECTORY = os.path.join(STACK_MONITORING_DIR, DEPLOYMENT_NAME)
LOCAL_DEPLOYMENT_TEMPLATE_DIRECTORY = os.path.join(LOCAL_DEPLOYMENT_DIRECTORY, "cloud_templates")
LOCAL_SEDJSON_DIRECTORY = os.path.join(LOCAL_DEPLOYMENT_DIRECTORY, "input")
ENMAAS_CONF = []

CONF_FILE_PATH = os.path.join(STACK_MONITORING_DIR, CONF_FILE)
SED_EXCEPTION_FILE_PATH = os.path.join(STACK_MONITORING_DIR, SED_EXCEPTION_FILE_NAME)

EMP_HOST_IP_INDEX = 0
LAF_HOST_IP_INDEX = 1
SSH_USER = "cloud-user"
SED_FILE_NAME = "sed.json"

CLOUD_TEMPLATES_VERSION = "v4"
CLOUD_TEMPLATES_DIR_ON_LAF = os.path.join("/vnflcm-ext", "enm", "cloudtemplates", CLOUD_TEMPLATES_VERSION)
SSH_USER_HOME_DIR = os.path.join(HOME_DIR, SSH_USER)
CLOUD_TEMPLATES_DIR_ON_LAF_SSH_USER = os.path.join(SSH_USER_HOME_DIR, CLOUD_TEMPLATES_VERSION)

SEDJSON_FILE_ON_LAF = os.path.join("/vnflcm-ext", "enm", SED_FILE_NAME)
SEDJSON_FILE_ON_LAF_SSH_USER = os.path.join(SSH_USER_HOME_DIR, SED_FILE_NAME)

LOCAL_SED_PATH = os.path.join(LOCAL_SEDJSON_DIRECTORY, SED_FILE_NAME)

TIMEOUT = "ConnectTimeout=60"
KEYCHECK = "StrictHostKeyChecking=no"
LOGLEVEL = "LogLevel=ERROR"
BYTE_TO_STRING_DECODE_TYPE_UTF_8 = "utf-8"
CLI_EXECUTION_TIMEOUT = "10"
TAB_SEP = "\t\t\t\t\t"

# Log provisioners
SEP = "-"
SEP1 = "-----------------------------------------------------------------------------------"
SEP2 = "==================================================================================="
LOG = LOGDIR + "/" + "stack_monitoring" +\
      SEP + DEPLOYMENT_NAME + SEP + time.strftime("%Y%m%d-%H%M%S") + ".log"


class EnmConfig:
    """
    Class used to store sourced definition information.
    name == Deployment name from configuration section.
    key == private key that is used to connect to deployments where consul is accessible.
    ips == list of candidate ips used to validate deployment's health. The external addresses
    can be i.e. SCP, LAF, and EMP nodes.
    """
    def __init__(self, name, key, ips):
        self.name = name
        self.key = os.path.expanduser(key)
        self.ips = map(str.strip, ips.split(","))

    def __str__(self):
        return self.name

    def __repr__(self):
        return self.__str__()


def configure_logger():
    """
    Configures logging for this script.
    """
    global logger
    if not os.path.exists(LOGDIR):
        os.makedirs(LOGDIR)
    logger = logging.getLogger()
    logger.setLevel(logging.INFO)
    formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
    # Will configure Log file size limit as 5MB with 3 backups.
    rfh = RotatingFileHandler(LOG, maxBytes=5 * 1024 * 1024, backupCount=3)
    rfh.setLevel(logging.INFO)
    rfh.setFormatter(formatter)
    sh = logging.StreamHandler()
    sh.setLevel(logging.INFO)
    sh.setFormatter(formatter)
    logger.addHandler(sh)
    logger.addHandler(rfh)


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


def log_monitoring_errors(log_content, stc_name= None):
    """
    Logs message with ERROR level.
    Logs the errors caught in monitoring on the console and log file
    """
    logger.info(SEP1)
    logger.error("Error found in Stack: {}".format(stc_name))
    logger.error(log_content)
    logger.info(SEP1)
    return True


def for_deployment_run(log_message, function_to_run):
    """
    Helper function that invokes provided function on each sourced Deployment.

    :param log_message: custom log message to output the execution state/flow.
    :param function_to_run: provided function to be run on each sourced Deployment.
    """
    if not ENMAAS_CONF:
        log_error("Cannot fetch Config", 1)
    enmaas_conf = ENMAAS_CONF[0]
    logger.info("Running '%s' on deployment: '%s'.", function_to_run.__name__, enmaas_conf.name)
    log_header(log_message.format(enmaas_conf.name))
    function_to_run(enmaas_conf.name, enmaas_conf.key, enmaas_conf.ips)


def monitor_run(log_message, function_to_run):
    """
    Helper function that invokes provided monitor function on each sourced Deployment.
    """
    if not ENMAAS_CONF:
        log_error("Cannot fetch Config", 1)
    enmaas_conf = ENMAAS_CONF[0]
    logger.info("Running '%s' on deployment: '%s'.", function_to_run.__name__, enmaas_conf.name)
    log_header(log_message.format(enmaas_conf.name))
    function_to_run()


def read_cfg():
    config = ConfigParser.ConfigParser()
    config.readfp(open(CONF_FILE_PATH))
    source_enmaas_deployments_configuration(config)


def source_enmaas_deployments_configuration(config):
    """
    Source Deployment(s) configurations and store them as a list of EnmConfig objects.
    If there is a problem with Deployment(s)- log error with exit code: 1
    If no Deployments found - log error. Also exit script with exit code: 5.

    :param config: config file to read Deployment(s) configuration from.
    """
    try:
        key = config.get(DEPLOYMENT_NAME, "key")
        ENMAAS_CONF.append(EnmConfig(DEPLOYMENT_NAME, key, config.get(DEPLOYMENT_NAME, "ips")))
    except Exception as e:
        log_error("Invalid Deployment", 1)

    if not ENMAAS_CONF:
        log_error("Cannot fetch Config", 5)


def execute_commands_on_remote_host(ssh_user, host_ip, ssh_key, ssh_commands):
    """
    Function to execute given command on remote host. eg: on LAF server
    :param ssh_user: User for remote SSH access
    :param host_ip: Remote host ip
    :param ssh_key: SSH key for remote access
    :param ssh_commands: Commands to be executed on remote machine
    :return: If Success returns command o/p; if Failed returns Error/exception
    """
    ssh_user_and_host = '{}@{}'.format(ssh_user, host_ip)
    logger.debug("Will try to SSH to %s.", ssh_user_and_host)
    logger.debug("SSH commands :\n%s" % ssh_commands)

    ssh = Popen(['ssh', '-t', '-q', '-o', TIMEOUT, '-o', KEYCHECK, '-o', LOGLEVEL,
                 '-i', ssh_key, ssh_user_and_host, 'bash'],
                stdin=PIPE, stdout=PIPE, stderr=PIPE)

    if not isinstance(ssh_commands, bytes):
        ssh_commands = ssh_commands.encode(BYTE_TO_STRING_DECODE_TYPE_UTF_8)

    stdout, stderr = ssh.communicate(ssh_commands)

    if ssh.returncode == 0:
        logger.info("SSH commands OK on [Host: '%s']." % host_ip)
        stdout = stdout.strip()
        return stdout

    else:
        stderr = stderr.strip()
        log_error("SSH command error :\n%s" % stderr, 1)


def perform_scp(ssh_user, host_ip, ssh_key, local_path, remote_path, local_to_remote=True,
                remote_file_is_dir=True):
    """
    Function to move a file to/from remote machine from/to local environment.
    Cloud templates folder and sed file copied from LAF server using this function.
    :param ssh_user: SSH user for remote access
    :param host_ip: Host IP of remote server
    :param ssh_key: SSH key for access
    :param local_path: Local path to copy the file/folder
    :param remote_path: Remote path to fetch the file/folder from
    :param local_to_remote: Flag indicating direction of flow
    :param remote_file_is_dir: Flag indicating type of data transferred
    :return:
    """
    ssh_user_host_and_remote_path = '{}@{}:{}'.format(ssh_user, host_ip, remote_path)
    logger.debug("Will try to SCP to/from local path : %s.", local_path)
    logger.debug("Will try to SCP to/from remote path : %s.", ssh_user_host_and_remote_path)

    copy_dir = ""
    if local_to_remote:
        if os.path.isdir(local_path):
            copy_dir = "-r"
        scp = Popen("scp -q {} -o {} -o {} -o {} -i {} {} {}".
                    format(copy_dir, TIMEOUT, KEYCHECK, LOGLEVEL, ssh_key, local_path,
                           ssh_user_host_and_remote_path), shell=True)

    else:
        if remote_file_is_dir:
            copy_dir = "-r"
        scp = Popen("scp -q {} -o {} -o {} -o {} -i {} {} {}".
                    format(copy_dir, TIMEOUT, KEYCHECK, LOGLEVEL, ssh_key,
                           ssh_user_host_and_remote_path, local_path), shell=True)

    retval = scp.wait()

    if retval == 0:
        logger.info("SCP OK on [Host: '%s'].", host_ip)
    else:
        message = "SCP failed on [Host: '%s']. Code: %s." % (host_ip, retval)
        log_error(message, 1)


def print_config_values(deployment_name, key, ips):
    """
    Function to print config values from config file for user readability.
    :param deployment_name: Name of the tenant
    :param key: Local path where ssh key is stored
    :param ips: IPs of EMP node and LAF node
    :return: No return
    """
    logger.info("Deployment name: {}".format(deployment_name))
    logger.info("Key: {}".format(key))
    logger.info("Emp Ip: {} | Laf Ip: {}".format(ips[0], ips[1]))


def get_cloudtemplates_from_laf(deployment_name, key, ips):
    """
    Function to get cloud templates from LAF server for a deployment.
    Two steps are involved here:
    1. Moving the cloud template files from /vnflcm-ext/enm/cloudtemplates/v4 to /home/cloud-user
    2. Perform scp to fetch the file from /home/cloud-user to Local path
    :param deployment_name: Name of the ENM deployment
    :param key: Local path of SSH key
    :param ips: Ips of EMP and LAF nodes
    :return: No return
    """

    laf_ip = ips[LAF_HOST_IP_INDEX]

    ssh_commands = "sudo cp -r {} {}".format(CLOUD_TEMPLATES_DIR_ON_LAF, SSH_USER_HOME_DIR)

    # Copy cloudtemplates dir from root user to cloud-user
    execute_commands_on_remote_host(SSH_USER, laf_ip, key, ssh_commands)

    # Create template dir under deployment if not exists
    if not os.path.exists(LOCAL_DEPLOYMENT_TEMPLATE_DIRECTORY):
        os.makedirs(LOCAL_DEPLOYMENT_TEMPLATE_DIRECTORY)

    # Copy cloudtemplates from LAF host to local
    perform_scp(SSH_USER, laf_ip, key, LOCAL_DEPLOYMENT_TEMPLATE_DIRECTORY, CLOUD_TEMPLATES_DIR_ON_LAF_SSH_USER, local_to_remote=False)


def get_sed_json_from_laf(deployment_name, key, ips):
    """
    Function to get SED file from LAF server to local server.
    Follows same step as above function to fetch cloud templates dir.
    :param deployment_name: Name of the ENM deployment
    :param key: Local path of SSH key
    :param ips: Ips of EMP and LAF nodes
    :return: No return
    """
    laf_ip = ips[LAF_HOST_IP_INDEX]

    ssh_commands = "sudo cp -r {} {}".format(SEDJSON_FILE_ON_LAF, SSH_USER_HOME_DIR)

    # Copy sed.json file from vnflcm dir to cloud-user dir
    execute_commands_on_remote_host(SSH_USER, laf_ip, key, ssh_commands)

    # Create sed directory under deployment if not exists
    if not os.path.exists(LOCAL_SEDJSON_DIRECTORY):
        os.makedirs(LOCAL_SEDJSON_DIRECTORY)

    # Copy sed.json from LAF host to local
    perform_scp(SSH_USER, laf_ip, key, LOCAL_SEDJSON_DIRECTORY, SEDJSON_FILE_ON_LAF_SSH_USER, local_to_remote=False, remote_file_is_dir=False)


def load_template_parameters():
    """
    Function to load parameters in all template files (definition files are ignored)
    :return: Dictionary containing sets of parameters for each service in the stack
    """
    parameters = {}
    # Look at the files in the templates directory.
    # Safe to ignore the full definitions.
    try:
        local_template_dir = os.path.join(LOCAL_DEPLOYMENT_TEMPLATE_DIRECTORY, CLOUD_TEMPLATES_VERSION)
        _, _, filenames = os.walk(local_template_dir).next()
        templates = [f for f in filenames if "definition" not in f]
    except Exception as e:
        log_error("Cannot load template parameters", 5)

    # Get template name, load the file, and set values in parameters.
    for f in templates:
        template_name = f.split('.')[0]
        parameters[template_name] = set()
        with open(os.path.join(local_template_dir, f), 'r') as stream:
            contents = yaml.safe_load(stream)
        for param, _ in contents['parameters'].iteritems():
            parameters[template_name].add(param)

    return parameters


def create_heat_client():
    """
    Create Heat client for a given deployment.
    Takes all credentials from ENV. Expects keystone file for deployment to be loaded prior.
    :return: heat client
    """
    # Pull these credentials from the local environment.
    # Not sure if this is going to work from a cronjob...
    # We might have to source $HOME/rc/keystone.sh before running.
    try:
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
        # Create an openstack heat client and return it.
        loader = loading.get_plugin_loader('password')
        auth = loader.load_from_options(**credentials)
        sess = session.Session(auth=auth, verify=False)
        heat = client.Client('1', session=sess)
        return heat
    except Exception as e:
        log_error("Cannot Load Heat Client. Exception : {}".format(e), 1)


def convert_parameter(p):
    """
    The results from the Python client and the SED file and templates are
    in various inconsistent forms. So this function attempts to make the inputs
    consistent
    :param p:
    :return: converted parameter
    """
    # If it's a one-element list, return the first element.
    # If it's a multi-element list, return the list.
    if isinstance(p, list):
        if len(p) == 1:
            return p[0]
        return p
    # This is in a "try" because it won't work if the type isn't string-like.
    try:
        # If it's text fake-boolean, make it a real boolean.
        if p.lower() in ["true", "false"]:
            return p.lower() == "true"
        # If it's comma-separated, split it into a list.
        if ',' in p:
            return p.split(',')
        # If it's all digits, return an int.
        if p.isdigit():
            return int(p)
    except:
        pass
    # If nothing above was applicable, just return.
    return p


def parameters_are_equal(p1, p2):
    """
    Check if p1 == p2 in an ordered way
    :param p1:
    :param p2:
    :return: Comparison result as Boolean flag
    """
    if isinstance(p1, list):
        return set(p1) == set(p2)
    else:
        return p1 == p2


def load_sed_exception_file_as_list(file_location):
    """
    Function to load sed exception parameters text file as list
    :param file_location:
    :return: list of sed exception parameters
    """
    exception_list = []
    try:
        with open(file_location, 'r') as filehandle:
            filecontents = filehandle.readlines()

            for line in filecontents:
                # remove linebreak which is the last character of the string
                current_item = line[:-1]

                # add item to the list
                exception_list.append(current_item)
    except Exception as e:
        log_error("Cannot open Sed Exception file", 5)

    return exception_list


def fetch_parameters_for_stack(heat_client, stackid):
    """
    Function to fetch parameters (key-values) for each Stack
    :param heat_client: Heat client generated
    :param stackid: UUId for a given stack
    :return: Stack Parameters
    """
    try:
        stack_parameters = heat_client.stacks.get(stack_id=stackid).parameters
    except Exception as e:
        logger.error("Cannot fetch stack parameters for Stack id: {}\nException: {}".format(stackid, e))

    return stack_parameters


def execute_cli_locally(command, timeout=CLI_EXECUTION_TIMEOUT,
                        return_output_as_string=True):
    """
    Execute CLI locally

    :param command: Command to execute
    :param timeout: Command execution timeout
    :param return_output_as_string: If True, Return output as string, Else, as list.
    :return: stdout if command succeeds, else False
    """
    try:
        logger.debug("Executing commands locally :\n%s", command)
        ssh = Popen(command, shell=True, stdout=PIPE, stderr=PIPE)

        stdout, stderr = ssh.communicate(command)

        if ssh.returncode == 0:
            stdout = stdout.strip()
            return stdout

        else:
            log_error("Local commands [{}] execution failed. Error :\n{}".format(command, stderr), 1)

    except (OSError, Exception) as e:
        log_error("Error while running local command [{}]. Error :\n{}".format(command, str(e)), 1)


def check_stack_health():
    """
    This is the core function which performs health check for all stacks in given deployment
    Parameters are loaded from template files based on Service name (each stack in a stack list has a unique service name)
    Values for each parameters are loaded from sed file
    The expected parameter-value map is compared with each stack parameter
    :return: No return
    """
    unhealth_flag = False
    # Get list of all parameters for all services within deployment
    template_parameters = load_template_parameters()

    # Load sed file
    if os.path.exists(LOCAL_SED_PATH):
        local_sed_file = LOCAL_SED_PATH
    else:
        log_error("Cannot open Sed file Locally", 5)

    # Load sed exception file
    sed_exception_list = load_sed_exception_file_as_list(SED_EXCEPTION_FILE_PATH)

    # Set up a client to the openstack heat API.
    heat = create_heat_client()

    # Get the list of all stacks we're allowed to see.
    stacks = heat.stacks.list()

    # Load the SED file
    with open(local_sed_file, "r") as sed_file:
        sed = json.load(sed_file)
    sed_defaults = sed['parameter_defaults']

    # Run check for each stack one at a time
    for stack in stacks:
        # Get the attributes that we'll print in our errors.
        global stack_name
        global stack_uuid
        global creation_time
        stack_name = stack.stack_name
        stack_uuid = stack.id
        creation_time = stack.creation_time

        # Skip vnflcm and security group stacks.
        stacks_to_skip = ['vnflcm', 'security_group', 'laf_db_volume', 'vnf_laf', 'network_internal_stack', '_cu_key']
        if any(s in stack_name.lower() for s in stacks_to_skip):
            continue

        # Parse the stack name into a deployment id and a service name.
        stack_name_fields = stack_name.split('_')
        deployment_id = stack_name_fields[0]
        service_name = stack_name_fields[1]

        # For each stack (for a deployment) we extract the parameters here to compare with expected parameter-value map
        stack_parameters = fetch_parameters_for_stack(heat, stack_uuid)

        if deployment_id != DEPLOYMENT_NAME:
            unhealth_flag = log_monitoring_errors("Deployment name: {} mismatches with expected value".format(deployment_id), stack_name)

        if service_name not in template_parameters:
            unhealth_flag = log_monitoring_errors("Service Name: {} in Stack: {} mismatches with template".format(service_name, stack_name), stack_name)
        else:
            for key in template_parameters[service_name]:
                if key not in stack_parameters:
                    unhealth_flag = log_monitoring_errors("Mandatory Parameter: {} missing in Stack: {}".format(key, stack_name), stack_name)

            # Create a dictionary map with Keys:from Template parameter and Values:from sed.json

        for key, value in stack_parameters.iteritems():
            # Python client sometimes gives you lists translated into their text
            # representations.

            try:
                real_value = ast.literal_eval(value)
            except:
                real_value = value
            # Convert these to something consistent we can compare.
            converted_value = convert_parameter(real_value)

            # Checking if OS::stack_name in parameter list for stack is equal to StackName
            if str(key) == "OS::stack_name":
                if converted_value != stack_name:
                    unhealth_flag = log_monitoring_errors("Parameter OS::stack_name has value mismatch with Stack_name\n"
                                          "Expected value: {} Current value: {}".format(stack_name, converted_value), stack_name)

            # Run the comparison.
            if key in sed_defaults:
                converted_default = convert_parameter(sed_defaults[key])
                if not parameters_are_equal(converted_value, converted_default):
                    unhealth_flag = log_monitoring_errors("Parameter: {} Expected_Value: {} Current_Value: {}".format(key,
                                                                                                      converted_default,
                                                                                                      converted_value), stack_name)
            else:
                # skipping some keys which are expected to be not in sedfile
                if key in sed_exception_list:
                    continue
                # sed_defaults[key] = converted_value
                unhealth_flag = log_monitoring_errors("Parameter: {} is missing in sed file".format(key),
                                      stack_name)

        for key, value in stack_parameters.iteritems():
            # "ipv6" and "mtu" paramters are regularly empty
            parameters_to_skip = ['ipv6', 'external_mtu', 'external_share_ip_list']
            if any(s in key.lower() for s in parameters_to_skip):
                continue
            if len(value) == 0:
                unhealth_flag = log_monitoring_errors("Missing value for Parameter: {}".format(key), stack_name)

        # Check for empty or unset tags.
        deployment_id_tag_exists = False
        service_name_tag_exists = False
        if (stack.tags is None) or (len(stack.tags) == 0):
            unhealth_flag = log_monitoring_errors("Missing tags", stack_name)
        else:
            # Check each value to make sure it's set to something. Later,
            # next function will make sure the value is correct.
            for tag in stack.tags:
                if "=" not in tag:
                    unhealth_flag = log_monitoring_errors("Malformed tag: {}".format(tag), stack_name)
                else:
                    tag_key, tag_value = tag.split('=', 1)
                    if not tag_value:
                        unhealth_flag = log_monitoring_errors("Missing value for tag: {}".format(tag), stack_name)
                    else:
                        if tag_key == 'enm_deployment_id':
                            deployment_id_tag_exists = True
                            if tag_value != deployment_id:
                                unhealth_flag = log_monitoring_errors("Tag: {} has value mismatch with Stack Name: {}".format(tag_key, stack_name), stack_name)
                        elif tag_key == 'enm_stack_name':
                            service_name_tag_exists = True
                            if tag_value != service_name:
                                unhealth_flag = log_monitoring_errors("Tag: {} has value mismatch with Stack Name: {}".format(tag_key, stack_name), stack_name)
                        else:
                            unhealth_flag = log_monitoring_errors("Unknown Tag for stack", stack_name)

            if not deployment_id_tag_exists:
                unhealth_flag = log_monitoring_errors("Missing Key and/or Missing Value for Tag Deployment Id", stack_name)

            if not service_name_tag_exists:
                unhealth_flag = log_monitoring_errors("Missing Key and/or Missing Value for Tag Stack name")

    if not unhealth_flag:
        logger.info(SEP1)
        logger.info("Stack Health for each Stack in deployment:: OK\n"
                    "\t\t\t\t\tAll parameters verified against template files\n"
                    "\t\t\t\t\tValues of all SED parameters in stack are verified\n"
                    "\t\t\t\t\tAll Tags are verified\n"
                    "\t\t\t\t\tParameter OS::Stack Name verifed")
        logger.info(SEP1)


def check_nested_stack_status():
    """
    Function to check nested stack health status
    :return: Log errors if for any stack, the status is not equal to Update/Create complete
    """
    unhealth_flag = False
    command = "openstack stack list --nested -c 'Stack Name' -c 'Stack Status' -f json --insecure"
    output = execute_cli_locally(command)
    if not isinstance(output, str):
        stroutput = str(output)
    else:
        stroutput = output
    dictoutput = json.loads(stroutput)

    for each in dictoutput:
        if each["Stack Status"]:
            if each["Stack Status"] not in ["CREATE_COMPLETE", "UPDATE_COMPLETE"]:
                unhealth_flag = log_monitoring_errors("Stack Name: {} status : {} is not create/update completed".format(each["Stack Name"], each["Stack Status"]), each["Stack Name"])
        else:
            unhealth_flag = log_monitoring_errors("Stack Name: {} Status is empty".format(each["Stack Name"]), each["Stack Name"])

    if not unhealth_flag:
        logger.info(SEP1)
        logger.info("All Nested Stack Health OK. No errors found\n"
                    "{}Status is either UPDATE COMPLETE or CREATE COMPLETE".format(TAB_SEP))
        logger.info(SEP1)


def check_volume_attachments_status():
    """
    Function to check if for each stack with volume attachment, status is healthy
    :return: Log errors
    """
    unhealth_flag = False
    volume_uuid_list = []
    # Set up a client to the openstack heat API.
    heat = create_heat_client()

    # Get the list of all stacks we're allowed to see.
    stacks = heat.stacks.list()

    # For each stack in the deployment, we get all the Volume attachment UUID into a list

    for stack in stacks:
        current_stack_name = stack.stack_name
        current_stack_uuid = stack.id

        stacks_to_skip = ['vnflcm', 'security_group', 'laf_db_volume', 'vnf_laf', 'network_internal_stack', '_cu_key']
        if any(s in current_stack_name.lower() for s in stacks_to_skip):
            continue

        stack_parameters = fetch_parameters_for_stack(heat, current_stack_uuid)

        for key, value in stack_parameters.iteritems():
            # Python client sometimes gives you lists translated into their text
            # representations.
            try:
                real_value = ast.literal_eval(value)
            except:
                real_value = value

            if "volume_uuid_list" in key:
                if isinstance(real_value, list):
                    for each in real_value:
                        dictmap = {}
                        dictmap[str(current_stack_name)] = str(each)
                        volume_uuid_list.append(dictmap)
                else:
                    log_monitoring_errors("Key: {} does not have a list value".format(key), current_stack_name)

    logger.debug("Final list : {}".format(volume_uuid_list))
    # Now we have the complete UUID list of all volume attachments, we need to validate if for each volume, the status
    # is in-use

    for each in volume_uuid_list:
        each_uuid = next(iter(each.values()))
        each_stack = next(iter(each.keys()))
        volume_check_command = "openstack volume show {} -c status -f value --insecure".format(each_uuid)

        # execute command locally to fetch volume status
        output = execute_cli_locally(volume_check_command)
        if not isinstance(output, str):
            stroutput = str(output)
        else:
            stroutput = output

        if stroutput:
            if stroutput != "in-use":
                unhealth_flag = log_monitoring_errors("Stack Name: {} Volume UUID: {} does not have status IN-USE".format(each_stack, each_uuid), each_stack)
        else:
            unhealth_flag = log_monitoring_errors("Volume UUID: {} Status is NULL".format(each_uuid))

    if not unhealth_flag:
        logger.info(SEP1)
        logger.info("Status of all Volume Attachments verified :: OK\n"
                    "{}Status is In-Use".format(TAB_SEP))
        logger.info(SEP1)


def main():
    """
    Main execution workflow
    """
    configure_logger()
    read_cfg()
    for_deployment_run("PRINT CONFIG VALUES FOR DEPLOYMENT", print_config_values)
    if UPDATE_FLAG:
        for_deployment_run("GET CLOUD TEMPLATES FROM LAF FOR CURRENT DEPLOYMENT", get_cloudtemplates_from_laf)
        for_deployment_run("GET SED JSON FROM LAF FOR CURRENT DEPLOYMENT", get_sed_json_from_laf)
    monitor_run("MONITOR HEALTH FOR ALL STACKS IN CURRENT DEPLOYMENT", check_stack_health)
    monitor_run("CHECK NESTED STACK STATUS", check_nested_stack_status)
    monitor_run("CHECK VOLUME ATTACHMENT STATUS", check_volume_attachments_status)


if __name__ == "__main__":
    main()

