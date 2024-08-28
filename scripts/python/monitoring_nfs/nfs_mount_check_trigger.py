import ConfigParser
import datetime
import argparse
import json
import logging
from logging.handlers import RotatingFileHandler
import math
import os.path
import shutil
import ssl
import sys
import urllib2
from subprocess import PIPE, Popen


if __name__ == '__main__':
    global args
    parser = argparse.ArgumentParser()
    parser.add_argument("deployment_name", help="Provide deployment name.")
    parser.add_argument("log_file", default="nfs_mount_check_trigger.py", nargs="?",
                        help="Provide log file name.")
    #parser.add_argument("--usage", help="Display help.", action="store_true")
    args = parser.parse_args()

DEPLOYMENT_NAME = args.deployment_name

HOME_DIR = "/home"

NMAAS_SCRIPTBOX_USER = "nmaasuser"

NFS_MONITORING_DIR_NAME = "monitoring_nfs"


SEP1 = "-----------------------------------------------------------------------------------"
SEP2 = "==================================================================================="
LOG = os.path.join(HOME_DIR, NMAAS_SCRIPTBOX_USER, NFS_MONITORING_DIR_NAME, "logs") + "/" \
      + args.log_file + "." + DEPLOYMENT_NAME + ".log"

DIR = os.path.dirname(LOG)


def configure_logger():
    """
    Configures logging for this script.
    """
    global logger
    logger = logging.getLogger()
    logger.setLevel(logging.DEBUG)
    formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
    # Will configure Log file size limit as 5MB with 3 backups.
    rfh = RotatingFileHandler(LOG, maxBytes=5 * 1024 * 1024, backupCount=3)
    rfh.setLevel(logging.INFO)
    rfh.setFormatter(formatter)
    logger.addHandler(rfh)


configure_logger()


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


CONF_FILE = "nfs_mount_check.cfg"
CONF_URL = os.path.join(DIR, CONF_FILE)
EMP_HOST_IP_INDEX = 0
LAF_HOST_IP_INDEX = 1
ENMAAS_CONFS = []

SSH_USER = "cloud-user"

CLOUD_TEMPLATES_VERSION = "v4"
CLOUD_TEMPLATES_DIR_ON_LAF = os.path.join("/vnflcm-ext", "enm", "cloudtemplates",
                                          CLOUD_TEMPLATES_VERSION)
SSH_USER_HOME_DIR = os.path.join(HOME_DIR, SSH_USER)
CLOUD_TEMPLATES_DIR_ON_LAF_SSH_USER = os.path.join(SSH_USER_HOME_DIR, CLOUD_TEMPLATES_VERSION)

DEFINITION_FILE_IGNORE_LIST = ["_custom_application_name_definition.yaml",
                               "fm_definition.yaml"]

DEFINITION_YAML_FILE_POSTFIX = "_definition.yaml"
NFS_CLIENT_SHARES_CONFIG_PATH_STRING = "path: /etc/auto.enm"
CONTENT_STRING = "content: |"

NFS_CLIENT_SHARES_FILE_NAME = "nfs_client_shares.json"
NFS_MOUNT_CHECK_FILE_NAME = "nfs_mount_check.py"

NFS_MOUNT_CHECK_FILE_PATH = os.path.join(HOME_DIR, NMAAS_SCRIPTBOX_USER,
                                         NFS_MONITORING_DIR_NAME,
                                         NFS_MOUNT_CHECK_FILE_NAME)

VM_BATCH_COUNT = 20

TIMEOUT = "ConnectTimeout=60"
KEYCHECK = "StrictHostKeyChecking=no"
LOGLEVEL = "LogLevel=ERROR"
CLI_EXECUTION_TIMEOUT = "10"
HOST_IDENTIFICATION_CHANGE_MESSAGE = "WARNING: REMOTE HOST IDENTIFICATION HAS CHANGED!"
KEYBOARD_INTERACTIVE_AUTHENTICATIO_DISABLED_MESSAGE = \
    "Keyboard-interactive authentication is disabled to avoid man-in-the-middle attacks."

STALE_MOUNTS_FILE_NAME = "stale_mounts_info.json"

BYTE_TO_STRING_DECODE_TYPE_UTF_8 = "utf-8"

NFS_MONITORING_DIR_PARENT_PATH_ON_EMP_HOST = "/var"

NFS_MONITORING_DIR = os.path.join(HOME_DIR, NMAAS_SCRIPTBOX_USER, NFS_MONITORING_DIR_NAME,
                                  DEPLOYMENT_NAME, NFS_MONITORING_DIR_NAME)

NFS_MONITORING_DIR_ON_EMP = os.path.join(SSH_USER_HOME_DIR, NFS_MONITORING_DIR_NAME)
NFS_MOUNT_CHECK_FILE = os.path.join(NFS_MONITORING_DIR_ON_EMP, NFS_MOUNT_CHECK_FILE_NAME)

STALE_MOUNTS_FILE_ON_EMP = os.path.join(NFS_MONITORING_DIR_ON_EMP, STALE_MOUNTS_FILE_NAME)

STALE_MOUNTS_FILE = os.path.join(NFS_MONITORING_DIR, STALE_MOUNTS_FILE_NAME)

CONF_FILE_PATH = os.path.join(HOME_DIR, NMAAS_SCRIPTBOX_USER,
                              NFS_MONITORING_DIR_NAME, CONF_FILE)

NFS_CLIENT_SHARES_DICT = {}
STALE_MOUNTS_LIST = []
STALE_MOUNTS_COUNT = 0

PYTHON_BIN_ON_EMP_HOST = "/bin/python"

STATUS_OK = "OK"
STATUS_FAILED = "FAILED"

DEFAULT_EAMIL_SUBJECT_FOR_FAIL = "[{}] NFS stale mount check script execution failed"\
    .format(DEPLOYMENT_NAME)

STALE_MOUNTS_EMAIL_SUBJECT = "[{}] NFS shares mount issue(s) found.".format(DEPLOYMENT_NAME)
STALE_MOUNTS_EMAIL_MESSAGE_HEADER = "List of NFS clients having stale mounts " \
                                    "(NFS CLIENT, IP ADDRESS) :"
STALE_MOUNTS_EMAIL_MESSAGE_FOOTER = "NOTE : For more information, check " \
                                    "nfs_mount_check.py.log on EMP node."
STALE_MOUNTS_EMAIL_MESSAGE = ""


def read_cfg():
    """
    Reads the config file (defined in CONF_FILE variable) and sources e-mail and
    deployment(s) information.

    Validates that the deployment(s) information is valid.
    """
    source_config_file()


def source_config_file():
    """
    Read the config file (defined in CONF_FILE variable) and source the e-mail
    and deployment(s) information.
    """
    config = ConfigParser.ConfigParser()
    config.readfp(open(CONF_FILE_PATH))

    source_default_config(config)
    source_enmaas_deployments_configuration(config)


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
        log_error("There was a problem reading configuration file '{}'. "
                  "Variable '{}' is not set.".format(CONF_FILE, "EMAIL_URL"), 3)
    else:
        global EMAIL_URL
        EMAIL_URL = config.get("DEFAULT", "EMAIL_URL")

    if not config.has_option("DEFAULT", "EMAIL_TO"):
        log_error("There was a problem reading configuration file '{}'. "
                  "Variable '{}' is not set.".format(CONF_FILE, "EMAIL_TO"), 4)
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
    try:
        key = config.get(DEPLOYMENT_NAME, "key")
        ENMAAS_CONFS.append(EnmConfig(DEPLOYMENT_NAME, key, config.get(DEPLOYMENT_NAME, "ips")))
    except Exception as e:
        send_deployment_validation_failed_email("Problem with configuration file: '{}'."
                                                .format(CONF_FILE),
                                                "There was a problem reading configuration file "
                                                "'{}'. {}. Exit code: {}.".format(CONF_FILE, e, 2))

    if len(ENMAAS_CONFS) == 0:
        send_deployment_validation_failed_email("Problem with configuration file: '{}'."
                                                .format(CONF_FILE),
                                                "There was a problem reading configuration file "
                                                "'{}'. No configured ENMaaS Deployments found. "
                                                "Exit code: {}.".format(CONF_FILE, 5))
        sys.exit(5)


def for_deployment_run(log_message, function_to_run):
    """
    Helper function that invokes provided function on each sourced Deployment.

    :param log_message: custom log message to output the execution state/flow.
    :param function_to_run: provided function to be run on each sourced Deployment.
    """
    logger.info("Running '%s' on deployment: '%s'.", function_to_run.__name__, ENMAAS_CONFS)
    enmaas_conf = ENMAAS_CONFS[0]
    log_header(log_message.format(enmaas_conf.name))
    function_to_run(enmaas_conf.name, enmaas_conf.key, enmaas_conf.ips)


def send_deployment_validation_failed_email_and_exit(message, exit_code,
                                                     subject=DEFAULT_EAMIL_SUBJECT_FOR_FAIL):

    send_deployment_validation_failed_email(subject, message)
    log_error(message, exit_code)


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
    Prepares and sends email over configured email service via EMAIL_URL configuration property if
    Deployment's health check has failed.

    :param deployment_name: Deployment's name.
    :param subject: email health check subject.
    :param message: email health check message.
    """
    from_sender = "{}@ericsson.com".format(deployment_name)
    logger.info("Sending mail from '%s' to '%s'." % (from_sender, EMAIL_TO))

    json_string = {"personalizations": [{"to": [{"email": EMAIL_TO}], "subject": subject}],
                   "from": {"email": from_sender},
                   "content": [{"type": "text/plain", "value": message}]}
    post_data = json.dumps(json_string).encode("utf8")

    ssl._create_default_https_context = ssl._create_unverified_context
    req = urllib2.Request(EMAIL_URL, data=post_data, headers={'cache-control': 'no-cache',
                                                              'content-type': 'application/json'})
    try:
        response = urllib2.urlopen(req, timeout=10)
        if response.code == 200:
            logger.info("Sent email to: '%s'.", EMAIL_TO)
        else:
            logger.error("Failed to send email to: '%s'. Bad response: '%s' - '%s'" %
                         (EMAIL_TO, response.status_code, response))
    except urllib2.URLError as e:
        logger.error("Failed to send email to: '%s'. Exception: %s" % (EMAIL_TO, str(e)))
    finally:
        logger.info(SEP1)


def get_cloudtemplates_from_laf(deployment_name, key, ips):

    laf_ip = ips[LAF_HOST_IP_INDEX]

    ssh_commands = "sudo cp -r {} {}".format(CLOUD_TEMPLATES_DIR_ON_LAF, SSH_USER_HOME_DIR)

    # Copy cloudtemplates dir from root user to cloud-user
    execute_commands_on_remote_host(SSH_USER, laf_ip, key, ssh_commands)

    # Create "monitoring_nfs" dir inside deployment if not exists
    if not os.path.exists(NFS_MONITORING_DIR):
        os.makedirs(NFS_MONITORING_DIR)

    # Copy cloudtemplates from LAF host to local
    perform_scp(SSH_USER, laf_ip, key, NFS_MONITORING_DIR,
                CLOUD_TEMPLATES_DIR_ON_LAF_SSH_USER, local_to_remote=False)


def perform_scp(ssh_user, host_ip, ssh_key, local_path, remote_path, local_to_remote=True,
                remote_file_is_dir=True):

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
        send_deployment_validation_failed_email_and_exit(message, 11)


def read_definition_file_content(file):
    """
    Read *_definition.yaml file content

    :param file: file path
    :return: file content
    :raise IOError: if the file read has error
    """
    definition_file = None
    try:
        definition_file = open(file, 'r')
        definition = definition_file.read()
        return definition

    except IOError as e:
        message = "Couldn't read the definition file : %s. Error:\n%s" % (file, str(e))
        raise ValueError(DEFAULT_EAMIL_SUBJECT_FOR_FAIL, message)
    finally:
        definition_file.close()


def parse_nfs_share_info(line):
    """
    Parse NFS shares info from given line

    :param line: line content
    :return: content in dict format
    """
    try:
        line = line.strip()
        path, mount = line.split("-")
        path = path.strip()
        mount_types, mount_path = mount.split()
        mount_details = mount_types.split(",")
        mount_server, mount_path = mount_path.split(":")

        logger.debug("path = %s, mount_access = %s, mount_type = %s, mount_server = %s, "
                     "mount_path = %s" % (path, mount_details[0], mount_details[1], mount_server,
                                          mount_path))

        mount_shares_dict = {"path": path, "mount_access": mount_details[0],
                             "mount_type": mount_details[1], "mount_server": mount_server,
                             "mount_path": mount_path}

        return mount_shares_dict

    except IndexError as e:
        message = "Failed to parse info from NFS shares line : %s. Error :\n%s" % (line, str(e))
        raise ValueError(DEFAULT_EAMIL_SUBJECT_FOR_FAIL, message)


def get_nfs_shares_lines_from_definition(definition):
    """
    Get NFS shares lines from the *_definition file content

    :param definition: definition file content
    :return: lines with NFS shares info
    """
    try:
        nfs_client_shares_config_path_string = definition.find(NFS_CLIENT_SHARES_CONFIG_PATH_STRING)
        logger.debug("String [%s] index = %s" % (NFS_CLIENT_SHARES_CONFIG_PATH_STRING,
                                                 nfs_client_shares_config_path_string))
        if nfs_client_shares_config_path_string == -1:
            logger.info("No NFS client shares info found in the definition.")
            return ""

        definition = definition[definition.find(NFS_CLIENT_SHARES_CONFIG_PATH_STRING):]
        definition = definition[definition.find(CONTENT_STRING):]
        definition = definition[(len(CONTENT_STRING) + 1):definition.find("- path:")]
        definition = definition.strip()
        logger.debug("NFS client shares lines :\n%s" % definition)

        return definition

    except IndexError as e:
        message = "Failed to get NFS shares lines from definition :\n%s." \
                  "\n\nError :\n%s" % (definition, str(e))
        raise ValueError(DEFAULT_EAMIL_SUBJECT_FOR_FAIL, message)


def get_nfs_client_shares_info(cloud_templates_dir):
    """
    Get NFS client shares information from the *_definition.yaml files

    :param cloud_templates_dir: cloud templates dir where *_definition.yaml files are stored
    :return: NFS client shares info in dict format
    """
    definition_files_count = 0

    try:
        for file in os.listdir(cloud_templates_dir):
            if file.endswith(DEFINITION_YAML_FILE_POSTFIX):

                logger.info("File name : %s" % file)

                if file in DEFINITION_FILE_IGNORE_LIST:
                    logger.info("Ignoring file : %s" % file)
                    continue

                nfs_client_name = file[:file.find("_")]
                file = os.path.join(cloud_templates_dir, file)

                try:
                    definition = read_definition_file_content(file)
                except ValueError as e:
                    send_deployment_validation_failed_email(e.args[0], e.args[1])
                    continue

                try:
                    definition = get_nfs_shares_lines_from_definition(definition)
                    if definition == "":
                        continue
                except ValueError as e:
                    send_deployment_validation_failed_email(e.args[0], e.args[1])
                    continue

                nfs_shares_mount_index = 0
                NFS_CLIENT_SHARES_DICT[nfs_client_name] = {}

                lines = definition.split("\n")
                for line in lines:
                    try:
                        mount_shares_dict = parse_nfs_share_info(line)
                    except ValueError as e:
                        send_deployment_validation_failed_email(e.args[0], e.args[1])
                        continue

                    NFS_CLIENT_SHARES_DICT[nfs_client_name][nfs_shares_mount_index] = \
                        mount_shares_dict
                    nfs_shares_mount_index += 1

                logger.info(SEP1)
                definition_files_count += 1

        logger.debug(SEP2)
        logger.debug("Total definition files parsed : %s" % definition_files_count)
        logger.debug("NFS client shares info : %s" % str(NFS_CLIENT_SHARES_DICT))
        logger.debug(SEP2)

        return NFS_CLIENT_SHARES_DICT

    except OSError as e:
        message = "Failed to list files from Cloud templates dir :%s." \
                  "\n\nError :\n%s" % (cloud_templates_dir, str(e))
        send_deployment_validation_failed_email_and_exit(message, 15)

    except IndexError as e:
        message = "Failed to parse NFS client shares info from definition file : %s." \
                  "\n\nError :\n%s" % (cloud_templates_dir, str(e))
        send_deployment_validation_failed_email_and_exit(message, 16)


def store_nfs_shares_info_in_file(nfs_client_shares_file, nfs_client_shares_info):
    """
    Store NFS shares info in a file

    :param nfs_client_shares_file: NFS client shares file name
    :param nfs_client_shares_info: NFS client shares info
    """
    file = None
    try:
        file = open(nfs_client_shares_file, "w")
        file.write(nfs_client_shares_info)

    except (OSError, IOError) as e:
        message = "Couldn't write NFS client shares info to the file : %s" % nfs_client_shares_file
        send_deployment_validation_failed_email_and_exit(message, 17)
    finally:
        file.close()


def parse_cloudtemplates_and_store_nfs_client_shares_info(deployment_name, key, ips):

    cloud_templates_dir = os.path.join(NFS_MONITORING_DIR, CLOUD_TEMPLATES_VERSION)

    # Get NFS client shares info from "cloudtemplates/*_definition.yaml"
    nfs_client_shares_info = get_nfs_client_shares_info(cloud_templates_dir)

    nfs_client_shares_file = os.path.join(NFS_MONITORING_DIR, NFS_CLIENT_SHARES_FILE_NAME)

    # Store nfs_client_shares.json file in monitoring_nfs dir
    store_nfs_shares_info_in_file(nfs_client_shares_file, json.dumps(nfs_client_shares_info))


def prepare_and_copy_monitoring_nfs_dir_to_emp_host(deployment_name, key, ips):

    cloud_templates_dir = os.path.join(NFS_MONITORING_DIR, CLOUD_TEMPLATES_VERSION)

    # Copy SSH key to monitoring_nfs
    shutil.copy(key, NFS_MONITORING_DIR)

    # Copy nfs_mount_check.py to monitoring_nfs
    shutil.copy(NFS_MOUNT_CHECK_FILE_PATH, NFS_MONITORING_DIR)

    # Remove cloudtemplates dir from monitoring_nfs before copying to EMP host
    if os.path.exists(cloud_templates_dir):
        shutil.rmtree(cloud_templates_dir)

    emp_host_ip = ips[EMP_HOST_IP_INDEX]

    # Copy monitoring_nfs dir to EMP host
    perform_scp(SSH_USER, emp_host_ip, key, NFS_MONITORING_DIR, SSH_USER_HOME_DIR)


def execute_commands_on_remote_host(ssh_user, host_ip, ssh_key, ssh_commands):

    ssh_user_and_host = '{}@{}'.format(ssh_user, host_ip)
    logger.debug("Will try to SSH to %s.", ssh_user_and_host)
    logger.debug("SSH commands :\n%s" % ssh_commands)

    ssh = Popen(['ssh', '-t', '-o', TIMEOUT, '-o', KEYCHECK, '-o', LOGLEVEL,
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
        logger.error("SSH command error :\n%s" % stderr)
        message = "SSH commands execution failed on [Host: '%s']. Code: %s. " \
                  "Error :\n%s" % (host_ip, ssh.returncode, stderr)
        send_deployment_validation_failed_email_and_exit(message, 10)


def execute_nfs_check_script_and_parse_response(deployment_name, key, ips):

    emp_host_ip = ips[EMP_HOST_IP_INDEX]

    start_time = datetime.datetime.now()
    logger.info("NFS CHECK SCRIPT START TIME : %s" % start_time)
    logger.info(SEP2)

    nfs_client_shares_dict_len = len(NFS_CLIENT_SHARES_DICT)
    iterations = int(math.ceil(float(nfs_client_shares_dict_len) / VM_BATCH_COUNT))

    logger.info("NFS Client shares files count : %d" % nfs_client_shares_dict_len)
    logger.info("VM batch count : %d" % VM_BATCH_COUNT)
    logger.info("Iterations for NFS mount script execution : %d" % iterations)

    end_index = nfs_client_shares_dict_len - 1
    min_index = 0
    max_index = VM_BATCH_COUNT - 1

    for i in range(iterations):

        logging.info("Executing NFS mount check script for batch : %d - %d"
                     % (min_index, max_index))

        ssh_command = "{} {} {} {}".format(PYTHON_BIN_ON_EMP_HOST, NFS_MOUNT_CHECK_FILE,
                                           min_index, max_index)
        stale_mounts_json = execute_commands_on_remote_host(SSH_USER, emp_host_ip, key, ssh_command)

        #perform_scp(SSH_USER, emp_host_ip, key, NFS_MONITORING_DIR, STALE_MOUNTS_FILE_ON_EMP,
        #            local_to_remote=False, remote_file_is_dir=False)

        #stale_mounts_json = read_definition_file_content(STALE_MOUNTS_FILE)

        parse_nfs_check_script_response(stale_mounts_json)

        min_index = max_index + 1
        if (max_index + VM_BATCH_COUNT) <= end_index:
            max_index = max_index + VM_BATCH_COUNT
        else:
            max_index = end_index

    end_time = datetime.datetime.now()
    logger.info(SEP2)
    logger.info("NFS CHECK SCRIPT END TIME : %s" % end_time)
    logger.info("TOTAL EXECUTION TIME : %s" % (end_time - start_time))
    logger.info(SEP2)


def parse_nfs_check_script_response(output):

    global STALE_MOUNTS_COUNT
    global STALE_MOUNTS_EMAIL_MESSAGE

    logger.info("NFS check script output :\n%s" % output)

    try:
        output = json.loads(output)
    except ValueError as e:
        send_deployment_validation_failed_email_and_exit(output, 18)

    status = output['status']

    if status != STATUS_OK:
        message = output['message'] + "\n\n"

        stale_mounts_count = output['stale_mounts_count']
        if stale_mounts_count != 0:
            STALE_MOUNTS_COUNT += stale_mounts_count
            stale_mounts = output['stale_mounts']
            for index, stale_mount in stale_mounts.items():
                stale_mount_entry = [stale_mount['nfs_client'], stale_mount['ip_address']]
                if stale_mount_entry not in STALE_MOUNTS_LIST:
                    STALE_MOUNTS_LIST.append(stale_mount_entry)
                    stale_mounts_message = stale_mount['nfs_client'] + " - " + \
                        stale_mount['ip_address'] + "\n\n"
                    message += stale_mounts_message
                    STALE_MOUNTS_EMAIL_MESSAGE += stale_mounts_message

        logger.error(message)


def send_mail_on_failure():

    global STALE_MOUNTS_EMAIL_MESSAGE

    if STALE_MOUNTS_EMAIL_MESSAGE != "":
        STALE_MOUNTS_EMAIL_MESSAGE = STALE_MOUNTS_EMAIL_MESSAGE_HEADER + "\n\n" + \
                                     STALE_MOUNTS_EMAIL_MESSAGE + \
                                     STALE_MOUNTS_EMAIL_MESSAGE_FOOTER
        send_deployment_validation_failed_email(STALE_MOUNTS_EMAIL_SUBJECT,
                                                STALE_MOUNTS_EMAIL_MESSAGE)


# Read config file
read_cfg()

# Get "cloudtemplates" dir from VNF LAF
for_deployment_run("GET CLOUDTEMPLATES FROM LAF", get_cloudtemplates_from_laf)

# Parse "*_definition.yaml" files and store NFS client shares info into json files
for_deployment_run("PARSE CLOUDTEMPLATES AND STORE NFS CLIENT SHARES INFO INTO JSON",
                   parse_cloudtemplates_and_store_nfs_client_shares_info)

# Prepare and copy monitoring_nfs dir to EMP
for_deployment_run("COPY monitoring_nfs DIR TO EMP HOST",
                   prepare_and_copy_monitoring_nfs_dir_to_emp_host)

# Trigger nfs_mount_check.py file on EMP host and parse response
for_deployment_run("EXECUTE NFS CHECK SCRIPT ON EMP HOST AND PARSE RESPONSE",
                   execute_nfs_check_script_and_parse_response)

# send email thing
send_mail_on_failure()
