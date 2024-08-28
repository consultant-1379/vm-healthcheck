import ConfigParser
import datetime
import argparse
import json
import logging
from logging.handlers import RotatingFileHandler
import os.path
import socket
import shutil
import ssl
import sys
import urllib2
from subprocess import PIPE, Popen


if __name__ == '__main__':
    global args
    parser = argparse.ArgumentParser()
    parser.add_argument("deployment_name", help="Provide deployment name.")
    parser.add_argument("log_file", default="nfs_mount_check_for_deployment.py", nargs="?",
                        help="Provide log file name.")
    #parser.add_argument("--usage", help="Display help.", action="store_true")
    args = parser.parse_args()

DEPLOYMENT_NAME = args.deployment_name

HOME_DIR = "/home"

NMAAS_SCRIPTBOX_USER = "nmaasuser"

NFS_MONITORING_DIR_NAME = "monitoring_nfs"

NFS_MONITORING_DIR = os.path.join(HOME_DIR, NMAAS_SCRIPTBOX_USER, NFS_MONITORING_DIR_NAME)

SEP1 = "-----------------------------------------------------------------------------------"
SEP2 = "==================================================================================="
LOG = os.path.join(NFS_MONITORING_DIR, "logs") + "/" + args.log_file +\
      "." + DEPLOYMENT_NAME + ".log"
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
    sh = logging.StreamHandler()
    sh.setLevel(logging.DEBUG)
    sh.setFormatter(formatter)
    logger.addHandler(sh)
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

NFS_MOUNT_CHECK_TRIGGER_FILE_NAME = "nfs_mount_check_trigger.py"

NFS_MOUNT_CHECK_FILE_PATH = os.path.join(NFS_MONITORING_DIR, NFS_MOUNT_CHECK_TRIGGER_FILE_NAME)

PYTHON_BIN_PATH = "/usr/bin/python"

CLI_EXECUTION_TIMEOUT = "10"

CONF_FILE_PATH = os.path.join(NFS_MONITORING_DIR, CONF_FILE)

DEFAULT_EAMIL_SUBJECT_FOR_FAIL = "[{}] NFS stale mount check script execution failed"\
    .format(DEPLOYMENT_NAME)


def read_cfg():
    """
    Reads the config file (defined in CONF_FILE variable) and sources e-mail and
    deployment(s) information.

    Validates that the deployment(s) information is valid.
    """
    log_header("VALIDATING CONFIGURATION FILE: '{}'.".format(CONF_FILE_PATH))
    check_config_file_accessible()
    source_config_file()

    for_deployment_run("VALIDATING '{}' DEPLOYMENT KEY AND IPs.", validate_deployment_from_config)

    logger.info("Configuration file '%s' has been Verified. Check logs for more information.",
                CONF_FILE)
    logger.info(SEP1)


def check_config_file_accessible():
    """
    Validates the config file (defined in CONF_FILE variable) exists and is accessible
    (i.e. has valid read-access).

    If fails - log error and send email. Also exit script with exit code: 1.
    """
    try:
        if not os.access(CONF_FILE_PATH, os.R_OK):
            log_error("Please verify that the configuration file '{}' exists "
                      "and has valid read access.".format(CONF_FILE), 1)
    except IOError as e:
        logger.error(e)
        log_error("Please verify that the configuration file '{}' exists "
                  "and has valid read access.".format(CONF_FILE), 1)


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
        raise ValueError("Problem with '{}' Deployment's IP: '{}'.".format(deployment_name, ip),
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


def validate_private_key(key):
    """
    Validates provided key file to exist and be in read-access mode;
    Also validates the content of the file to contain "PRIVATE KEY" which implies that this
    file is a private key file.

    If key is not accessible (i.e. doesn't exist or can't be read) - log error and send email
    with exit code: 6.
    If key is not a private key (i.e. doesn't contain "PRIVATE KEY") - log error and send email
    with exit code: 7.

    :param key: path to private key.
    """
    try:
        if os.access(key, os.R_OK):
            logger.info("'%s' has read-access - OK.", key)
        else:
            log_error("Problem with private key file: '{}'.".format(key),
                      "Please verify that the private key file '{}' exists and has valid "
                      "read access. Exit code: {}.".format(key, 6))
    except IOError as e:
        logger.error(e)
        log_error("Problem with private key file: '{}'.".format(key),
                  "Please verify that the private key file '{}' exists and has valid "
                  "read access. Exit code: {}.".format(key, 6))

    if not "PRIVATE KEY" in open(key).read():
        log_error("Problem with private key file: '{}'.".format(key),
                  "Please verify that the private key file '{}' is a valid "
                  "private key file. Exit code: {}.".format(key, 7))
    else:
        logger.info("'%s' is a private key file.", key)


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

    logger.info("EMAIL post-data :\n%s" % str(post_data))

    ssl._create_default_https_context = ssl._create_unverified_context
    req = urllib2.Request(EMAIL_URL, data=post_data, headers={'cache-control': 'no-cache',
                                                              'content-type': 'application/json'})
    try:
        response = urllib2.urlopen(req, timeout=10)
        if response.code == 200:
            logger.info("Sent email to: '%s'.", EMAIL_TO)
        else:
            logger.error("EMAIL response :\n%s" % str(response))
            logger.error("Failed to send email to: '%s'. Bad response: '%s' - '%s'" %
                         (EMAIL_TO, response.status_code, response))
    except urllib2.URLError as e:
        logger.error("Failed to send email to: '%s'. Exception: %s" % (EMAIL_TO, str(e)))
    finally:
        logger.info(SEP1)


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
        logger.info("Executing commands locally :\n%s", command)
        ssh = Popen(command, shell=True, stdout=PIPE, stderr=PIPE)

        stdout, stderr = ssh.communicate(command)

        if ssh.returncode == 0:
            stdout = stdout.strip()
            if len(stdout) != 0:
                logger.info("Stdout :\n%s", stdout)
            return stdout

        else:
            message = "Local command execution failed. Error :\n%s" % stderr.strip()
            logger.error(message)
            send_deployment_validation_failed_email_and_exit(message, 10)

    except (OSError, Exception) as e:
        message = "Local command execution failed. Error :\n%s" % str(e)
        logger.error(message)
        send_deployment_validation_failed_email_and_exit(message, 10)


def execute_nfs_mount_check_trigger_script():

    stdout = execute_cli_locally("ps -ef | grep " + NFS_MOUNT_CHECK_TRIGGER_FILE_NAME)
    stdout_list = stdout.split("\n")

    try:
        for line in stdout_list:
            entries = line.split()
            entries_len = len(entries)
            if entries[entries_len - 2] == NFS_MOUNT_CHECK_FILE_PATH and \
                    entries[entries_len - 1] == DEPLOYMENT_NAME:
                message = "NFS mount check script is already running for the deployment : {}. " \
                          "Hence, aborting this execution.\n" \
                          "Next execution will run as per schedule in the cronjob."\
                    .format(DEPLOYMENT_NAME)
                subject = "[{}] NFS mount check script already running".format(DEPLOYMENT_NAME)
                send_deployment_validation_failed_email_and_exit(message, 0, subject)

    except (IndexError, OSError, Exception) as e:
        message = "Failed to check if NFS mount check script is running. Error :\n%s" % str(e)
        logger.error(message)
        send_deployment_validation_failed_email_and_exit(message, 1)

    execute_cli_locally("{} {} {}".format(PYTHON_BIN_PATH,
                                          NFS_MOUNT_CHECK_FILE_PATH, DEPLOYMENT_NAME))


# Read config file
read_cfg()

# Execute "nfs_mount_check_trigger.py" script if is not running already
execute_nfs_mount_check_trigger_script()
