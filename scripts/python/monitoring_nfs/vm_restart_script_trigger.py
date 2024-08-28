import ConfigParser
import datetime
import argparse
import json
import os.path
import sys
from subprocess import PIPE, Popen
import time


if __name__ == '__main__':
    global args
    parser = argparse.ArgumentParser()
    parser.add_argument("deployment_name", help="Provide deployment name.")
    parser.add_argument("vm_list", help="Provide ENM VM list to restart.")
    #parser.add_argument("--usage", help="Display help.", action="store_true")
    args = parser.parse_args()

DEPLOYMENT_NAME = args.deployment_name

HOME_DIR = "/home"

NFS_MONITORING_DIR_NAME = "monitoring_nfs"


SEP1 = "-----------------------------------------------------------------------------------" \
    + "-----------------"
SEP2 = "==================================================================================="

VM_LIST_ARG = args.vm_list
VM_LIST = []


def print_header(content):
    """
    Prints message surrounded with SEP2 characters.

    :param content: content of print message.
    """
    print(SEP2)
    print(content)
    print(SEP2)


def print_error(content, exit_code):
    """
    Prints message with ERROR level.
    Then exits application with provided exit code.

    :param content: content of print message.
    :param exit_code: exit code to exit the application with.
    """
    print(content)
    print("Exiting (exit code: %s)." % exit_code)
    sys.exit(exit_code)


CONF_FILE = "nfs_mount_check.cfg"
EMP_HOST_IP_INDEX = 0
LAF_HOST_IP_INDEX = 1
ENMAAS_CONFS = []

SSH_USER = "cloud-user"

SSH_USER_HOME_DIR = os.path.join(HOME_DIR, SSH_USER)

VM_RESTART_FILE_NAME = "vm_restart.py"
VM_HEALTHCHECK_PASS_WAIT_FILE_NAME = "vm_healthcheck_pass_wait.py"

VM_RESTART_FILE_PATH = os.path.join(HOME_DIR,
                                    NFS_MONITORING_DIR_NAME,
                                    VM_RESTART_FILE_NAME)
VM_HEALTHCHECK_PASS_WAIT_FILE_PATH = os.path.join(HOME_DIR,
                                                  NFS_MONITORING_DIR_NAME,
                                                  VM_HEALTHCHECK_PASS_WAIT_FILE_NAME)

TIMEOUT = "ConnectTimeout=60"
KEYCHECK = "StrictHostKeyChecking=no"
LOGLEVEL = "LogLevel=ERROR"
CLI_EXECUTION_TIMEOUT = "10"
HOST_IDENTIFICATION_CHANGE_MESSAGE = "WARNING: REMOTE HOST IDENTIFICATION HAS CHANGED!"
KEYBOARD_INTERACTIVE_AUTHENTICATIO_DISABLED_MESSAGE = \
    "Keyboard-interactive authentication is disabled to avoid man-in-the-middle attacks."

BYTE_TO_STRING_DECODE_TYPE_UTF_8 = "utf-8"

NFS_MONITORING_DIR = os.path.join(HOME_DIR, NFS_MONITORING_DIR_NAME,
                                  DEPLOYMENT_NAME, NFS_MONITORING_DIR_NAME)

NFS_MONITORING_DIR_ON_EMP = os.path.join(SSH_USER_HOME_DIR, NFS_MONITORING_DIR_NAME)
VM_RESTART_FILE = os.path.join(NFS_MONITORING_DIR_ON_EMP, VM_RESTART_FILE_NAME)
VM_HEALTHCHECK_PASS_WAIT_FILE = os.path.join(NFS_MONITORING_DIR_ON_EMP,
                                             VM_HEALTHCHECK_PASS_WAIT_FILE_NAME)

CONF_FILE_PATH = os.path.join(HOME_DIR, NFS_MONITORING_DIR_NAME, CONF_FILE)

PYTHON_BIN_ON_EMP_HOST = "/bin/python"

STATUS_OK = "OK"
STATUS_FAILED = "FAILED"
STATUS_SKIPPED = "SKIPPED"

DEFAULT_EAMIL_SUBJECT_FOR_FAIL = "[{}] VM restart script execution failed"\
    .format(DEPLOYMENT_NAME)

VM_BATCH_COUNT = 10

CONSUL_MEMBERS_COMMAND = "consul members"
CONSUL_MEMBER_STATUS_ALIVE = "alive"

SLEEP_TIME_AFTER_CONSUL_KILL = 60
SLEEP_TIME_BETWEEN_CONSUL_CHECK_FOR_VM_STATUS_ALIVE = 30
TIMEOUT_FOR_VM_STATUS_ALIVE = 300
SLEEP_TIME_AFTER_VM_STATUS_ALIVE = 180

SLEEP_TIME_BETWEEN_VM_HEALTHCHECK_STATUS_CHECK = 30
TIMEOUT_FOR_VM_HEALTHCHECK_STATUS_PASS = 300

VM_RESTART_RESULT = {}
VM_STATUS_ALIVE_RESULT = {}
VM_COUNT = 0
INVALID_VM_DICT = {}
INVALID_VM_COUNT = 0
VALID_VM_LIST_STRING = ""
VM_HEALTHCHECK_RESULT = {}


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


def source_enmaas_deployments_configuration(config):
    """
    Source Deployment(s) configurations and store them as a list of EnmConfig objects.

    If there is a problem with Deployment(s)- print error and send email with exit code: 2
    .
    If no Deployments found - print error and send email. Also exit script with exit code: 5.

    :param config: config file to read Deployment(s) configuration from.
    """
    try:
        key = config.get(DEPLOYMENT_NAME, "key")
        ENMAAS_CONFS.append(EnmConfig(DEPLOYMENT_NAME, key, config.get(DEPLOYMENT_NAME, "ips")))
    except Exception as e:
        print_error("Problem with configuration file: '{}'."
                    .format(CONF_FILE),
                    "There was a problem reading configuration file "
                    "'{}'. {}. Exit code: {}.".format(CONF_FILE, e, 2), 2)

    if len(ENMAAS_CONFS) == 0:
        print_error("Problem with configuration file: '{}'."
                    .format(CONF_FILE),
                    "There was a problem reading configuration file "
                    "'{}'. No configured ENMaaS Deployments found. "
                    "Exit code: {}.".format(CONF_FILE, 5), 5)


def for_deployment_run(print_message, function_to_run):
    """
    Helper function that invokes provided function on each sourced Deployment.

    :param print_message: custom print message to output the execution state/flow.
    :param function_to_run: provided function to be run on each sourced Deployment.
    """
    print("Running '%s' on deployment: '%s'." % (function_to_run.__name__, ENMAAS_CONFS))
    enmaas_conf = ENMAAS_CONFS[0]
    print_header(print_message.format(enmaas_conf.name))
    function_to_run(enmaas_conf.name, enmaas_conf.key, enmaas_conf.ips)


def perform_scp(ssh_user, host_ip, ssh_key, local_path, remote_path, local_to_remote=True,
                remote_file_is_dir=True):

    ssh_user_host_and_remote_path = '{}@{}:{}'.format(ssh_user, host_ip, remote_path)
    #print("Will try to SCP to/from local path : %s." % local_path)
    #print("Will try to SCP to/from remote path : %s." % ssh_user_host_and_remote_path)

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
        print("SCP OK on [Host: '%s']." % host_ip)
    else:
        message = "SCP failed on [Host: '%s']. Code: %s." % (host_ip, retval)
        print_error(message, 11)


def execute_commands_on_remote_host(ssh_user, host_ip, ssh_key, ssh_commands):

    ssh_user_and_host = '{}@{}'.format(ssh_user, host_ip)
    #print("Will try to SSH to %s." % ssh_user_and_host)
    print("SSH commands :\n%s" % ssh_commands)

    ssh = Popen(['ssh', '-t', '-q', '-o', TIMEOUT, '-o', KEYCHECK, '-o', LOGLEVEL,
                 '-i', ssh_key, ssh_user_and_host, 'bash'],
                stdin=PIPE, stdout=PIPE, stderr=PIPE)

    if not isinstance(ssh_commands, bytes):
        ssh_commands = ssh_commands.encode(BYTE_TO_STRING_DECODE_TYPE_UTF_8)

    stdout, stderr = ssh.communicate(ssh_commands)

    if ssh.returncode == 0:
        #print("SSH commands OK on [Host: '%s']." % host_ip)
        return stdout

    else:
        stderr = stderr.strip()
        print("SSH command error :\n%s" % stderr)
        message = "SSH commands execution failed on [Host: '%s']. Code: %s. " \
                  "Error :\n%s" % (host_ip, ssh.returncode, stderr)
        print_error(message, 10)


def execute_vm_restart_script_and_parse_response(deployment_name, key, ips):

    emp_host_ip = ips[EMP_HOST_IP_INDEX]

    ssh_command = "{} {} '{}'".format(PYTHON_BIN_ON_EMP_HOST, VM_RESTART_FILE, VM_LIST_ARG)
    vm_restart_results = execute_commands_on_remote_host(SSH_USER, emp_host_ip, key, ssh_command)

    parse_vm_restart_script_response(vm_restart_results)


def execute_vm_healthcheck_pass_wait_script_and_parse_response(deployment_name, key, ips):

    emp_host_ip = ips[EMP_HOST_IP_INDEX]

    print_header("FOR EACH VM : SLEEP = {} sec, TIMEOUT = {} sec"
                 .format(SLEEP_TIME_BETWEEN_VM_HEALTHCHECK_STATUS_CHECK,
                         TIMEOUT_FOR_VM_HEALTHCHECK_STATUS_PASS))

    ssh_command = "{} {} '{}'".format(PYTHON_BIN_ON_EMP_HOST,
                                      VM_HEALTHCHECK_PASS_WAIT_FILE, VALID_VM_LIST_STRING)
    vm_healthcheck_results = execute_commands_on_remote_host(SSH_USER, emp_host_ip, key,
                                                             ssh_command)

    parse_vm_healthcheck_pass_wait_script_response(vm_healthcheck_results)


def get_character_length_times(character, length):
    line = ""
    for i in range(length):
        line += character
    return line


def get_table_format(stale_mounts_list):
    longest_cols = [
        (max([len(str(row[i])) for row in stale_mounts_list]))
        for i in range(len(stale_mounts_list[0]))
    ]

    total_col_length = 1
    for longest_col in longest_cols:
        total_col_length += longest_col + 3

    row_format = "| " + " | ".\
        join(["{:<" + str(longest_col) + "}" for longest_col in longest_cols]) + " |"

    row_count = 0
    table_lines = ""
    for row in stale_mounts_list:
        if row_count == 0:
            table_lines += get_character_length_times("=", total_col_length) + "\n"

        table_lines += row_format.format(*row) + "\n"

        if row_count == 0:
            table_lines += get_character_length_times("=", total_col_length) + "\n"

        row_count += 1

    table_lines += get_character_length_times("=", total_col_length)

    return table_lines


def print_vm_healthcheck_results():

    global VM_HEALTHCHECK_RESULT

    vm_list = [["VM NAME", "IP ADDRESS", "HEALTHCHECK STATUS", "REASON", "OUTPUT"]]
    for index, vm in VM_HEALTHCHECK_RESULT.items():
        vm_list.append([vm['name'], vm['ip_address'],
                        vm['vm_healthcheck_status'], vm['reason'],
                        vm['output']])

    table_lines = get_table_format(vm_list)
    print(table_lines)


def parse_vm_healthcheck_pass_wait_script_response(output):

    #print_header("VM healthcheck pass wait script output")
    #print(output)

    try:
        output = json.loads(output)
    except ValueError as e:
        print_error(output, 18)

    status = output['status']
    if status != STATUS_OK:
        message = "[{}] VM healthcheck pass wait script execution had issue(s).\n".format(
            DEPLOYMENT_NAME)
        message += output['message'] + "\n\n"
        message += "NOTE : For more information, check vm_healthcheck_pass_wait.py.log on EMP node."

        print_error(message, 21)

    global VM_HEALTHCHECK_RESULT
    VM_HEALTHCHECK_RESULT = output['vm_healthcheck_result']

    print_vm_healthcheck_results()


def parse_vm_restart_script_response(output):

    #print_header("VM restart script output")
    #print(output)

    try:
        output = json.loads(output)
    except ValueError as e:
        print_error(output, 18)

    status = output['status']
    if status != STATUS_OK:
        message = "[{}] VM restart script execution had issue(s).\n".format(DEPLOYMENT_NAME)
        message += output['message'] + "\n\n"
        message += "NOTE : For more information, check vm_restart.py.log on EMP node."

        print_error(message, 20)

    global VM_RESTART_RESULT
    VM_RESTART_RESULT = output['vm_restart_result']


def get_vm_list():

    vm_list_splitted = VM_LIST_ARG.strip().split(",")

    if len(vm_list_splitted) > 10:
        print("VM list should have maximum 10 VMs.")
        exit(1)

    print_header("VM list input")

    for vm in vm_list_splitted:
        vm = vm.strip()
        VM_LIST.append(vm)
        print(vm)

    print(SEP2)


def parse_consul_members(consul_members_output):

    try:
        consul_members_output_split = consul_members_output.split("\n")
        consul_members_dict = {}
        consul_member_index = 0
        for line in consul_members_output_split:
            member_details_splitted = line.split()
            address_splitted = member_details_splitted[1].split(":")
            member_details = {"name": member_details_splitted[0],
                              "ip_address": address_splitted[0], "port": address_splitted[1],
                              "status": member_details_splitted[2],
                              "type": member_details_splitted[3],
                              "build": member_details_splitted[4],
                              "protocol": member_details_splitted[5],
                              "dc": member_details_splitted[6]}
            consul_members_dict[consul_member_index] = member_details
            consul_member_index += 1

        return consul_members_dict

    except (IndexError, Exception) as e:
        print_error("Error while parsing consul members from output [%s]. "
                    "Error : [%s]" % (consul_members_output, str(e)), 14)


def print_bad_vms():

    global INVALID_VM_DICT

    if len(INVALID_VM_DICT) != 0:

        print_header("Invalid or Failed (to kill consul process) VMs LIST")

        vm_list = [["VM NAME", "IP ADDRESS", "CONSUL KILL STATUS", "REASON", "OUTPUT"]]
        for index, vm in INVALID_VM_DICT.items():
            vm_list.append([vm['name'], vm['ip_address'],
                            vm['consul_kill_status'], vm['reason'],
                            vm['output']])

        table_lines = get_table_format(vm_list)
        print(table_lines)


def wait_for_vm_batch_to_come_up(deployment_name, key, ips):

    emp_host_ip = ips[EMP_HOST_IP_INDEX]

    global VM_RESTART_RESULT
    global INVALID_VM_DICT
    global INVALID_VM_COUNT
    global VALID_VM_LIST_STRING

    grep_options = "grep"
    for index, vm in VM_RESTART_RESULT.items():
        if vm['consul_kill_status'] == STATUS_OK or vm['consul_kill_status'] == STATUS_SKIPPED:
            vm_name = vm['name']
            grep_options += " -e {}".format(vm_name)
            VALID_VM_LIST_STRING += "{},".format(vm_name)
        else:
            INVALID_VM_DICT[INVALID_VM_COUNT] = vm
            INVALID_VM_COUNT += 1

    VALID_VM_LIST_STRING = VALID_VM_LIST_STRING[:-1]

    print_bad_vms()

    if grep_options != "grep":

        start_time = time.time()
        while True:

            ssh_command = CONSUL_MEMBERS_COMMAND + " | " + grep_options
            consul_members_output = execute_commands_on_remote_host(SSH_USER, emp_host_ip, key,
                                                                    ssh_command)
            consul_members_output = consul_members_output.strip()
            print("Consul members output :")
            print(SEP1)
            print(consul_members_output)
            print(SEP1)

            consul_members_dict = parse_consul_members(consul_members_output)

            all_vm_are_alive = True
            for index, consul_member in consul_members_dict.items():
                status = consul_member['status']

                if status != CONSUL_MEMBER_STATUS_ALIVE:
                    all_vm_are_alive = False
                    break

            if all_vm_are_alive is True:
                print_header("SUCCESS : All VM restarted and status became 'alive'")
                break

            time.sleep(SLEEP_TIME_BETWEEN_CONSUL_CHECK_FOR_VM_STATUS_ALIVE)

            end_time = time.time()

            if (end_time - start_time) >= TIMEOUT_FOR_VM_STATUS_ALIVE:
                print_header("FAIL : All VM status is not 'alive' within {} seconds."
                             .format(TIMEOUT_FOR_VM_STATUS_ALIVE))
                break


def copy_scripts_to_emp(deployment_name, key, ips):

    emp_host_ip = ips[EMP_HOST_IP_INDEX]

    # Copy vm_restart.py to EMP host
    perform_scp(SSH_USER, emp_host_ip, key, VM_RESTART_FILE_PATH, NFS_MONITORING_DIR_ON_EMP)

    # Copy vm_healthcheck_pass_wait.py to EMP host
    perform_scp(SSH_USER, emp_host_ip, key, VM_HEALTHCHECK_PASS_WAIT_FILE_PATH,
                NFS_MONITORING_DIR_ON_EMP)


# Read config file
read_cfg()

# Get Serves list from passed argument
get_vm_list()

# Copy vm_restart.py to EMP host
for_deployment_run("COPY VM RESTART AND HEALTHCHECK WAIT SCRIPT ON EMP HOST", copy_scripts_to_emp)

# Trigger vm_restart.py file on EMP host and parse response
for_deployment_run("EXECUTE VM RESTART SCRIPT ON EMP HOST AND PARSE RESPONSE",
                   execute_vm_restart_script_and_parse_response)

print_header("SLEEPING FOR %s SECONDS BEFORE WAITING TO CHECK VM STATUS ALIVE"
             % SLEEP_TIME_AFTER_CONSUL_KILL)
time.sleep(SLEEP_TIME_AFTER_CONSUL_KILL)

# Wait for VM batch to become 'alive'
for_deployment_run("WAIT FOR VM STATUS TO BE ALIVE (SLEEP = {} sec, TIMEOUT = {} sec)"
                   .format(SLEEP_TIME_BETWEEN_CONSUL_CHECK_FOR_VM_STATUS_ALIVE,
                           TIMEOUT_FOR_VM_STATUS_ALIVE),
                   wait_for_vm_batch_to_come_up)

print_header("SLEEPING FOR %s SECONDS BEFORE WAITING TO CHECK VM HEALTHCHECK STATUS PASS"
             % SLEEP_TIME_AFTER_VM_STATUS_ALIVE)
time.sleep(SLEEP_TIME_AFTER_VM_STATUS_ALIVE)

# Trigger vm_healthcheck_pass_wait.py file on EMP host and parse response
for_deployment_run("EXECUTE VM HEALTHCHECK PASS WAIT SCRIPT ON EMP HOST AND PARSE RESPONSE",
                   execute_vm_healthcheck_pass_wait_script_and_parse_response)
