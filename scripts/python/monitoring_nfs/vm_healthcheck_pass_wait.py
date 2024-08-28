import argparse
import logging
from logging.handlers import RotatingFileHandler
import os.path
import sys
from subprocess import PIPE, Popen
import json
import time


if __name__ == '__main__':
    global args
    parser = argparse.ArgumentParser()
    parser.add_argument("vm_list", help="Provide ENM VM list to restart.")
    parser.add_argument("log_file", default="vm_healthcheck_pass_wait.py", nargs="?",
                        help="Provide log file name.")
    #parser.add_argument("--usage", help="Display help.", action="store_true")
    args = parser.parse_args()


VM_LIST_ARG = args.vm_list
VM_LIST = []

HOME_DIR = "/home"

SSH_USER = "cloud-user"

SSH_USER_HOME_DIR = os.path.join(HOME_DIR, SSH_USER)

NFS_MONITORING_DIR_NAME = "monitoring_nfs"
NFS_MONITORING_DIR = os.path.join(SSH_USER_HOME_DIR, NFS_MONITORING_DIR_NAME)

SEP1 = "-----------------------------------------------------------------------------------"
SEP2 = "==================================================================================="
LOG = NFS_MONITORING_DIR + "/" + args.log_file + ".log"
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


TIMEOUT = "ConnectTimeout=10"
COMMAND_TIMEOUT = "15"
KEYCHECK = "StrictHostKeyChecking=no"
LOGLEVEL = "LogLevel=ERROR"
CLI_EXECUTION_TIMEOUT = "10"
HOST_IDENTIFICATION_CHANGE_MESSAGE = "WARNING: REMOTE HOST IDENTIFICATION HAS CHANGED!"
KEYBOARD_INTERACTIVE_AUTHENTICATIO_DISABLED_MESSAGE = \
    "Keyboard-interactive authentication is disabled to avoid man-in-the-middle attacks."

SSH_KEY_POSTFIX = ".pem"

BYTE_TO_STRING_DECODE_TYPE_UTF_8 = "utf-8"

CONSUL_MEMBERS_COMMAND = "consul members"
CONSUL_MEMBER_STATUS_ALIVE = "alive"

ALL_HEALTHCHECKS_PASSED_MESSAGE = "All healthchecks passed"

STATUS_OK = "OK"
STATUS_FAILED = "FAILED"
STATUS_NOT_PASSED_YET = "NOT PASSED YET"
STATUS_PASSED = "PASSED"
STATUS_SKIPPED = "SKIPPED"

VM_BATCH_COUNT = 10

SLEEP_TIME_BETWEEN_VM_HEALTHCHECK_STATUS_CHECK = 30
TIMEOUT_FOR_VM_HEALTHCHECK_STATUS_PASS = 300

VM_HEALTHCHECK_RESULT = {}
VM_COUNT = 0


def print_response_and_exit(status, message, exit_code=0):

    response = {"status": status, "message": message,
                "vm_healthcheck_result": VM_HEALTHCHECK_RESULT}
    response = json.dumps(response)
    print(response)
    sys.exit(exit_code)


def get_ssh_key_file():

    global SSH_KEY_FILE
    try:
        for file in os.listdir(NFS_MONITORING_DIR):
            if file.endswith(SSH_KEY_POSTFIX):
                SSH_KEY_FILE = os.path.join(NFS_MONITORING_DIR, file)
                break
        if not SSH_KEY_FILE:
            print_response_and_exit(STATUS_FAILED,
                                    "Failed to find SSH key in directory {}."
                                    .format(NFS_MONITORING_DIR))

    except OSError as e:
        logger.error(e)
        print_response_and_exit(STATUS_FAILED,
                                "Error in getting SSH key in directory {}. Error: [{}]"
                                .format(NFS_MONITORING_DIR, str(e)))


def parse_consul_members(consul_members_output):

    try:
        consul_members_output_split = consul_members_output.split("\n")
        consul_members_dict = {}
        consul_member_index = 0
        for line in consul_members_output_split[1:]:
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
        logger.error(e)
        print_response_and_exit(STATUS_FAILED,
                                "Error while parsing consul members from output [%s]. "
                                "Error : [%s]" % (consul_members_output, str(e)))


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
            logger.error("Local command execution failed. Error :\n%s" % stderr)
            print_response_and_exit(STATUS_FAILED,
                                    "Local commands [%s] execution failed. Error :\n%s" %
                                    (command, stderr))

    except (OSError, Exception) as e:
        logger.error(e)
        print_response_and_exit(STATUS_FAILED,
                                "Error while running local command [%s]. Error :\n%s" %
                                (command, str(e)))


def execute_commands_on_remote_host(ssh_user, host_ip, ssh_key, ssh_commands,
                                    command_log_message_prefix="SSH commands"):

    ssh_user_and_host = '{}@{}'.format(ssh_user, host_ip)
    logger.info("Will try to SSH to %s.", ssh_user_and_host)
    logger.info("%s :\n%s" % (command_log_message_prefix, ssh_commands))

    ssh = Popen(['timeout', COMMAND_TIMEOUT, 'ssh', '-q',
                 '-o', TIMEOUT, '-o', KEYCHECK, '-o', LOGLEVEL,
                 '-i', ssh_key, '-t', ssh_user_and_host, 'bash'],
                stdin=PIPE, stdout=PIPE, stderr=PIPE)

    if not isinstance(ssh_commands, bytes):
        ssh_commands = ssh_commands.encode(BYTE_TO_STRING_DECODE_TYPE_UTF_8)

    stdout, stderr = ssh.communicate(ssh_commands)

    if ssh.returncode == 0:
        #logger.info("%s OK on [Host: '%s']." % (command_log_message_prefix, host_ip))
        stdout = stdout.strip()
        logger.info("%s output :\n%s" % (command_log_message_prefix, stdout))
        return True, stdout

    else:
        logger.error("%s failed on [Host: '%s']. Code: %s. Error:\n%s" %
                     (command_log_message_prefix, host_ip, ssh.returncode, stderr))
        return False, stderr.strip()


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


def log_vm_healthcheck_results():

    global VM_HEALTHCHECK_RESULT

    vm_list = [["VM NAME", "IP ADDRESS", "HEALTHCHECK STATUS", "REASON", "OUTPUT"]]
    for index, vm in VM_HEALTHCHECK_RESULT.items():
        vm_list.append([vm['name'], vm['ip_address'],
                        vm['vm_healthcheck_status'], vm['reason'],
                        vm['output']])

    table_lines = get_table_format(vm_list)
    logger.info("\n" + table_lines)


def get_vm_list():

    vm_list_splitted = VM_LIST_ARG.strip().split(",")

    for vm in vm_list_splitted:
        VM_LIST.append(vm.strip())


def wait_for_vm_healthcheck_status_pass(vm_ip):

    start_time = time.time()
    vm_healthcheck_pass_result = False
    output = None
    while True:

        result, output = execute_commands_on_remote_host(SSH_USER, vm_ip,
                                                         SSH_KEY_FILE,
                                                         "tail -1 /var/log/healthcheck.log",
                                                         "VM healthcheck log check command")

        if result is True:
            if ALL_HEALTHCHECKS_PASSED_MESSAGE in output:
                vm_healthcheck_pass_result = True
                break

        time.sleep(SLEEP_TIME_BETWEEN_VM_HEALTHCHECK_STATUS_CHECK)

        end_time = time.time()

        if (end_time - start_time) >= TIMEOUT_FOR_VM_HEALTHCHECK_STATUS_PASS:
            break

    return vm_healthcheck_pass_result, output


def vm_healthcheck_pass_wait(consul_members_dict):

    global VM_HEALTHCHECK_RESULT
    global VM_COUNT

    for vm_name in VM_LIST:

        vm_found = False
        vm_ip = None

        for index, consul_member in consul_members_dict.items():

            if vm_name == consul_member['name']:
                vm_found = True
                vm_ip = consul_member['ip_address']
                break

        reason = ""
        output = ""
        vm_healthcheck_status = STATUS_NOT_PASSED_YET

        if vm_found:

            result, output = wait_for_vm_healthcheck_status_pass(vm_ip)

            if result is False:
                reason = "Timeout (All healthchecks are not passed yet)"
            else:
                #reason = "All healthchecks passed"
                vm_healthcheck_status = STATUS_PASSED

        else:
            reason = "VM not found in consul members"
            vm_healthcheck_status = None

        vm_result = {'name': vm_name, 'ip_address': vm_ip,
                     'reason': reason, 'output': output,
                     'vm_healthcheck_status': vm_healthcheck_status}
        VM_HEALTHCHECK_RESULT[VM_COUNT] = vm_result
        VM_COUNT += 1

    log_vm_healthcheck_results()


# Get SSH key file
get_ssh_key_file()

# Get Serves list from passed argument
get_vm_list()

# Get consul members details from "consul members" output
consul_members_output = execute_cli_locally(CONSUL_MEMBERS_COMMAND)
consul_members_dict = parse_consul_members(consul_members_output)

# VM healthcheck pass wait
vm_healthcheck_pass_wait(consul_members_dict)

print_response_and_exit(STATUS_OK, "VM healthcheck status check task completed for good VMs.")
