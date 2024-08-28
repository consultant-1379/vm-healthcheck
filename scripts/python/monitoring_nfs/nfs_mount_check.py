import argparse
import datetime
import logging
from logging.handlers import RotatingFileHandler
import os.path
import sys
from subprocess import PIPE, Popen
import json
import re


if __name__ == '__main__':
    global args
    parser = argparse.ArgumentParser()
    parser.add_argument("min_index", nargs="?", help="Provide min index.")
    parser.add_argument("max_index", nargs="?", help="Provide max index.")
    parser.add_argument("log_file", default="nfs_mount_check.py", nargs="?",
                        help="Provide log file name.")
    #parser.add_argument("--usage", help="Display help.", action="store_true")
    args = parser.parse_args()


HOME_DIR = "/home"

SSH_USER = "cloud-user"

SSH_USER_HOME_DIR = os.path.join(HOME_DIR, SSH_USER)

NFS_MONITORING_DIR_NAME = "monitoring_nfs"
NFS_MONITORING_DIR = os.path.join(SSH_USER_HOME_DIR, NFS_MONITORING_DIR_NAME)

SEP1 = "-----------------------------------------------------------------------------------"
SEP2 = "==================================================================================="
LOG = NFS_MONITORING_DIR + "/" + args.log_file + ".log"
DIR = os.path.dirname(LOG)

MIN_INDEX = int(args.min_index)
MAX_INDEX = int(args.max_index)


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


TIMEOUT = "ConnectTimeout=20"
COMMAND_TIMEOUT = "20"
KEYCHECK = "StrictHostKeyChecking=no"
LOGLEVEL = "LogLevel=ERROR"
CLI_EXECUTION_TIMEOUT = "20"
HOST_IDENTIFICATION_CHANGE_MESSAGE = "WARNING: REMOTE HOST IDENTIFICATION HAS CHANGED!"
KEYBOARD_INTERACTIVE_AUTHENTICATIO_DISABLED_MESSAGE = \
    "Keyboard-interactive authentication is disabled to avoid man-in-the-middle attacks."

NFS_CLIENT_SHARES_FILE_NAME = "nfs_client_shares.json"
NFS_CLIENT_SHARES_FILE = os.path.join(NFS_MONITORING_DIR, NFS_CLIENT_SHARES_FILE_NAME)

STALE_MOUNTS_FILE_NAME = "stale_mounts_info.json"
STALE_MOUNTS_FILE = os.path.join(NFS_MONITORING_DIR, STALE_MOUNTS_FILE_NAME)


SSH_KEY_POSTFIX = ".pem"

BYTE_TO_STRING_DECODE_TYPE_UTF_8 = "utf-8"

CONSUL_MEMBERS_COMMAND = "consul members"
NFS_CHECK_TOUCH_FILE = ".nfs_check"

STALE_MOUNTS = {}
STALE_MOUNT_COUNT = 0

STATUS_OK = "OK"
STATUS_FAILED = "FAILED"

DEFINITION_TO_CONSUL_MEMBER_MAPPING = {"haproxyint": "haproxy-int",
                                       "haproxysb": "haproxy-sb",
                                       "lvs": "lvsrouter",
                                       "nfsnorollback": "nfsnrbk",
                                       "nfspmlinks": "nfspmlink",
                                       "presentation": "uiserv",
                                       "scripting": "scp",
                                       "security": "secserv",
                                       "serviceregistry": "servicereg"}

ENM_NODES_IGNORE_NFS_MOUNT_CHECKLIST = ["nfspmlink", "nfsnrbk", "nfscommon",
                                        "nfspm", "nfssmrs", "repo", "lvsrouter", "emp"]

UISERV_IGNORE_MOUNT_SHARES_LIST = ["/ericsson/batch",
                                   "/ericsson/symvol",
                                   "/ericsson/tor/smrs",
                                   "/ericsson/config_mgt"]

MSCMAPG_IGNORE_MOUNT_SHARES_LIST = ["/ericsson/tor/smrs"]


def store_stale_mounts_info_in_file(stale_mounts_file, stale_mounts_info):
    """
    Store NFS shares info in a file

    :param stale_mounts_file: NFS client shares stale mounts file name
    :param stale_mounts_info: NFS client shares stale mounts info
    """
    file = None
    try:
        file = open(stale_mounts_file, "w")
        file.write(stale_mounts_info)

    except (OSError, IOError) as e:
        message = "Couldn't write NFS client shares info to the file : %s" % stale_mounts_file
        logger.error(message)
    finally:
        file.close()


def print_response_and_exit(status, message, exit_code=0):

    response = {"status": status, "message": message, "stale_mounts": STALE_MOUNTS,
                "stale_mounts_count": STALE_MOUNT_COUNT}
    response = json.dumps(response)
    print(response)
    #store_stale_mounts_info_in_file(STALE_MOUNTS_FILE, response)

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


def read_nfs_client_shares_file():

    nfs_client_shares_file = None
    try:
        nfs_client_shares_file = open(NFS_CLIENT_SHARES_FILE, 'r')
        nfs_client_shares_json = nfs_client_shares_file.read()
        return nfs_client_shares_json

    except (IOError, OSError) as e:
        logger.error(e)
        print_response_and_exit(STATUS_FAILED,
                                "Error in reading NFS client shares file {}. "
                                "Error: [{}]".format(NFS_CLIENT_SHARES_FILE, str(e)))
    finally:
        nfs_client_shares_file.close()


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


def list_consul_member_ip_addresses(consul_members_dict, name):

    ip_address_list = []
    name_string = r"-" + name + r"-\d+"
    regex_obj = re.compile(name_string)

    for index, consul_member in consul_members_dict.items():
        regex_match = regex_obj.findall(consul_member['name'])
        if regex_match is not None and len(regex_match) != 0:
            logger.debug("Regex match : %s" % str(regex_match))
            ip_address_list.append(consul_member['ip_address'])

    logger.info(SEP1)
    logger.info("Consul member [%s] IP address list : %s" % (name, str(ip_address_list)))

    return ip_address_list


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
    logger.debug("Will try to SSH to %s.", ssh_user_and_host)
    logger.debug("%s :\n%s" % (command_log_message_prefix, ssh_commands))

    ssh = Popen(['timeout', COMMAND_TIMEOUT, 'ssh',
                 '-o', TIMEOUT, '-o', KEYCHECK, '-o', LOGLEVEL,
                 '-i', ssh_key, '-t', ssh_user_and_host, 'bash'],
                stdin=PIPE, stdout=PIPE, stderr=PIPE)

    if not isinstance(ssh_commands, bytes):
        ssh_commands = ssh_commands.encode(BYTE_TO_STRING_DECODE_TYPE_UTF_8)

    stdout, stderr = ssh.communicate(ssh_commands)

    if ssh.returncode == 0:
        logger.info("%s OK on [Host: '%s']." % (command_log_message_prefix, host_ip))
        return True, stdout.strip()

    else:
        stderr = stderr.strip()
        logger.error("%s failed on [Host: '%s']. Code: %s. Error:\n%s" %
                     (command_log_message_prefix, host_ip, ssh.returncode, stderr))
        result = False
        if "Permission denied" in stderr:
            result = True
        return result, stderr


def verify_df_command(nfs_client, ip_address):

    global STALE_MOUNTS
    global STALE_MOUNT_COUNT

    result, output = execute_commands_on_remote_host(SSH_USER, ip_address, SSH_KEY_FILE,
                                                     "df -k", "NFS status command")
    if result is False:
        stale_mount = {"nfs_client": nfs_client, "ip_address": ip_address,
                       "reason": "'df -k' failed", "output": output}
        STALE_MOUNTS[STALE_MOUNT_COUNT] = stale_mount
        STALE_MOUNT_COUNT += 1


def verify_touch_command(nfs_client, ip_address, mounts):

    global STALE_MOUNTS
    global STALE_MOUNT_COUNT

    for index, mount in mounts.items():

        mount_path = mount['path']

        # Ignore below 4 mount paths for 'uiserv', due to below error :
        # touch: cannot touch `/ericsson/batch/.nfs_check': No such file or directory
        # touch: cannot touch `/ericsson/symvol/.nfs_check': No such file or directory
        # touch: cannot touch `/ericsson/tor/smrs/.nfs_check': No such file or directory
        # touch: cannot touch `/ericsson/config_mgt/.nfs_check': No such file or directory
        if nfs_client == "uiserv":
            if mount_path in UISERV_IGNORE_MOUNT_SHARES_LIST:
                logger.info("Ignoring mount path [%s] for 'uiserv' since the directory does not "
                            "exist" % mount_path)
                continue

        # Ignore below mount paths for 'mscmapg', due to below error :
        # touch: cannot touch `/ericsson/tor/smrs/.nfs_check': No such file or directory
        if nfs_client == "mscmapg":
            if mount_path in MSCMAPG_IGNORE_MOUNT_SHARES_LIST:
                logger.info("Ignoring mount path [%s] for 'mscmapg' since the directory does not "
                            "exist" % mount_path)
                continue

        touch_file = os.path.join(mount_path, NFS_CHECK_TOUCH_FILE)
        logger.info("Touch file : %s" % touch_file)

        result, output = execute_commands_on_remote_host(SSH_USER, ip_address, SSH_KEY_FILE,
                                                         "sudo -i touch " + touch_file,
                                                         "NFS status command")
        if result is False:
            stale_mount = {"nfs_client": nfs_client, "ip_address": ip_address,
                           "reason": "'touch %s' failed" % touch_file, "output": output}
            STALE_MOUNTS[STALE_MOUNT_COUNT] = stale_mount
            STALE_MOUNT_COUNT += 1


def nfs_stale_mount_check(nfs_client_shares_dict, consul_members_dict):

    start_time = datetime.datetime.now()
    log_header("NFS MOUNT CHECK START TIME : %s" % start_time)

    message = ""
    count = 0
    for nfs_client, mounts in nfs_client_shares_dict.items():

        if MIN_INDEX <= count <= MAX_INDEX:

            #if ("lvs" != nfs_client) and ("opendj" != nfs_client):
                #continue

            # For certain *_definition.yaml file, there is a mismatch between that name and ENM node
            # in the output of "consul members"
            # For ex: "presentation_definition.yaml" -> "presentation" -> "uiserv"
            # DEFINITION_TO_CONSUL_MEMBER_MAPPING includes the mapping of all such servers
            if nfs_client in DEFINITION_TO_CONSUL_MEMBER_MAPPING:
                nfs_client = DEFINITION_TO_CONSUL_MEMBER_MAPPING[nfs_client]

            # Ignore NFS mount check 'touch' for nodes defined in ENM_NODES_IGNORE_NFS_MOUNT_CHECKLIST
            # Because it gives error: [sudo: sorry, you must have a tty to run sudo]
            check_touch_for_nfs_client = True
            if nfs_client in ENM_NODES_IGNORE_NFS_MOUNT_CHECKLIST:
                logger.info("ENM node [%s] requires tty to run sudo. Hence, 'touch' check will be "
                            "ignored." % nfs_client)
                check_touch_for_nfs_client = False

            nfs_client_ip_addresses = list_consul_member_ip_addresses(consul_members_dict, nfs_client)

            if len(nfs_client_ip_addresses) == 0:
                logger.info(SEP1)
                logger.info("Consul member [{}] IP addresses not found. Hence, skipping NFS check."
                            .format(nfs_client))
            else:
                for ip_address in nfs_client_ip_addresses:

                    logger.info(SEP1)
                    logger.info("##### EXECUTING COMMANDS ON [%s] #####" % ip_address)
                    logger.info(SEP1)

                    logger.info(">>> EXECUTING 'df' COMMAND <<<")
                    verify_df_command(nfs_client, ip_address)

                    if check_touch_for_nfs_client is True:
                        logger.info(">>> EXECUTING 'touch' COMMANDS <<<")
                        verify_touch_command(nfs_client, ip_address, mounts)

        count += 1

    global STALE_MOUNTS
    if len(STALE_MOUNTS) != 0:
        message += "STALE MOUNTS FOUND."
        log_stale_mounts()

    end_time = datetime.datetime.now()
    logger.info(SEP2)
    logger.info("NFS MOUNT CHECK END TIME : %s" % end_time)
    logger.info("TOTAL EXECUTION TIME : %s" % (end_time - start_time))
    logger.info("STALE MOUNTS COUNT : %s" % STALE_MOUNT_COUNT)
    logger.info(SEP2)

    if message == "":
        print_response_and_exit(STATUS_OK, "All NFS client shares mounts verified successfully.")
    else:
        print_response_and_exit(STATUS_FAILED, message)


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


def log_stale_mounts():

    global STALE_MOUNTS

    stale_mounts_list = [["NFS CLIENT", "IP ADDRESS", "REASON", "COMMAND OUTPUT"]]
    for index, stale_mount in STALE_MOUNTS.items():
        output = stale_mount['output']
        if not output:
            output = "Command output is empty. Probably timed out."
        stale_mounts_list.append([stale_mount['nfs_client'], stale_mount['ip_address'],
                                  stale_mount['reason'], output])

    table_lines = get_table_format(stale_mounts_list)
    logger.info("\n" + table_lines)


# Get SSH key file
get_ssh_key_file()

# Read nfs_client_shares.json file and convert to dict
nfs_client_shares_file_content = read_nfs_client_shares_file()
nfs_client_shares_dict = json.loads(nfs_client_shares_file_content)

# Get consul members details from "consul members" output
consul_members_output = execute_cli_locally(CONSUL_MEMBERS_COMMAND)
consul_members_dict = parse_consul_members(consul_members_output)

# Check stale mount
nfs_stale_mount_check(nfs_client_shares_dict, consul_members_dict)

