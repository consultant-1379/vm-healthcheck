# Live-migrate Instances

Live-migrating an instance means moving its virtual machine to a different OpenStack Compute server while the instance continues running.
This script will perform live migrations based on a host map configuration that describes the desired distribution of virtual machines on compute nodes.
The script runs in sequence migrating one instance at a time.

### How it works

The script utilises the OpenStack Compute API (python novaclient module) to gather the current distribution of virtual machines on compute nodes.
The provided host map configuration is then compared to the current distribution to determine which if any virtual machines are to be migrated.
The user is then prompted before each migration if they would like to proceed.

## Options

* --help [arg]
    + Show help.

* --host_map [arg]
    + Host map configuration file (JSON).

* --timeout [arg]
    + Timeout in seconds for a single instance status check after launching migration. (default timout of 600 seconds).

* --y, --yes [arg]
    + Do not prompt before server migration.

## Host map configuration example (JSON file)

This is an example host map configuration:

``` json
{
    "compute001": ["kswenm01-vnflaf-services-0"],
    "compute002": ["BMASenm01-haproxy-0"],
    "compute003": ["kswenm01-haproxy-0", "CbrsENM01-vnflaf-services-0"]
}
```

## Script location

The script is located on the Genie Utility Server. The console snippit below will show the exact location:

``` sh
[root@genie-utility server_live_migration]$ pwd
/home/server_live_migration
[root@genie-utility server_live_migration]$
[root@genie-utility server_live_migration]$ ll
-rw-r--r-- 1 root root  264 Sep  5 15:04 host_map.json
-rwxr-xr-x 1 root root 7003 Sep  5 14:58 openstack_live_migration.py
[root@genie-utility server_live_migration]$
```

## Notes

You’ll need to provide nova with your OpenStack Keystone user information by setting the required environment variables.
The script will initialize the nova client with this information at run time.

If after running the migration script the instance is still running on the source host, the migration failed.
The nova-scheduler and nova-conductor log files on the controller and the nova-compute log file on the source compute host can help pin-point the problem.

A single instance migration will have a default timeout of 600 seconds, a custom timeout can be provided to the script as a configuration parameter.

### How to know that the migration timed out

To determine that the migration timed out, inspect the nova-compute log file on the source host. The following log entry shows that the migration timed out:

``` sh
### grep WARNING.*d1df1b5a-70c4-4fed-98b7-423362f2c47c /var/log/nova/nova-compute.log

...
WARNING nova.virt.libvirt.migration [req-...] [instance: ...]
live migration not completed after 1800 sec
```

Visit [Openstack live migration usage](https://docs.openstack.org/nova/pike/admin/live-migration-usage.html) for more details.

## Script execution

- Command line

``` sh
source $HOME/rc/keystone.sh
./openstack_live_migration.py --host_map host_map.json --timeout 500
```
