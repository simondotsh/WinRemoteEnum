# WinRemoteEnum
WinRemoteEnum is a module-based collection of operations achievable by a low-privileged domain user, sharing the goal of remotely gathering information of Windows hosts, and their hardening status on commonly-leveraged techniques.

Since most is enumerated through exposed built-in MS-RPC methods, it is heavily based off [impacket](https://github.com/SecureAuthCorp/impacket).

Blog post: <https://simondotsh.com/infosec/2022/01/12/winremoteenum-use-cases.html>

## What Purpose Does WinRemoteEnum Serve?
While it is possible to obtain similar results using well-known tools, WinRemoteEnum simplifies the process by offering modules operating with minimal input, and generating easy-to-consume reports (HTML and JSON). Therefore, it is a great starting point to enumerate a given scope during an engagement, or to answer specific questions as described in the [Example of Operations](#examples-of-operations) section.

Furthermore, WinRemoteEnum follows a read-only mindset, meaning that all requests aim to read information and never to write. Though, ensure to take notice of the [Warning: Understanding the Impact](#warning-understanding-the-Impact) section.

Lastly, the development of the tool was foremost a learning experience regarding concretely interacting with various MS-RPC interfaces, and the endless possibilities of domain hardening.

### Auditing
When possible, modules implement an auditing feature allowing to easily report if a target has been hardened against the technique. Visit [Example of Auditing](#examples-of-auditing) for examples, and the [wiki](https://github.com/simondotsh/WinRemoteEnum/wiki#audit) to learn about exactly what is audited.

## Supported Windows Versions
WinRemoteEnum was tested successfully on Windows 7 SP1 and newer, both on workstations and servers.

While unsupported, most modules _should_ work on Windows XP SP3 except [users](https://github.com/simondotsh/WinRemoteEnum/wiki/Module-users), which runs into a disagreement with MS-LSAD's LsarQueryInformationPolicy, and most-likely more methods.

In case of an unexpected behavior, please only open an issue for supported versions.

## Warning: Understanding the Impact
The operator must take into account the following before executing WinRemoteEnum on a scope:

1. Multiprocessing is used to enumerate a large amount of targets simultaneously. To be precise, two extra processes are spawned per module to perform the task; however only one module runs at a time.

2. WinRemoteEnum will authenticate using the provided credentials a considerable amount of times, which depends entirely on the selected modules. In the context of a domain, this implies the usual impact of sending authentication requests to the domain controller, incrementing the `badPwdCount` attribute on failed login attempts, generating Windows Event logs and so on.

3. Under the wiki page of each module is documented the RPC methods that will be called upon execution. Understand that depending on the monitoring strategy of the environment, these may very well trigger monitoring use cases. Therefore, ensure to inform the surveillance team of your operations.

## Installation
```
git clone https://github.com/simondotsh/WinRemoteEnum
cd WinRemoteEnum/
python3 -m venv venv
source venv/bin/activate
pip3 install -r requirements.txt
```

## Usage
```
usage: winremoteenum.py [-h] [-v] -u USERNAME -d DOMAIN [-p PASSWORD | -nt NT_HASH] [-m MODULES] [-a] [-nv] [-t TIMEOUT] targets

positional arguments:
  targets               Targets to enumerate. Must be a single IP (e.g. 10.0.0.1), a range (e.g. 10.0.0.0/24), or a file containing the
                        aforementioned formats separated by a new line.

optional arguments:
  -h, --help            show this help message and exit

  -v, --version         show program's version number and exit

  -u USERNAME, --username USERNAME
                        Username used to authenticate on targets.

  -d DOMAIN, --domain DOMAIN
                        Domain to authenticate to.

  -p PASSWORD, --password PASSWORD
                        Username's password. If a password or a hash is not provided, a prompt will request the password on execution.

  -nt NT_HASH, --nt-hash NT_HASH
                        Username's NT hash.

  -m MODULES, --modules MODULES
                        Modules to execute on targets, separated by a comma (,). List of modules: sessions,users,host_info,shares,logged_on
                        (default: runs all).

  -a, --audit           Audit mode. This will validate a subset of operations against targets for the selected modules, without reporting the
                        entire results. See the audit section in the wiki for each operation performed.

  -nv, --no-validation  Credentials and connectivity to targets will not be validated.

  -t TIMEOUT, --timeout TIMEOUT
                        Drops connection after x seconds when waiting to receive packets from the target (default: 2).
```

## Modules
The [wiki](https://github.com/simondotsh/WinRemoteEnum/wiki#modules) documents modules with their goals, MS-RPC methods used and design decisions.

| Name | Enumerates |
| ----------- | ----------- |
| [users](https://github.com/simondotsh/WinRemoteEnum/wiki/Module-users) | Local users, groups and their members. |
| [sessions](https://github.com/simondotsh/WinRemoteEnum/wiki/Module-sessions) | Net sessions established. |
| [logged_on](https://github.com/simondotsh/WinRemoteEnum/wiki/Module-logged_on) | Users logged on. |
| [shares](https://github.com/simondotsh/WinRemoteEnum/wiki/Module-shares) | Shares and their first-level content. |
| [host_info](https://github.com/simondotsh/WinRemoteEnum/wiki/Module-host_info) | Various OS info and whether the executing user has administrative privileges. |

## Results
Results are located in the `results/` directory. Visit the [Reporting wiki](https://github.com/simondotsh/WinRemoteEnum/wiki/Reporting) for more information.

## Examples of Operations
### Run all modules on a target
`python3 winremoteenum.py -u $USER -p $PASSWORD -d $DOMAIN $TARGET`

### Who are the members of BUILTIN\Administrators and BUILTIN\Remote Desktop Users on this target?
`python3 winremoteenum.py -u $USER -p $PASSWORD -d $DOMAIN -m users $TARGET`

### Is my user a Local Administrator on this target?
`python3 winremoteenum.py -u $USER -p $PASSWORD -d $DOMAIN -m host_info $TARGET`

### I'm hunting for a specific user's NT hash in LSASS' memory. Where is this user authenticated?
`python3 winremoteenum.py -u $USER -p $PASSWORD -d $DOMAIN -m sessions,logged_on $RANGE`

### Which network shares can I read on this range?
`python3 winremoteenum.py -u $USER -p $PASSWORD -d $DOMAIN -m shares $RANGE`

## Examples of Auditing
### Has access to the SAM Remote Protocol been hardened on this range?
`python3 winremoteenum.py -u $USER -p $PASSWORD -d $DOMAIN -m users -a $RANGE`

### Have session collection vectors been hardened on this range?
`python3 winremoteenum.py -u $USER -p $PASSWORD -d $DOMAIN -m sessions,logged_on -a $RANGE`

## Acknowledgements
Thank you to the following for their direct or indirect involvement with the project:

- [@marcan2020](https://twitter.com/marcan2020) for code review sessions, along with answering the unfortunate interrogations of "Design-wise, what would be the best way to ...".
- The [impacket](https://github.com/SecureAuthCorp/impacket) project for providing easy-to-use interactions with MS-RPC interfaces.

## License
See the `LICENSE` file for legal wording. Essentially it is MIT, meaning that I cannot be held responsible for whatever results from using this code, and do not offer any warranty. By agreeing to this, you are free to use and do anything you like with the code.
