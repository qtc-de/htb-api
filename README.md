### HTB API

----

This repository contains just a simple python script that can be used to access *HackTheBox's* API. It
is not really a dedicated project and just contains three different API actions. After launching the script
a command prompt opens supporting the following commands:

* ``flag <flag> <difficulty> [<machine-name>]`` - Submit a flag for the specified machine name or IP address.
* ``reset [<machine-name>]`` - Issue a reset on the specified machine name or IP address.
* ``cancel [<machine-name>]`` - Cancel a reset on the specified machine name or IP address.

In all the above mentioned commands, if the ``<machine-name>`` is left out, the script uses the IP address
specified inside of the environment variable ``$IP``. If this is also not set, you will receive an error message ;)


### Installation

----

The script itself does not require installation, but you may need to install the dependencies. First, make sure that
the python dependencies are satisfied by running:

```
$ pip3 install -r requirements.txt --user
```

This will install the *requests* and *prompt_toolkit* packages if not already present. Furthermore, the script requires
*python3-gi* to access the **gnome-keyring**. *python3-gi* cannot be installed via *pip*, but is available in most package managers.
On Kali, just run the following command to install it:

```
$ sudo apt install python3-gi
```

In order to work, the script needs access to *HTB's* API and requires setup of your personal *HTB API key*. Your key is stored
inside the **gnome-keyring** and retrieved during startup of the script. **gnome-keyring** is installed and started per default
on **Kali Linux** and the script should work out of the box. If your keyring does not unlock during startup, make sure that 
the **login-keyring** is set as your default keyring. To store your API key inside the keyring, use the following command:

```
$ ./htb-api.py --store
[+] Enter HTB API key: **************************************************************                                                                                                                               
[+] Enter HTB VPN lab: eu-free-2                                                                                                                                                                                    
[+] Credentials stored.
```

### Usage

----

After storing your API key, you should be able to run the script without any arguments to obtain the interactive prompt:

```
$ ./htb-api.py
[+] 158 Machines loaded.
[+] Starting interactive shell.
> help                                                                                                                                                                                                              
[-] Usage:
[-]       	flag <flag> <difficulty> [<machine-name>]
[-]       	reset [<machine-name>]
[-]       	cancel [<machine-name>]
[-]       	help
[-]       	exit
```

Each command is self explanatory. It is recommended to place the IP address of the machine you are currently doing in an environment
variable with name ``$IP``. If this is set up correctly, you can omit the machine name in all of the above commands.


### Credits

----

Currently, HTB does not expose any API documentation. The API endpoint descriptions were taken from [this repository](https://github.com/sp1ral-vx/hackthebox-api).

Copyright 2020, Tobias Neitzel and the *htb-api* contributors.
