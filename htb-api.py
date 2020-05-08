#!/usr/bin/python3

import re
import shlex
import base64
import os, sys
import requests
import argparse

import gi
gi.require_version('Secret', '1')
from gi.repository import Secret

from prompt_toolkit import prompt
from prompt_toolkit.history import InMemoryHistory


def keyring_store(api_key, lab_id):
    '''
    Stores your HTB API key and your HTB VPN lab identifier inside the gnomekeyring.

    Parameters:
        api_key             (string)            HTB API key.
        lab_id              (string)            HTB VPN lab identifier.

    Returns:
        boolean             (boolean)           True or False.
    '''
    HTB = Secret.Schema.new("htb.api.Store", Secret.SchemaFlags.NONE, {"name": Secret.SchemaAttributeType.STRING})
    result = Secret.password_store_sync(HTB, {"name":"htb_api_key"}, Secret.COLLECTION_DEFAULT, "HTB API Key", api_key, None)
    result2 = Secret.password_store_sync(HTB, {"name":"htb_vpn_lab"}, Secret.COLLECTION_DEFAULT, "HTB VPN LAB", lab_id, None)
    return result and result2


def keyring_retrieve():
    '''
    Retrieve your HTB API key and your HTB VPN lab identifier from the gnomekeyring.

    Parameters:
        None

    Returns:
        key,vpn             (tuple)             HTB API key and HTB VPN lab identifier.
    '''
    HTB = Secret.Schema.new("htb.api.Store", Secret.SchemaFlags.NONE, {"name": Secret.SchemaAttributeType.STRING})
    key = Secret.password_lookup_sync(HTB, {"name": "htb_api_key"}, None)
    vpn = Secret.password_lookup_sync(HTB, {"name": "htb_vpn_lab"}, None)
    return (key,vpn)


class HtbException(Exception):
    '''
    Custom exception type. Not really used for now. Maybe we decide later to
    catch these exceptions differently. For now, they are handeled in the same
    way as other exceptions.
    '''


class HtbApi():
    '''
    This class stores the basic information that is required to access the HTB API.
    It contains the API key as well as the API endpoint and defines methods to send
    requests to the API.
    '''


    def __init__(self, key, vpn_lab_id):
        '''
        Initializes the HtbApi object with the API key of the user.

        Parameters:
            key             (string)            HTB API key.
            vpn_lab_id      (string)            Name of the VPN lab.

        Returns:
            self            (HtbApi)            HtbApi object.
        '''
        self.api = requests.Session()
        self.api.headers = {
            'User-Agent'     : 'htb-api-client/1.0',
            'Authorization'  : f'Bearer {key}',
            'Accept-Encoding': 'gzip, deflate',
            'Accept'         : 'application/json',
            'Connection'     : 'Close',
        }
        self.url = 'https://www.hackthebox.eu'
        self.vpn_lab_id = vpn_lab_id
        self.machines = self._get_machines()
        self.machine = os.getenv('IP', None)
        if self.machine:
            self.machine = self._get_machine(self.machine)


    def _request(self, method, endpoint, params):
        '''
        Send a request to the HTB API.

        Parameters:
            self            (HtbApi)            HtbApi object.
            method          (string)            HTTP method to use (GET|POST).
            endpoint        (string)            Exact API endpoint to query.
            params          (dict)              Parameter array to use.

        Returns:
            response        (response)          Requests response object.
        '''
        if method == 'GET':
            return self.api.get(f'{self.url}{endpoint}', params=params)
        elif method == 'POST':
            return self.api.post(f'{self.url}{endpoint}', data=params)
        else:
            raise HtbException(f'_request(..: Unsupported method: {method}')


    def _get_machines(self):
        '''
        Retrieves a list of available HTB machines.

        Parameters:
            self            (HtbApi)            HtbApi object.

        Returns:
            machines        (list)              List of machine dictionaries
        '''
        response = self._request('GET', '/api/machines/get/all', None).json()

        if 'error' in response:
            error = response['error']
            raise HtbException(f'_get_machines(..: Unable to obtain available machines: {error}')

        return response


    def _get_machine(self, ip_or_name):
        '''
        Returns the machine object with the requested IP address or machine name.

        Parameters:
            self            (HtbApi)            HtbApi object.
            ip_or_name      (string)            IP address or machine name.

        Returns:
            machine         (dict)              Corresponding machine object.
        '''
        if ip_or_name == None:
            if self.machine:
                return self.machine
            raise HtbException(f'_get_machine(..: No default machine set and no machine name was specified')

        for machine in self.machines:
            if (machine["ip"] == ip_or_name) or (machine["name"].lower() == ip_or_name.lower()):
                return machine
        raise HtbException(f'_get_machine(..: Machine with identifier {ip_or_name} not found')
            

    def reset_machine(self, ip_or_name=None):
        '''
        Resets the machine with the specified IP address / machine name or the default machine.

        Parameters:
            self            (HtbApi)            HtbApi object.
            ip_or_name      (string)            IP address or machine name.

        Returns:
            output          (string)            Output received from the API.
        '''
        machine = self._get_machine(ip_or_name)
        machine_id = machine['id']
        response = self._request('POST', f'/api/vm/reset/{machine_id}', None).json()

        if not int(response['success']):
            raise HtbException('reset_machine(..: Reset failed. Server response: {}'.format(response['text']))
        else:
            return response['output']


    def cancel_reset(self, ip_or_name=None):
        '''
        Cancel reset on machine with the specified IP address or name.

        Parameters:
            self            (HtbApi)            HtbApi object.
            ip_or_name      (string)            IP address or machine name.

        Returns:
            output          (string)            Output received from the API.
        '''
        machine = self._get_machine(ip_or_name)
        machine_name = machine['name']
        response = self._request('POST', '/api/shouts/get/initial/info/html/30', None).json()

        if not int(response['success']):
            raise HtbException("cancel_reset(..: Unable to get shoutbox content.")

        find_pattern = f'requested a <span class="text-danger">reset</span> on <span class="c-white">{machine_name}</span> <span class="text-success">[{self.vpn_lab_id}]</span>'
        reset_pattern = re.escape('Type <span class="c-white">/cancel</span> <span class="text-success"><INT></span> within two minutes to cancel the reset]</p>').replace('<INT>', '(\\d+)')
        reset_pattern = re.compile(reset_pattern)
        
        response['html'].reverse()
        for shout in response['html']:
            if find_pattern not in shout:
                continue

            match = reset_pattern.search(shout)
            token = match.group(1)
            response = self._request('POST', '/api/shouts/new/', params={"text": f'/cancel {token}'}).json()

            if not int(response['success']):
                raise HtbException('cancel_reset(..: Reset cancel failed. Server response: {}'.format(response['text']))

            return response['output']

        raise HtbException(f'cancel_reset(..: Reset of {machine_name} failed. No active reset found.')


    def own_machine(self, flag, difficulty=5, ip_or_name=None):
        '''
        Submit a flag for the specified machine.

        Parmaeters:
            self            (HtbApi)            HtbApi object.
            flag            (string)            md5sum representing a HTB flag.
            difficulty      (int)               difficulty rating for the machine.
            ip_or_name      (string)            IP address or machine name.
        
        Returns:
            status          (string)            Flag submission status from the API.
        '''
        machine = self._get_machine(ip_or_name)

        flag = flag.strip()
        if len(flag) != 32:
            raise HtbException(f"own_machine(..: Invalid flag format: {flag}")

        difficulty = int(difficulty)
        if (difficulty < 0) or (difficulty > 10):
            raise HtbException(f"own_machine(..: Specified difficulty '{difficulty}' is not in expected range [0,10].")

        data = {
            'flag': flag,
            'difficulty': difficulty * 10,
            'id': machine['id']
        }
        response = self._request('POST', '/api/machines/own', data).json()

        if not int(response['success']):
            raise HtbException('own_machine(..: Flag submission for {} failed: {}'.format(machine['name'], response['status']))

        return response['status']


def cmd_loop(api_key, vpn_lab):
    '''
    Starts an infinite loop that constantly asks the user for new commands.

    Parameters:
        api_key             (string)            HTB API key.
        vpn_lab             (string)            HTB VPN lab identifier.

    Returns:
        None
    '''
    history = InMemoryHistory()

    try:
        api = HtbApi(api_key, vpn_lab)
    except Exception as e:
        print("[-] Unable to connect to HTB's API: " + str(e))
        sys.exit(1)

    machines = len(api.machines)
    print(f'[+] {machines} Machines loaded.')
    print(f'[+] Starting interactive shell.')

    while True:
        try:

            cmd = prompt("> ", history=history)
            split = shlex.split(cmd)
            if len(split) == 0:
                continue

            try:

                if split[0] == 'flag':

                    if len(split) < 2:
                        print("[-] Usage: flag <flag> <difficulty> [<machine-name>] ")
                        continue

                    elif len(split) == 2:
                        result = api.own_machine(split[1])
                    elif len(split) == 3:
                        result = api.own_machine(split[1], split[2])
                    else:
                        result = api.own_machine(split[1], split[2], split[3])

                elif split[0] == 'reset':

                    if len(split) == 1:
                        result = api.reset_machine()
                    else:
                        result = api.reset_machine(split[1])

                elif split[0] == 'cancel':

                    if len(split) == 1:
                        result = api.cancel_reset()
                    else:
                        result = api.cancel_reset(split[1])

                elif split[0] == 'exit':
                    sys.exit(0)

                else:
                    print("[-] Usage:")
                    print("[-]       \tflag <flag> <difficulty> [<machine-name>]")
                    print("[-]       \treset [<machine-name>]")
                    print("[-]       \tcancel [<machine-name>]")
                    print("[-]       \thelp")
                    print("[-]       \texit")
                    continue

                print("[+] Result: " + result)

            except Exception as e:
                print("[-] Exception was thrown: " + str(e))

        except (KeyboardInterrupt, EOFError) as e:
            print('[-] Aborted.')
            sys.exit(1)


parser = argparse.ArgumentParser(description='''Simple python script to query HTB's public API.''')
parser.add_argument('--store', action='store_true', dest='store', help='store API key inside gnome keyring')
parser.add_argument('--retrieve', action='store_true', dest='retrieve', help='display API key stored inside gnome keyring')
args = parser.parse_args()

if args.store:

    try:
        api_key = prompt("[+] Enter HTB API key: ", is_password=True)
        vpn_lab = prompt("[+] Enter HTB VPN lab: ")
    except (KeyboardInterrupt, EOFError) as e:
        print('[-] Aborted.')
        sys.exit(1)

    if keyring_store(api_key, vpn_lab):
        print("[+] Credentials stored.")
        sys.exit(0)

    print("[-] Failed.")
    sys.exit(1)

api_key,vpn_lab = keyring_retrieve()

if (not api_key) or (not vpn_lab):
    print("[-] Cannot find credentials in gnomekeyring.")
    sys.exit(1)

if args.retrieve:
    print(f"[+] API key: {api_key}")
    print(f"[+] VPN lab: {vpn_lab}")
    sys.exit(0)

cmd_loop(api_key, vpn_lab)
