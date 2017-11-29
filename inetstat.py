#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import os
import sys
import pwd
import glob
import re
import socket
import time
import struct
from collections import OrderedDict
from multiprocessing import Process, Manager, cpu_count
try:
    import _pickle as pickle  # Python 3.5 import of cPickle
except ImportError:
    import pickle

python_exec = sys.executable
python_version = sys.version

current_path = os.getcwd()
script_path = os.path.dirname(os.path.realpath(__file__))
python_path = os.path.dirname(python_exec)

running_arch = "{0} bits".format(8 * struct.calcsize("P"))
threads_available = int(cpu_count() / 2) + 1

system_pid_pattern = '/proc/[0-9]*/fd/[0-9]*'
process_state_pattern = re.compile(r"\(([A-Za-z0-9_]+)\)")
sc_clk_tck = os.sysconf_names['SC_CLK_TCK']
clock_tick = os.sysconf(sc_clk_tck)

kernel_tcp4_info = '/proc/net/tcp'
tcp_timers = {'00': 'z_no_timer', '01': 'retransmit', '02': 'keep_alive', '03': 'time_wait', '04': 'window_probe'}

tcp_states = {'01': 'ESTABLISHED', '02': 'SYN_SENT', '03': 'SYN_RECV', '04': 'FIN_WAIT1', '05': 'FIN_WAIT2',
              '06': 'TIME_WAIT', '07': 'CLOSE', '08': 'CLOSE_WAIT', '09': 'LAST_ACK', '0A': 'LISTEN', '0B': 'CLOSING'}

umask_octal_codes = {'0': 'rwx', '1': 'rw-', '2': 'r-x', '3': 'r--', '4': '-wx', '5': '-w-', '6': '--x', '7': '---'}

umask_special_bits = {'0': '', '1': 'Sticky', '2': 'SGID', '4': 'SUID'}


def split_lists(original_list, max_slices):
    """ Split a list into a list of small lists given the desired number of sub lists """
    slices = max_slices - 1
    original_list_size = len(original_list)
    split_index = int(original_list_size / slices)
    return [original_list[x:x + split_index] for x in range(0, len(original_list), split_index)]


def hex2dec(hex_value):
    """ Returns a decimal representation of a given hex value"""
    return str(int(hex_value, 16))


def reversed_endian2octets(hex_ip):
    """ IPs on /proc/net/tcp are stored as big-endian value interpreted as per the machine "endianness", which means it
    ends up reversed on little-endian machines """
    reversed_bytes = [hex_ip[6:8], hex_ip[4:6], hex_ip[2:4], hex_ip[0:2]]
    octets = [hex2dec(_oct) for _oct in reversed_bytes]
    return '.'.join(octets)


def get_pid_of_inode(inode):
    """ Check which running PID is using the given inode """
    for inode_pid in glob.glob(system_pid_pattern):
        try:
            if re.search(inode, os.readlink(inode_pid)):
                return inode_pid.split('/')[2]
        except FileNotFoundError:
            return '-NA-'


def umask_human_representation(umask):
    """ Returns a string with a human readable representation of a given umask """
    _machine_reading_umask = str(umask)[::-1]
    _other = umask_octal_codes[_machine_reading_umask[0]]
    _group = umask_octal_codes[_machine_reading_umask[1]]
    _user = umask_octal_codes[_machine_reading_umask[2]]
    try:
        _special = umask_special_bits[_machine_reading_umask[3]]
    except IndexError:
        _special = ''
    human_readable_umask = "{0}{1}{2}{3}".format(_special, _user, _group, _other)
    return human_readable_umask


def get_process_info(pid_number):
    """ Check relevant data about a given process using it's Kernel representation on /proc filesystem. It returns the
     process Name, State, Threads owned by it, VmRSS memory taken by it and it's permissions """
    process_status_file = "/proc/{0}/status".format(str(pid_number))
    process_status_dict = dict()
    try:
        with open(process_status_file, 'r') as proc_status:
            _status = proc_status.readlines()
            for _item in _status:
                _item, _value = [i.lstrip().rstrip() for i in _item.split(":")]
                process_status_dict.update({_item: _value})
    except IOError:
        return {'pname': '---', 'pumask': '---', 'pstate': '---', 'th': '---', 'pmem': '---'}

    _name = process_status_dict['Name']
    _umask = umask_human_representation(process_status_dict['Umask'])
    if "(" and ")" in process_status_dict['State']:
        _state = re.findall(process_state_pattern, process_status_dict['State'])[0]
    else:
        _state = process_status_dict['State']
    _threads = process_status_dict['Threads']
    _mem = process_status_dict['VmRSS']
    return {'pname': _name, 'pumask': _umask, 'pstate': _state, 'th': _threads, 'pmem': _mem}


def timers_and_jiffies(tcp_timer, jiffy):
    """ Use Kernel constant values for clock in Hz and the jiffy values given by /proc/net/tcp to describe the type of
    timer (tcp_timer_type) associated with a connection and it's current time countdown in seconds (tcp_timer) """
    tcp_timer_type = tcp_timers[tcp_timer]
    _time = int(int(hex2dec(jiffy)) / clock_tick)  # int int to round secs (human-readable value)
    tcp_timer = _time if _time > 0 else 0
    return tcp_timer_type, tcp_timer


class MinimalWhois(object):

    def __init__(self):
        """ This is my minimalistic whois implementation using sockets. It's inherited by INetStat class, and it's
        purpose is to return ASN related information against a given IP address """

        self.whois_host = "whois.cymru.com"
        self.whois_port, self.ipcheck_port = 43, 80
        self.ipcheck_address = "8.8.8.8"

        self.timeout = 2
        self.object_flags = " -v {0}\r\n"

        self.socket = None
        self.sock_family, self.sock_type = socket.AF_INET, socket.SOCK_STREAM
        self.sock_type_2 = socket.SOCK_DGRAM

        self.local_ip = self.check_local_ip()

    def check_local_ip(self):
        """ As long as I'm already using sockets, let's use a socket connection to 8.8.8.8 to get our local IP address
        as any other method will return 127.0.0.1 as per all other Linux methods characteristics """
        self.socket = socket.socket(self.sock_family, self.sock_type_2)
        try:
            self.socket.connect((self.ipcheck_address, self.ipcheck_port))
            return self.socket.getsockname()[0]
        except socket.error as socket_error:
            print('Socket Error:', socket_error)
            sys.exit(1)

    def lookup(self, ip_address):
        """ Performs socket connection with "whois.cymru.com" passing the given IP as flag and returns response """
        self.socket = socket.socket(self.sock_family, self.sock_type)
        _response = b''
        try:
            self.socket.settimeout(self.timeout)
            self.socket.connect((self.whois_host, self.whois_port))
            self.socket.send(bytes(self.object_flags.format(ip_address).encode()))

            while True:
                _data = self.socket.recv(4096)
                _response += _data
                if not _data:
                    break
            self.socket.close()
        except socket.error:
            return None

        _response = _response.decode('utf-8', 'replace')
        return _response

    def parse_data(self, dictionary, ip_address):
        """ Receives a multiprocessing managed dictionary and an IP address to perform a lookup method and parse
         all the returned information concerning the IP's ASN information. Retries 3 times in case of a timeout """
        _retries = 3
        _whois_data = self.lookup(ip_address)
        while _whois_data is None and _retries > 0:
            _retries -= 1
            _whois_data = self.lookup(ip_address)

        if len(_whois_data) and isinstance(_whois_data, str):
            _lines = [_line for _line in _whois_data.splitlines()[:2]]
            _keys, _values = [[_item.lstrip().rstrip() for _item in _line.split('|')] for _line in _lines]
            _keys = [_key.lower().replace(' ', '_') for _key in _keys]
            _values = [_value.split(',')[0] for _value in _values]
            dictionary.update({ip_address: dict(zip(_keys, _values))})


class MinimalNetstat(MinimalWhois):

    def __init__(self):
        """ This is my Python 3 netstat implementation. My intention here is not reinvent the wheel. Instead of the
        default Linux netstat's behaviour, my implementation will describe and monitor states and timers. We're
         inheriting my whois implementation to have proper access to my local ip """

        super(MinimalNetstat, self).__init__()

        self.tcp4 = kernel_tcp4_info
        self.states = tcp_states
        self.tcp4_data = self.parse_tcp4_data()
        if self.tcp4_data is not None:
            self.netstat = self.tcp4_data
        else:
            print("Could not retrieve TCP data.")
            sys.exit(1)

    def read_proc_tcp4(self):
        """ Reads the data on /proc/net/tcp to get all currently available IPv4 TCP connections """
        try:
            with open(self.tcp4, 'r') as _proc:
                return [_line.replace('\n', '') for _line in _proc.readlines()[1:] if len(_line)]
        except IOError:
            return None

    def parse_tcp4_data(self):
        """ Get information about all currently available IPv4 TCP connections using the read_proc_tcp4 method and
        parse the information through some conversion methods as per Linux Kernel conventions """
        _status_keys = ['pname', 'pumask', 'pstate', 'th', 'pmem']
        _tcp4_data = dict()
        _data = self.read_proc_tcp4()
        if _data is None:
            return _data

        for _entry in _data:
            _cells = _entry.split()

            _id = _cells[0].replace(':', '')

            _hex_local_host, _hex_local_port = _cells[1].split(':')
            _local_host, _local_port = reversed_endian2octets(_hex_local_host), hex2dec(_hex_local_port)

            _hex_remote_host, _hex_remote_port = _cells[2].split(':')
            _remote_host, _remote_port = reversed_endian2octets(_hex_remote_host), hex2dec(_hex_remote_port)

            if _remote_host != '0.0.0.0':

                _layer = 'secure' if _remote_port == '443' else 'insecure'
                _cstate = self.states[_cells[3]]

                _timer, _jiffy = _cells[5].split(':')
                _timer_type, _timer = timers_and_jiffies(_timer, _jiffy)

                _uid = pwd.getpwuid(int(_cells[7]))[0]

                _inode = _cells[9]
                _inode_pid = get_pid_of_inode(_inode)

                _pid_status = get_process_info(_inode_pid)
                _pname, _pumask, _pstate, _th, _pmem = [_pid_status[_ps_key] for _ps_key in _status_keys]

                _pname = _pname[:11] if len(_pname) > 11 else _pname

                try:
                    _app_path = os.readlink("/proc/{0}/exe".format(_inode_pid))  # .split(os.path.sep)[-1]
                except FileNotFoundError:
                    _app_path = '--NA--'

                _tcp4_entry = {'id': _id, 'cstate': _cstate, 'localhost': _local_host, 'lport': _local_port,
                               'remotehost': _remote_host, 'rport': _remote_port, 'time': _timer, 'timer': _timer_type,
                               'user': _uid, 'inode': _inode, 'pid': _inode_pid, 'name': _pname, 'app_path': _app_path,
                               'umask': _pumask, 'pstate': _pstate, 'th': _th, 'mem': _pmem, 'layer': _layer,
                               'ipv': 'IPv4'}

                _tcp4_data.update({_remote_host: _tcp4_entry})

        return _tcp4_data


class PickleDict:

    def __init__(self):
        """ Handles storage dictionaries to dist through cpickle and reading them to act as a cache on disk for ASN
         information concerning IP addresses already queried. TODO: store timestamp to query again if the stored record
         is older than X days (to check if a block of IPs now belongs to a different company """
        self.pickle_file = "asn_info.pickle"
        self.pickle_path = script_path
        self.my_pickle = os.path.join(self.pickle_path, self.pickle_file)

    def touch(self):
        """ This method is only being used while I write this code, to "reset" our cache for testing purposes """
        try:
            open(self.my_pickle, 'w').close()
        except IOError:
            print("Can't touch {0} file!".format(self.my_pickle))
            sys.exit(1)

    def read(self):
        """ Read the cache file from disk """
        if os.path.isfile(self.my_pickle):
            try:
                with open(self.my_pickle, 'rb') as _pickle:
                    return pickle.load(_pickle)
            except IOError:
                return False
        else:
            return False

    def write(self, pickle_data):
        """ Writes the given dictionary (pickle_data) to disk """
        try:
            with open(self.my_pickle, 'wb') as _pickle:
                pickle.dump(pickle_data, _pickle)
        except IOError:
            print("Can't write {0} file!".format(self.my_pickle))
            sys.exit(1)


class INetstat(MinimalNetstat):

    def __init__(self):
        """ We're inheriting MinimalNetstat Class (which inherits MinimalWhois) and we'll also store a timestamp right
         at the initialization so we can further check the execution time (for testing purposes) """
        self.start = time.time()
        super(INetstat, self).__init__()

        self.pickle_dict = PickleDict()
        self.open_connections = len(self.netstat)

        self.asn_data = self.get_asn_data()

        for mutual_key, values in self.netstat.items():
            self.netstat[mutual_key] = {**self.netstat[mutual_key], **self.asn_data[mutual_key]}

        def sort_items(dictionary):
            return dictionary[1]['ipv'], dictionary[1]['rport'], dictionary[1]['cstate'], dictionary[1]['timer'],\
                   dictionary[1]['time'], dictionary[1]['as_name'], dictionary[1]['cc'], dictionary[1]['allocated'],\
                   dictionary[1]['remotehost']

        _netstat_sorted_items = sorted(self.netstat.items(), key=sort_items)
        self.ordered_netstat = OrderedDict(_netstat_sorted_items)

    def read_asn_data_from_disk(self):
        """ Return our ASN cache from disk (cpickle stored file) or None if we could not find a cache file """
        _asn_data = self.pickle_dict.read()
        return _asn_data if _asn_data else None

    def get_asn_data(self):
        """ This method identifies which IP addresses are unknown to our cache file and prepare them to be queried.
         The list of IPs to query are divided into smaller lists concerning the number of available threads on the
         system, as we're multiprocessing the method that perform que queries to optimize execution time"""
        _ips_list = [_ip_address for _ip_address in self.netstat.keys()]

        _unknown_asn_data = list()
        _known_asn_data = self.read_asn_data_from_disk()

        if _known_asn_data and isinstance(_known_asn_data, dict):
            _unknown_asn_data = [_ip_address for _ip_address in _ips_list if _ip_address not in _known_asn_data]
        else:
            _known_asn_data = dict()
            _unknown_asn_data = [_ip_address for _ip_address in _ips_list if _ip_address not in _unknown_asn_data]

        manager = Manager()
        asn_dictionary = manager.dict()

        if len(_unknown_asn_data) > threads_available:
            _chunks_to_process = split_lists(_unknown_asn_data, threads_available)  # divides the list into smaller ones

            for _chunk in _chunks_to_process:  # start the query processes in chunks (concerning lists to be queried)
                job = [Process(target=self.parse_data, args=(asn_dictionary, _ip)) for _ip in _chunk]
                _ = [p.start() for p in job]
                _ = [p.join() for p in job]
        else:
            job = [Process(target=self.parse_data, args=(asn_dictionary, _ip)) for _ip in _unknown_asn_data]
            _ = [p.start() for p in job]
            _ = [p.join() for p in job]

        _complete_asn_data = {**asn_dictionary, **_known_asn_data}  # merge the previous known data (cache) with new one
        self.pickle_dict.write(_complete_asn_data)
        return _complete_asn_data


def dict_values_len(dictionary, minimum_column_size=5):
    """ Reads the given dictionary and return a new one containing each one of it's keys with it's correspondent length,
    which represents whe length of the largest value attributed to that same key"""
    _values_len_dict = dict()
    for k, v in dictionary.items():
        for _k, _v in v.items():
            _v = str(_v)
            if _k not in _values_len_dict or _values_len_dict[_k] < len(_v):
                _length = len(_v) if len(_v) >= minimum_column_size else minimum_column_size
                _values_len_dict.update({_k: _length})
    return _values_len_dict


def pretty_print(string, string_type=None):
    """ Take care of determining which fields should be justified to each side to improve readability """
    string = str(string)
    _string_length = pprint_dict[string_type] if string_type is not None else pprint_dict[string]
    _right_justified_strings = ['localhost', 'remotehost', 'mem', 'timer', 'bgp_prefix']
    if string in _right_justified_strings or string_type in _right_justified_strings:
        return string.rjust(_string_length)
    else:
        return string.ljust(_string_length)


def print_inetstat():
    """ Print inetstat results to the terminal """
    keys_to_print = ['localhost', 'lport', 'cstate', 'remotehost', 'rport', 'layer', 'ipv', 'pid', 'name', 'umask',
                     'pstate', 'th', 'mem', 'timer', 'time', 'cc', 'allocated', 'bgp_prefix', 'as_name']

    for key in keys_to_print:
        print(pretty_print(key), end=' ')
    print()

    for key, value in inetstat_dict.items():
        for _key in keys_to_print:
            print(pretty_print(value[_key], _key), end=' ')
        print()


if __name__ == "__main__":
    inetstat = INetstat()
    inetstat_dict = inetstat.ordered_netstat
    pprint_dict = dict_values_len(inetstat_dict)
    print_inetstat()
    end = time.time()
    print("exec time: {0:.2f}s".format(end - inetstat.start))
