# import paramiko # GNU LGPL v2.1
import os
import getpass
import traceback
import sys

import socket
from ssh2 import session     # GNU LGPL v2.1
from ssh2 import error_codes as ecd
from ssh2 import utils
from .config import SSHconfig
from io import BytesIO

if sys.version_info[0] == 3:
    raw_input = input


class SSH(object):

    mode = 'ssh'

    def __init__(self, timeout=None, config_path=None, pkey=None, **kwargs):
        self.__timeout = timeout
        self.__reset_socket()
        self._session = None
        self.__homedir = None
        self.__pkey = None
        self.__non_block = None
        self.__set_default_parameter(config_path, pkey)

    def __reset_socket(self):
        self._sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self._sock.settimeout(self.__timeout)

    def __init_socket(self, hostname, port):
        self._sock.connect((hostname, int(port)))
        self._sock.settimeout(None)

    def __set_default_parameter(self, config_path=None, pkey=None):
        self.__cfg = SSHconfig(config_path, pkey)
        self._stored_cfg = None

    @property
    def avail_host(self):
        return self.__cfg.avail

    def connect(self, hostname=None, port=None, username=None, pkey=None, dir=None, non_block=False):
        if self._session is not None:
            self.__disconnect()
        if hostname is None:
            hostname = raw_input('Hostname: ')
        if port is None:
            port = raw_input('Port(default=22): ') or 22
        self.__init_socket(hostname, port)
        self._session = session.Session()
        self._session.handshake(self._sock)
        self.__non_block = non_block

        if username is None:
            username = raw_input('Username(default={}): ').format(os.getlogin()) or str(os.getlogin())
        if pkey is None:
            password = getpass.getpass(prompt='Password: ', stream=None)
            code = self._session.userauth_password(username, password)
        else:
            code = self._session.userauth_publickey_fromfile(username, pkey)

        # self._session.set_blocking(False)
        if code != 0:
            raise Exception('Connection failed.')
        else:
            self.__check_homedir()
            self.__hostname = hostname
            self.__username = username
            self.__port = port
            self.__dir = dir

    def connect_by_idx(self, idx):
        cfg = self.__cfg.get_config_by_idx(idx)
        if 'pkey' not in cfg.keys():
            if self.__cfg.pkey_path is not None:
                cfg['pkey'] = self.__cfg.pkey_path
            self._stored_cfg = cfg

        self.connect(**cfg)
        self._stored_cfg['dir'] = self.homedir

    def connect_by_name(self, name):
        cfg = self.__cfg.get_config_by_name(name)
        if 'pkey' not in cfg.keys():
            if self.__cfg.pkey_path is not None:
                cfg['pkey'] = self.__cfg.pkey_path
            self._stored_cfg = cfg
        self.connect(**cfg)
        self._stored_cfg['dir'] = self.homedir

    def connected(self):
        try:
            return isinstance(self._sock.getpeername(), tuple)
        except:
            return False

    def __disconnect(self):
        self.__hostname = None
        self.__username = None
        self.__port = None
        self._session.disconnect()
        self._session = None
        self._sock.close()
        self.__homedir = None
        self.__reset_socket()
        self._stored_cfg = None

    def raise_connection_exception(self):
        raise Exception('The client is not connected to the remote system.')

    def __check_homedir(self):
        if self.connected():
            if self.__homedir is None:
                self.__homedir = str(self.exec_command('pwd', simple=True))
            else:
                pass
        else:
            self.raise_connection_exception()

    @property
    def homedir(self):
        return self.__homedir

    def open_sftp(self):
        if self._session is not None:
            return self._session.sftp_init()
        else:
            return None

    @property
    def socket(self):
        return self._sock

    @property
    def session(self):
        return self._session

    def exec_command(self, cmd, simple=False):
        chan = self.session.open_session()
        if self.__non_block is True:
            while chan == ecd.LIBSSH2_ERROR_EAGAIN:
                utils.wait_socket(self.socket, self.session)
                chan = self.session.open_session()
            while chan.execute(cmd) == ecd.LIBSSH2_ERROR_EAGAIN:
                utils.wait_socket(self.socket, self.session)
        else:
            chan.execute(cmd)
        rc1, stdout = chan.read_ex()
        if self.__non_block is True:
            while rc1 == ecd.LIBSSH2_ERROR_EAGAIN:
                rc1, stdout = chan.read_ex()
        if simple:
            chan.close()
            return stdout.decode('ascii')
        else:
            rc2, stderr = chan.read_stderr()
            chan.close()
            return BytesIO(stdout), BytesIO(stderr)

    def open_interface(self):
        from .interface import SSHInterface
        return SSHInterface(self)

    def close(self):
        self.__disconnect()

    # def refresh(self):
    #     self.__check_unexpected_disconnect()
    #
    # def __check_unexpected_disconnect(self):
    #     if not self.connected():
    #         if self.__hostname is not None:
    #             if self.__username is not None:
    #                 if self.__port is not None:
    #                     if self.__pkey is not None:
    #                         cfg = {'hostname': self.__hostname,
    #                                'port': self.__port,
    #                                'username': self.__username,
    #                                'pkey': self.__pkey}
    #                         self.__disconnect()
    #                         self.connect(*cfg)
    #     else:
    #         pass

    # def clone(self):
    #     if self._stored_cfg is not None:
    #         return SSH, self._stored_cfg
    #     else:
    #         return None

    def __repr__(self):
        (filename, line_number, function_name, text) = traceback.extract_stack()[-2]
        def_name = text[:text.find('=')].strip()
        output = []
        if self.connected():
            state = 'Connected'
            output.append("Hostname: {}".format(self.__hostname))
            output.append("Port: {}".format(self.__port))
            output.append("Username: {}".format(self.__username))
            output.append("Remote path: {}".format(self.__homedir))
        else:

            state = 'Disconnected'
            if os.path.exists(self.__cfg.config_path):
                config = 'Loaded'
            else:
                config = 'Not available'
            output.append("SSH Config: {}".format(config))
            if config == "Loaded":
                output.append("Available hosts:")
                for key, value in self.__cfg.avail.items():
                    output.append("\t{}: {}".format(key, value))
                output.append("Usage:")
                output.append("\t{}.connect_by_index([index in available hosts])".format(def_name))
                output.append("\t{}.conenct_by_name([name in available hosts])".format(def_name))
            else:
                output.append("Usage:")
                output.append("\t{}.connect_()")
            if self.__cfg.pkey_path is not None:
                pkey = 'Available'
            else:
                pkey = 'Not available'
            output.append("Private Key: {}".format(pkey))

        output.insert(0, "Connection state: {}".format(state))
        return '\n'.join(output)


# class SSH(paramiko.SSHClient):
#
#     mode = 'ssh'
#
#     def __init__(self, **kwargs):
#         super(SSH, self).__init__()
#         self.__initiate_attributes()
#         if 'pkey' in kwargs.keys():
#             self._set_default(pkey=kwargs['pkey'])
#         else:
#             self._set_default()
#
#     def __initiate_attributes(self):
#         self._cfg = dict()
#         self._pkey = None
#         self._hostnames = dict()
#         self._sftp = None
#         self._homedir = None
#         self._connected = False
#         self.ssh_config = None
#         self.ssh_path = None
#
#     # properties
#     @property
#     def avail(self):
#         return dict([(i, h) for i, h in enumerate(sorted(self._hostnames))])
#
#     @property
#     def connected(self):
#         return self._connected
#
#     @property
#     def cfg(self):
#         return self._cfg
#
#     @property
#     def homedir(self):
#         return self._homedir
#
#     def _check_homedir(self):
#         if self._connected:
#             self._homedir = self.exec_command('pwd')[1].readlines()[0].strip('\n')
#
#     def getcwd(self):
#         if self._connected:
#             with self.open_sftp() as sftp:
#                 if sftp.getcwd() is None:
#                     output = self._homedir
#                     # return self._homedir
#                 else:
#                     output = sftp.getcwd()
#                     # return sftp.getcwd()
#             return output
#         else:
#             return None
#
#     # config parser
#     def parse_cfg(self, idx):
#         if idx in self.avail.keys():
#             user_config = self.ssh_config.lookup(self.avail[idx])
#             for key in ["hostname", "user", "port"]:
#                 if key == "user":
#                     self._cfg['username'] = user_config[key]
#                 elif key == "port":
#                     self._cfg[key] = int(user_config[key])
#                 else:
#                     self._cfg[key] = user_config[key]
#         if self._pkey is not None:
#             self._cfg['pkey'] = self._pkey
#
#     # setters
#     def _set_default(self, pkey=None):
#         """
#         default configuration setter
#         """
#         if pkey is None:
#             pkey = 'id_rsa'
#
#         self.load_system_host_keys()
#         self.set_missing_host_key_policy(paramiko.WarningPolicy)
#
#         self.ssh_config = paramiko.SSHConfig()
#         self.ssh_path = os.path.join(os.path.expanduser("~"), '.ssh')
#
#         user_config_file = os.path.join(self.ssh_path, 'config')
#
#         # If config file exist at default path, parse the information
#         if os.path.exists(user_config_file):
#             with open(user_config_file) as f:
#                 self.ssh_config.parse(f)
#             # update hostnames
#             self._hostnames = [h for h in self.ssh_config.get_hostnames() if h is not '*']
#             if os.path.exists(pkey):
#                 pkey_path = pkey
#             else:
#                 pkey_path = os.path.join(self.ssh_path, pkey)
#             if os.path.exists(pkey_path):
#                 self.set_privatekey(pkey_path)
#
#     def set_hostname(self, hostname):
#         self._cfg['hostname'] = hostname
#
#     def set_username(self, username):
#         self._cfg['username'] = username
#
#     def set_port(self, port):
#         self._cfg['port'] = port
#
#     def set_privatekey(self, pkey_path):
#         if os.path.exists(pkey_path):
#             with open(pkey_path) as keyobj:
#                 self._pkey = paramiko.RSAKey.from_private_key(keyobj)
#         else:
#             self._pkey = None
#
#     # methods
#     def connect_host(self, idx=None, **kwargs):
#         if idx is None:
#             for key in kwargs.keys():
#                 if key == 'username':
#                     self._cfg['username'] = kwargs[key]
#                 elif key == 'password':
#                     self._cfg[key] = kwargs[key]
#                 elif key == 'hostname':
#                     self._cfg[key] = kwargs[key]
#                 elif key == 'port':
#                     self._cfg[key] = kwargs[key]
#                 elif key == 'pkey':
#                     self.set_privatekey(kwargs[key])
#                     self._cfg[key] = self._pkey
#                 else:
#                     pass
#         else:
#             self.parse_cfg(idx)
#
#         if "hostname" not in self._cfg.keys():
#             self._cfg["hostname"] = raw_input('Hostname: ')
#         else:
#             if "username" not in self._cfg.keys():
#                 default_user = getpass.getuser()
#                 username = raw_input('Username(default={}): '.format(default_user))
#                 if username is None:
#                     self._cfg["username"] = default_user
#                 else:
#                     self._cfg["username"] = username
#             if "pkey" not in self._cfg.keys():
#                 self._cfg["password"] = getpass.getpass(prompt='Password: ', stream=None)
#             if "port" not in self._cfg.keys():
#                 port = raw_input('Port(default=22): ')
#                 if port is None:
#                     port = 22
#                 self._cfg["port"] = port
#         try:
#             self.connect(**self._cfg)
#             self._connected = True
#             self._check_homedir()
#             print("Connected to {} as {}".format(self._cfg["hostname"], self._cfg["username"]))
#         except:
#             self._connected = False
#             print("Connection failed")
#
#     def close(self):
#         super(SSH, self).close()
#         self._connected = False
#         self._cfg = dict()
#
#     def open_interface(self):
#         from .interface import SSHInterface
#         return SSHInterface(self)
#
#     def __repr__(self):
#         (filename, line_number, function_name, text) = traceback.extract_stack()[-2]
#         def_name = text[:text.find('=')].strip()
#         output = []
#         if self._connected:
#             state = 'Connected'
#             output.append("Hostname: {}".format(self._cfg["hostname"]))
#             output.append("Port: {}".format(self._cfg["port"]))
#             output.append("Username: {}".format(self._cfg["username"]))
#             output.append("Remote path: {}".format(self.getcwd()))
#         else:
#             state = 'Disconnected'
#             if os.path.exists(os.path.join(self.ssh_path, 'config')):
#                 config = 'Loaded'
#             else:
#                 config = 'Not available'
#             output.append("SSH Config: {}".format(config))
#             if config == "Loaded":
#                 output.append("Available hostnames:")
#                 for key, value in self.avail.items():
#                     output.append("\t{}: {}".format(key, value))
#                 output.append("Usage:")
#                 output.append("\t{}.connect_host([index_of_hostname])".format(def_name))
#             else:
#                 output.append("Usage:")
#                 output.append("\t{}.connect_host()")
#             if self._pkey is not None:
#                 pkey = 'Available'
#             else:
#                 pkey = 'Not available'
#             output.append("Private Key: {}".format(pkey))
#
#         output.insert(0, "Connection state: {}".format(state))
#         return '\n'.join(output)


class SLURM(SSH):

    mode = 'slurm'

    def __init__(self, **kwargs):
        super(SLURM, self).__init__(**kwargs)

    def open_interface(self):
        from .interface import SLURMInterface
        return SLURMInterface(self)

    def clone(self):
        if self._stored_cfg is not None:
            return SLURM, self._stored_cfg
        else:
            return None