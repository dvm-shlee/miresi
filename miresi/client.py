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


class SLURM(SSH):

    mode = 'slurm'

    def __init__(self, **kwargs):
        super(SLURM, self).__init__(**kwargs)

    def open_interface(self):
        from .interface import SLURMInterface
        return SLURMInterface(self)

