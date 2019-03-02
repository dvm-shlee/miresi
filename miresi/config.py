import re
import os

class SSHconfig(object):

    _pattern_host = re.compile(r'Host\s+(.*)')
    _pattern_args = re.compile(r'\s+([A-Za-z0-9]+)\s(.*)')

    def __init__(self, path=None, pkey=None):
        if path is None:
            path = os.path.join(os.path.expanduser('~'), '.ssh')
        if pkey is None:
            pkey = 'id_rsa'
        self.set_sshpath(path, pkey)
        self.parse()

    def set_sshpath(self, path, pkey):
        self._sshpath = path
        self._cfgpath = os.path.join(path, 'config')
        self._pkypath = os.path.join(path, pkey)

    def parse(self):
        name, line_counter = None, None
        if os.path.exists(self._cfgpath):
            cfg = dict()
            with open(self._cfgpath, 'r') as f:
                for line in f.readlines():
                    if self._pattern_host.match(line):
                        name = self._pattern_host.sub(r'\1', line).strip()
                        cfg[name] = dict()
                    elif self._pattern_args.match(line):
                        if name is not None:
                            key, value = self._pattern_args.sub(r'\1,\2', line).lower().split(',')
                            if key in ['user', 'hostname', 'port', 'identityfile', 'dir']:
                                if key in ['user']:
                                    key+='name'
                                elif key in ['identityfile']:
                                    key = 'pkey'
                                cfg[name][key.lower().strip()] = value.strip()
                    else:
                        pass
        else:
            cfg = None
        self.__cfg = cfg

    @property
    def path(self):
        if os.path.exists(self._cfgpath):
            return self._cfgpath
        else:
            return None

    @property
    def config_path(self):
        if os.path.exists(self._cfgpath):
            return self._cfgpath
        else:
            return None

    @property
    def pkey_path(self):
        if os.path.exists(self._pkypath):
            return self._pkypath
        else:
            return None

    @property
    def avail(self):
        return {i:hostname for i, hostname in enumerate(self.__cfg.keys())}

    def get_config_by_idx(self, idx):
        return self.__cfg[self.avail[idx]]

    def get_config_by_name(self, name):
        return self.__cfg[name]

