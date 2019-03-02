import os, stat, re
import sys
from ssh2 import sftp as flags
from ssh2 import error_codes as ecd
from ssh2 import utils
from .path import Path

if sys.version_info[0] == 3:
    raw_input = input


class SSHInterface(object):
    def __init__(self, client=None):
        self._initiate_attributes()
        if client is None:
            pass
        else:
            self.set_client(client)

    def _initiate_attributes(self):
        self._client = None
        self._sftp = None
        self._path = None
        self._homedir = None
        self._umask = None
        self._curpath = list()
        self._drive = None

    def set_client(self, client):
        self._client = client
        if client.connected:
            self._sftp = client.open_sftp()
            while self._sftp is None:
                utils.wait_socket(client.socket, client.session)
                self._sftp = client.open_sftp()
            if self._homedir == None:
                while self._sftp == ecd.LIBSSH2_ERROR_EAGAIN:
                    utils.wait_socket(client.socket, client.session)
                    self._sftp = client.open_sftp()
                self._homedir = self._sftp.realpath('.')
                while self._homedir == ecd.LIBSSH2_ERROR_EAGAIN:
                    utils.wait_socket(client.socket, client.session)
                    self._homedir = self._sftp.realpath('.')
            self._path = Path(self)
            self._check_sep()
        else:
            pass

    def getcwd(self):
        if self._homedir is not None:
            if len(self._curpath) == 0:
                if self._drive is None:
                    self._curpath.append('')
                else:
                    self._curpath.append(self._drive)
            return self._sep.join(self._curpath)
        else:
            self._client.raise_connection_exception()

    @property
    def platform(self):
        return self._platform

    def _check_sep(self):
        stdout = self._client.exec_command('python -c "import sys; print(sys.platform)"', simple=True)
        self._platform = stdout.strip(), sys.platform

        if self._platform[0] in ["linux", "linux2", "darwin"]:
            self._sep = '/'
        elif self._platform[0] == "win32":
            self._sep = '\\'
            self._drive = self._homedir.split(self._sep)[0]
        else:
            raise Exception('NotCompatiblePlatform')
        self._curpath = self._homedir.split(self._sep)
        self.umask()

    @property
    def sep(self):
        return self._sep

    def chmod(self, path, mode):
        """ working as terminal chmod
        # TODO: need to check if it's functioning or not.
        """
        if isinstance(mode, str):
            if len(mode)> 4:
                mode = mode[-3:]
        elif isinstance(mode, int):
            mode = oct(mode)[-3:]
        else:
            raise Exception
        self._client.exec_command('chmod {} {}'.format(mode, path), simple=True)

    def umask(self, mask=None):
        """ different with os, on remote system, it works as commandline umask

        Args:
            mask(str):      user mask (e.g. '0022')

        Returns:
            umask(str):     current user mask if mask is not given.
        """
        if mask is None:
            if self._umask is None:
                self._umask = str(self._client.exec_command('umask', simple=True).strip())
            return self._umask
        else:
            _ = self._client.exec_command('umask {}'.format(mask).format())

    def __convert_umask_to_flags(self, umask, isdir=False):
        if isdir:
            mode = 777
        else:
            mode = 666
        if isinstance(umask, str):
            if len(umask) > 4:
                umask = umask[-3:]
        elif isinstance(umask, int):
            umask = oct(umask)[-3:]
        else:
            raise Exception

        return int(str(mode - int(umask)).zfill(3), 8)

    def open(self, file, mode='r'):
        """ this method opens the file on remote system (if possible)
        and returns a corresponding file object.
        sftp only handle binary mode so 't' and 'b' cannot be used as mode.

        Args:
            file(str):      path-like object (representing a file system path) giving the pathname
            mode(str):      mode while opening a file. If not provided, it defaults to 'r'.
                            'r': open a file for reading. (default)
                            'w': open a file for writing.
                                 creates a new file if it does not exist or truncates the file if it exists.
                            'x': open a file for exclusive creation. If the file already exists, the operation fails
                            'a': open for appending at the end of the file without truncating it,
                                 creates a new file if it does not exist.
                            '+': open a file for updating (reading and writing)
        Returns:

        """
        f_flags = 0
        rw_flag = 0
        for code in mode:
            if code == 'r':
                rw_flag = flags.LIBSSH2_FXF_READ
            elif code == 'w':
                rw_flag = flags.LIBSSH2_FXF_WRITE
                f_flags = f_flags | flags.LIBSSH2_FXF_CREAT | flags.LIBSSH2_FXF_TRUNC
            elif code == 'x':
                rw_flag = flags.LIBSSH2_FXF_WRITE
                f_flags = f_flags | flags.LIBSSH2_FXF_EXCL | flags.LIBSSH2_FXF_CREAT
            elif code == 'a':
                rw_flag = flags.LIBSSH2_FXF_WRITE
                f_flags = f_flags | flags.LIBSSH2_FXF_APPEND | flags.LIBSSH2_FXF_CREAT
            elif code == '+':
                if flags.LIBSSH2_FXF_READ == rw_flag:
                    f_flags = f_flags | flags.LIBSSH2_FXF_WRITE
                elif flags.LIBSSH2_FXF_WRITE == rw_flag:
                    f_flags = f_flags | flags.LIBSSH2_FXF_READ
                else:
                    f_flags = f_flags | flags.LIBSSH2_FXF_READ | flags.LIBSSH2_FXF_WRITE
            else:
                pass
        f_flags = f_flags + rw_flag
        umask = self.umask()
        f_mode = self.__convert_umask_to_flags(umask)

        fh = self._sftp.open(file, flags=f_flags, mode=f_mode)
        while fh is None:
            utils.wait_socket(self._client.socket, self._client.session)
            fh = self._sftp.open(file, flags=f_flags, mode=f_mode)
        return fh # TODO: File handler not compatible with other python modules

    @property
    def curdir(self):
        if self._client.connected:
            return self.getcwd()
        else:
            raise self._client.raise_connection_exception()

    @property
    def client(self):
        return self._client

    def walk(self, path):
        if self._client.connected:
            files = []
            folders = []
            if self.path.exists(self.path.abspath(path)):  # check if the file exist
                init_path = path
            else:
                print(path)
                raise Exception('NoPathException')  # the path is not exists
            fobjs = self.listdir(init_path, get_attr=True)
            for filename, fstat in fobjs:
                if stat.S_ISDIR(fstat.permissions):
                    folders.append(filename)
                else:
                    files.append(filename)
            yield path, folders, files
            for folder in folders:
                new_path = self.path.join(init_path, folder)
                for output in self.walk(new_path):
                    yield output

    @property
    def path(self):
        return self._path

    @property
    def sftp(self):
        return self._sftp

    def listdir(self, path=None, get_attr=False):
        if path is None:
            path = '.'

        dh = self._sftp.opendir(path)
        while dh == ecd.LIBSSH2_ERROR_EAGAIN:
            utils.wait_socket(self.client.socket, self.client.session)
            dh = self._sftp.opendir(path)
        output = []
        for size, buf, attr in dh.readdir():
            if size == ecd.LIBSSH2_ERROR_EAGAIN:
                utils.wait_socket(self.client.socket, self.client.session)
                continue
            if get_attr:
                if buf.decode('ascii') not in ['.', '..']:
                    output.append((buf.decode('ascii'), attr))
            else:
                if buf.decode('ascii') not in ['.', '..']:
                    output.append(buf.decode('ascii'))

        return output
        #
        #
        #     output = [(buf.decode('ascii'), attr) for size, buf, attr in self._sftp.opendir(path).readdir()
        #               if buf.decode('ascii') not in ['.', '..']]
        # else:
        #     output = [buf.decode('ascii') for size, buf, attr in self._sftp.opendir(path).readdir()
        #               if buf.decode('ascii') not in ['.', '..']]
        #

    def chdir(self, path):
        if path == '..':
            if len(self._curpath) == 0:
                pass
            self._curpath.pop()
        elif path == '.':
            pass
        else:
            self._curpath.append(path)

    def mkdir(self, path, mode=None):
        dirname =  os.path.dirname(path)
        if len(dirname) == 0:
            path = self.path.join(self.getcwd(), path)
        if mode is None:
            mode = self.__convert_umask_to_flags(self._umask, isdir=True)
        elif isinstance(mode, int):
            if len(str(mode)) == 3:
                mode = int(str(mode), 8)
            else:
                raise Exception('ModeValueError')
        else:
            raise Exception('ModeTypeError')
        code = self._sftp.mkdir(path, mode)
        while code == ecd.LIBSSH2_ERROR_EAGAIN:
            utils.wait_socket(self.client.socket, self.client.session)
            self._sftp.mkdir(path, mode)

    def unlink(self, path):
        if self.path.islink(path) or self.path.isfile(path):
            code = self._sftp.unlink(self.path.abspath(path))
            while code == ecd.LIBSSH2_ERROR_EAGAIN:
                utils.wait_socket(self.client.socket, self.client.session)
                code = self._sftp.unlink(self.path.abspath(path))
        else:
            raise Exception('PathFiletypeError')

    def rmdir(self, path):
        if self.path.isdir(path):
            code = self._sftp.rmdir(self.path.abspath(path))
            while code == ecd.LIBSSH2_ERROR_EAGAIN:
                utils.wait_socket(self.client.socket, self.client.session)
                code = self._sftp.rmdir(self.path.abspath(path))
        else:
            raise Exception('PathFiletypeError')

    def pid_exists(self, pid):
        """ Analog with psutil.pid_exists(pid)"""
        import re
        p = re.compile(r'(^\d+)\s(.*)')
        stdout = self._client.exec_command("ps -eo pid,command | grep {}".format(pid), simple=True)
        ps = map(str.strip, stdout.split('\n'))
        pids = [int(p.sub(r'\1', line)) for line in ps if p.match(line)]
        if pid in pids:
            return True
        else:
            return False


class SLURMInterface(SSHInterface):
    def __init__(self, *args, **kwargs):
        super(SLURMInterface, self).__init__(*args, **kwargs)

    def __check_jop_state(self, jobid):
        stdout = self._client.exec_command("squeue -j {} -l".format(jobid), simple=True)

        header = None
        values = None

        while stdout.strip().split()[0] != 'JOBID':
            header = stdout.readline().strip().split()
            values = stdout.readline().strip().split()

        return dict(zip(header, values))

    def pid_exists(self, pid):
        """Analog with psutil.pid_exists(pid) but for SLURM
        squeue can be use to check if the process currently working.
        """
        state = self.__check_jop_state(pid)
        if len(state) is 0:
            return False
        else:
            return True


# TODO: connect through Paramiko
# class SSHInterface(object):
#     """Remote pathname manipulations"""
#     def __init__(self, client=None):
#         self._initiate_attributes()
#         if client is None:
#             pass
#         else:
#             self.set_client(client)
#
#     def _initiate_attributes(self):
#         self._client = None
#         self._sftp = None
#         self._path = None
#
#     def set_client(self, client):
#         self._client = client
#         if client.connected:
#             self._sftp = client.open_sftp()
#             self._path = Path(self)
#             self._check_sep()
#         else:
#             pass
#
#     @property
#     def platform(self):
#         return self._platform
#
#     def _check_sep(self):
#         _, stdout, _ = self._client.exec_command('python -c "import sys; print(sys.platform)"')
#         self._platform = stdout.readlines()[0].strip(), sys.platform
#
#         if self._platform[0] in ["linux", "linux2", "darwin"]:
#             self._sep = '/'
#         elif self._platform[0] == "win32":
#             self._sep = '\\'
#
#     @property
#     def sep(self):
#         return self._sep
#
#     @property
#     def file(self):
#         return self._sftp.file
#
#     @property
#     def sftp(self):
#         return self._sftp
#
#     @property
#     def avail(self):
#         return self._client.avail
#
#     @property
#     def connect_host(self):
#         return self._client.connect_host
#
#     @property
#     def connect(self):
#         return self._client.connect
#
#     @property
#     def client(self):
#         return self._client
#
#     @property
#     def connected(self):
#         return self._client.connected
#
#     @property
#     def curdir(self):
#         if self.connected:
#             return self._client.getcwd()
#         else:
#             raise Exception  # Not connected to the server
#
#     def walk(self, path):
#         if self.connected:
#             files = []
#             folders = []
#             if self.path.exists(path):  # check if the file exist
#                 init_path = path
#             else:
#                 relpath = self.path.join(self.curdir, path)
#                 if self.path.exists(relpath):
#                     init_path = relpath
#                 else:
#                     raise Exception  # the path is not exists
#             fobjs = self._sftp.listdir_attr(init_path)
#             for i in range(len(fobjs)):
#                 if stat.S_ISDIR(fobjs[i].st_mode):
#                     folders.append(fobjs[i].filename)
#                 else:
#                     files.append(fobjs[i].filename)
#             yield path, folders, files
#             for folder in folders:
#                 new_path = self.path.join(init_path, folder)
#                 for output in self.walk(new_path):
#                     yield output
#
#     @property
#     def path(self):
#         return self._path
#
#     @property
#     def listdir(self):
#         return self._sftp.listdir
#
#     @property
#     def chdir(self):
#         return self._sftp.chdir
#
#     @property
#     def mkdir(self):
#         return self._sftp.mkdir
#
#     @property
#     def rm(self):
#         return self._sftp.rm
#
#     @property
#     def rmdir(self):
#         return self._sftp.rmdir
#
#     @property
#     def get(self):
#         return self._sftp.get
#
#     @property
#     def put(self):
#         return self._sftp.put
#
#     def pid_exists(self, pid):
#         """ Analog with psutil.pid_exists(pid)"""
#         import re
#         p = re.compile(r'(^\d+)\s(.*)')
#         _, stdout, _ = self._client.exec_command("ps -eo pid,command | grep {}".format(pid))
#         ps = map(str.strip, stdout.read().split('\n'))
#         pids = [int(p.sub(r'\1', line)) for line in ps if p.match(line)]
#         if pid in pids:
#             return True
#         else:
#             return False