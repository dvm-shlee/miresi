import os, stat, re
from ssh2 import error_codes as ecd


class Path(object):
    def __init__(self, interface):
        self._msi = interface

    def join(self, *args):
        remote_platform, local_platform = self._msi.platform
        if local_platform == remote_platform:
            return os.path.join(*args)
        else:
            return os.path.join(*args).replace(os.sep, self._msi.sep)

    def split(self, path):
        splitted = path.split(self._msi.sep)
        return self._msi.sep.join(splitted[:-1]), splitted[-1]

    def abspath(self, path):
        pattern = re.compile(r'^[{}].*'.format(self._msi.sep))
        if pattern.match(path):
            return path
        else:
            return self.join(self._msi.curdir, path)

    def dirname(self, path):
        return self.split(path)[0]

    def basename(self, path):
        return self.split(path)[1]

    @property
    def splitext(self):
        return os.path.splitext

    def isdir(self, path):
        # return stat.S_ISDIR(self.__ifc.sftp.lstat(path).st_mode)
        lstat = self._msi.sftp.lstat(path)
        while lstat == ecd.LIBSSH2_ERROR_EAGAIN:
            lstat = self._msi.sftp.lstat(path)
        return stat.S_ISDIR(lstat.permissions)

    def isfile(self, path):
        lstat = self._msi.sftp.lstat(path)
        while lstat == ecd.LIBSSH2_ERROR_EAGAIN:
            lstat = self._msi.sftp.lstat(path)
        return stat.S_ISREG(lstat.permissions)

    def islink(self, path):
        lstat = self._msi.sftp.lstat(path)
        while lstat == ecd.LIBSSH2_ERROR_EAGAIN:
            lstat = self._msi.sftp.lstat(path)
        return stat.S_ISLNK(lstat.permissions)

    def exists(self, path):
        """Test whether a path exists in remote host. Returns True for broken symbolic links"""
        if self._msi.client.connected:
            return bool(self._msi.client.exec_command('[ -e {} ] && echo 1 || echo 0', simple=True))
        else:
            # Not connected to the server
            raise Exception('OfflineClientException')
