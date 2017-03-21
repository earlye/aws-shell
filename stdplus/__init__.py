from _readfile import readfile
from _readSshConfig import readSshConfig
from _writefile import writefile
from _fexecvp import fexecvp
from _fnmatches import fnmatches

__all__ = ['fexecvp','readfile','writefile','defaultify','defaultifyDict','isInt','fnmatches','readSshConfig']

def defaultify(value,default):
    if None == value:
        return default
    else:
        return value

def defaultifyDict(dictionary,key,default):
    if key in dictionary:
        return defaultify(dictionary[key],default)
    else:
        return default

def isInt(s):
    try:
        int(s)
        return True
    except ValueError:
        return False
