from _readfile import readfile
from _writefile import writefile

__all__ = ['readfile','writefile','defaultify','defaultifyDict','isInt']

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
