from fnmatch import fnmatch

def fnmatches(string,patterns):
    for pattern in patterns:
        if fnmatch(string,pattern):
            return True;
    return False;
