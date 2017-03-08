import argparse
import cmd
import shlex

from SilentException import SilentException

class VAction(argparse.Action):
    def __call__(self, parser, args, values, option_string=None):
        # print 'values: {v!r}'.format(v=values)
        if values==None:
            values='1'
        try:
            values=int(values)
        except ValueError:
            values=values.count('v')+1
        setattr(args, self.dest, values)

class CommandArgumentParser(argparse.ArgumentParser):
    def __init__(self,command = None):
        argparse.ArgumentParser.__init__(self, prog=command)
        
    def exit(self, status=0, message=None):
        if None == message:
            raise SilentException()
        else:
            raise Exception(message)

    def error(self, message):
        raise Exception(message)

    def parse_args(self,commandLine):
        if isinstance(commandLine, basestring):
            commandLine = shlex.split(commandLine)
        return super(CommandArgumentParser,self).parse_args(commandLine)
    
