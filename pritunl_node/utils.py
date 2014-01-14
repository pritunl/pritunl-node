import subprocess

def rmtree(path):
    subprocess.check_call(['rm', '-r', path])

def check_output(*popenargs, **kwargs):
    # For python2.6 support
    if 'stdout' in kwargs:
        raise ValueError('stdout argument not allowed, ' + \
            'it will be overridden.')
    process = subprocess.Popen(stdout=subprocess.PIPE,
        *popenargs, **kwargs)
    output, unused_err = process.communicate()
    retcode = process.poll()
    if retcode:
        cmd = kwargs.get('args')
        if cmd is None:
            cmd = popenargs[0]
        raise subprocess.CalledProcessError(retcode, cmd, output=output)
    return output
