import subprocess

def rmtree(path):
    subprocess.check_call(['rm', '-r', path])
