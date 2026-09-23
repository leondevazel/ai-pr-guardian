import os, subprocess, hashlib

def run(cmd):
    os.system("ls " + cmd)
    subprocess.call("echo " + cmd, shell=True)

def handle(data):
    return eval(data)

def hashpw(p):
    return hashlib.md5(p.encode()).hexdigest()

PASSWORD = "hunter2supersecret"
