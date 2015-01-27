import re


def cpuInfo():
    return open("/proc/cpuinfo").read()
