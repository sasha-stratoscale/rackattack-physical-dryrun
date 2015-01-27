class CpuInfo(dict):

    def __init__(self, cpuinfoString):
        processor = {}
        for cpuinfoLine in cpuinfoString.split('\n'):
            if len(cpuinfoLine.strip()) == 0:
                if len(processor.keys()) == 0:
                    continue
                self[int(processor['processor'])] = processor
                processor = {}
                continue
            (k, v) = cpuinfoLine.split(':')
            processor[k.strip()] = v.strip()

    def hasFlag(self, processorNum, flagName):
        return flagName in self[processorNum]['flags']

    def hasVt(self, processorNum=0):
        return self.hasFlag(processorNum, 'vmx') or self.hasFlag(processorNum, 'svm')
