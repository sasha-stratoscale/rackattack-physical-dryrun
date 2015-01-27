import time
import logging


class WaitForPredicate:

    def __init__(self, timeout=3, interval=0.1):
        self._timeout = timeout
        self._interval = interval

    def waitAndReturn(self, predicate, * args, ** kwargs):
        before = time.time()
        while time.time() - before < self._timeout:
            ret = predicate(* args, ** kwargs)
            if ret:
                return ret
            time.sleep(self._interval)
        raise Exception("Predicate '%s' did not happen within timeout" % predicate)
