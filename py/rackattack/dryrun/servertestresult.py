class ServerTestResult(dict):

    def __init__(self, serverId):
        self['name'] = serverId
        self['status'] = 'SUCCESS'

    def addCheck(self, checkCategory, checkName, checkStatus, checkLog='', extra=None):
        categoryEntry = dict.setdefault(self, checkCategory, [])
        categoryEntry.append((checkName, checkStatus, checkLog, extra))
        if not checkStatus:
            self['status'] = 'FAIL'

    def failedChecks(self):
        failedTests = []
        for category, categoryChecks in dict.items(self):
            failedTests.extend([(category, check) for check in categoryChecks if check[1] is False])
        return failedTests

    def failedChecksByCategory(self, categoryName):
        return [check for check in self[categoryName] if check[1] is False]

    def summary(self):
        return {category: len(self.failedChecksByCategory(category)) == 0
                for category in self.keys() if category not in ['name', 'status']}

    def passed(self):
        return self['status'] == 'SUCCESS'
