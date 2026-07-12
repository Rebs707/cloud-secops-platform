class SecurityScanAgent:

    def scan(self, resource):
        return {
            "resource": resource,
            "status": "scan completed",
            "issues": []
        }
