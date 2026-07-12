class ThreatDetectionAgent:

    def detect(self, resource):
        return {
            "resource": resource,
            "threats": [],
            "status": "no threats detected"
        }
