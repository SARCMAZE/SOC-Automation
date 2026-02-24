import re
from typing import List, Dict

class RuleEngine:
    def __init__(self):
        self.rules = [
            self.brute_force_rule,
            self.suspicious_ip_rule,
            self.privilege_escalation_rule
        ]

    def evaluate(self, log: Dict) -> List[str]:
        triggered = []
        for rule in self.rules:
            result = rule(log)
            if result:
                triggered.append(result)
        return triggered

    def brute_force_rule(self, log):
        if log.get("event_type") == "login_failure" and log.get("attempts", 0) > 5:
            return "BRUTE_FORCE_DETECTED"
        return None

    def suspicious_ip_rule(self, log):
        blacklisted_ips = ["185.220.101.1", "45.33.32.156"]
        if log.get("source_ip") in blacklisted_ips:
            return "BLACKLISTED_IP_ACTIVITY"
        return None

    def privilege_escalation_rule(self, log):
        if log.get("event_type") == "role_change" and log.get("new_role") == "admin":
            return "PRIVILEGE_ESCALATION"
        return None
