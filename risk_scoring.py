class RiskScoringEngine:
    RULE_WEIGHTS = {
        "BRUTE_FORCE_DETECTED": 5,
        "BLACKLISTED_IP_ACTIVITY": 7,
        "PRIVILEGE_ESCALATION": 10
    }

    def calculate_score(self, correlated_data):
        score = 0
        for event in correlated_data["events"]:
            for alert in event["alerts"]:
                score += self.RULE_WEIGHTS.get(alert, 1)

        return score
