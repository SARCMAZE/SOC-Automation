from collections import defaultdict

class L2CorrelationAgent:
    def __init__(self):
        self.event_memory = defaultdict(list)

    def correlate(self, event):
        user = event["original_log"].get("user")
        self.event_memory[user].append(event)

        alert_count = sum(len(e["alerts"]) for e in self.event_memory[user])

        return {
            "user": user,
            "aggregated_alerts": alert_count,
            "events": self.event_memory[user]
        }
