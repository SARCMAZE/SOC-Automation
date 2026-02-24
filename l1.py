from engine.rule_engine import RuleEngine

class L1DetectionAgent:
    def __init__(self):
        self.rule_engine = RuleEngine()

    def process(self, log):
        triggered_rules = self.rule_engine.evaluate(log)
        return {
            "original_log": log,
            "alerts": triggered_rules
        }
