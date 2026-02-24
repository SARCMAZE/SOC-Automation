from agents.l1_detection import L1DetectionAgent
from agents.l2_correlation import L2CorrelationAgent
from agents.l3_response import L3ResponseAgent

sample_logs = [
    {"user": "alice", "event_type": "login_failure", "attempts": 7, "source_ip": "10.1.1.2"},
    {"user": "alice", "event_type": "role_change", "new_role": "admin", "source_ip": "10.1.1.2"},
    {"user": "bob", "event_type": "login_failure", "attempts": 2, "source_ip": "185.220.101.1"},
]

l1 = L1DetectionAgent()
l2 = L2CorrelationAgent()
l3 = L3ResponseAgent()

for log in sample_logs:
    l1_result = l1.process(log)
    l2_result = l2.correlate(l1_result)
    l3_result = l3.respond(l2_result)

    print(l3_result)
