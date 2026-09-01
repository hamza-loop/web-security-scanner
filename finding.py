class SecurityFinding:

    def __init__(self, name, severity, description, score_impact=0):
        self.name = name
        self.severity = severity
        self.description = description
        self.score_impact = score_impact

    def to_dict(self):
        return {
            "name": self.name,
            "severity": self.severity,
            "description": self.description,
            "score_impact": self.score_impact,
        }