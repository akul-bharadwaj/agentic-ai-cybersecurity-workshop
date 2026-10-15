from agent7 import MITRESecurityAgent


LOG_FILE = "tools/vulnerability_event.log"


def test_agent7_run():

    agent = MITRESecurityAgent()

    result = agent.run(LOG_FILE)

    # ------------------------------------------
    # Basic result validation
    # ------------------------------------------

    assert result["status"] == "success"

    # ------------------------------------------
    # Validate MITRE technique
    # ------------------------------------------

    technique = result["technique"]

    assert technique["status"] == "success"
    assert technique["technique_id"] == "T1190"

    assert (
        technique["name"]
        == "Exploit Public-Facing Application"
    )

    # ------------------------------------------
    # Validate observed activity
    # ------------------------------------------

    observed_activity = result["observed_activity"]

    assert len(observed_activity) == 3

    for event in observed_activity:

        assert "SUSPICIOUS_REQUEST" in event

    # ------------------------------------------
    # Validate LLM assessment
    # ------------------------------------------

    assessment = result["assessment"]

    assert isinstance(
        assessment,
        str
    )

    assert len(assessment.strip()) > 0

    # Agent 7 should maintain the
    # evidence/inference/unknown boundary.

    assert "EVIDENCE" in assessment
    assert "INFERENCE" in assessment
    assert "UNKNOWN" in assessment
    assert "RECOMMENDATIONS" in assessment

    print("All Agent 7 tests passed.")


if __name__ == "__main__":

    test_agent7_run()
