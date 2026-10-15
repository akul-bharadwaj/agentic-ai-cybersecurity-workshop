from agent8 import SOCAssistant


LOG_FILE = "tools/vulnerability_event.log"


def test_agent8_run():

    assistant = SOCAssistant()

    result = assistant.run(LOG_FILE)

    # ------------------------------------------
    # Basic result validation
    # ------------------------------------------

    assert result["status"] == "success"

    # ------------------------------------------
    # Validate Agent 6 / CVE enrichment
    # ------------------------------------------

    cve_result = result["cve"]

    assert cve_result["status"] == "success"

    assert cve_result["asset"]["product"] == \
        "Apache_HTTP_Server"

    assert cve_result["asset"]["version"] == \
        "2.4.49"

    assert cve_result["cve_results"]["status"] == \
        "success"

    assert cve_result["cve_results"]["total_results"] >= 1

    # ------------------------------------------
    # Validate Agent 7 / MITRE enrichment
    # ------------------------------------------

    mitre_result = result["mitre"]

    assert mitre_result["status"] == "success"

    assert mitre_result["technique"]["status"] == \
        "success"

    assert mitre_result["technique"]["technique_id"] == \
        "T1190"

    assert mitre_result["technique"]["name"] == \
        "Exploit Public-Facing Application"

    # ------------------------------------------
    # Validate observed activity
    # ------------------------------------------

    observed_activity = \
        mitre_result["observed_activity"]

    assert len(observed_activity) == 3

    for event in observed_activity:

        assert "SUSPICIOUS_REQUEST" in event

    # ------------------------------------------
    # Validate Agent 5 security boundary
    # ------------------------------------------

    boundary = result["security_boundary"]

    assert "suspicious" in boundary
    assert "indicators" in boundary

    # ------------------------------------------
    # Validate final SOC assessment
    # ------------------------------------------

    assessment = result["assessment"]

    assert isinstance(
        assessment,
        str
    )

    assert len(assessment.strip()) > 0

        # ------------------------------------------
    # Validate final SOC assessment
    # ------------------------------------------

    assessment = result["assessment"]

    assert isinstance(
        assessment,
        str
    )

    assert len(assessment.strip()) > 0

    # The LLM may vary capitalization or formatting,
    # so normalize the response before checking sections.

    assessment_upper = assessment.upper()

    assert "EVIDENCE" in assessment_upper
    assert "INFERENCE" in assessment_upper
    assert "UNKNOWN" in assessment_upper
    assert "RECOMMENDATIONS" in assessment_upper


    print("All Agent 8 tests passed.")


if __name__ == "__main__":

    test_agent8_run()
