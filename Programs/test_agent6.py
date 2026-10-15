from agent6 import VulnerabilityAgent


LOG_FILE = "tools/vulnerability_event.log"


def test_extract_product_version():

    agent = VulnerabilityAgent()

    with open(LOG_FILE, "r", encoding="utf-8") as file:
        lines = file.readlines()

    asset = agent.extract_product_version(lines)

    assert asset is not None
    assert asset["product"] == "Apache_HTTP_Server"
    assert asset["version"] == "2.4.49"


def test_agent6_run():

    agent = VulnerabilityAgent()

    result = agent.run(LOG_FILE)

    assert result["status"] == "success"

    assert result["asset"]["product"] == "Apache_HTTP_Server"
    assert result["asset"]["version"] == "2.4.49"

    cve_results = result["cve_results"]

    assert cve_results["status"] == "success"
    assert cve_results["total_results"] > 0

    cve_ids = [
        finding["cve_id"]
        for finding in cve_results["results"]
    ]

    assert "CVE-2021-41773" in cve_ids


def test_llm_assessment():

    agent = VulnerabilityAgent()

    result = agent.run(LOG_FILE)

    assessment = result["assessment"]

    assert assessment
    assert isinstance(assessment, str)

    # Agent 6 should produce the four
    # evidence-aware security sections.
    assert "EVIDENCE" in assessment.upper()
    assert "INFERENCE" in assessment.upper()
    assert "UNKNOWN" in assessment.upper()
    assert "RECOMMENDATIONS" in assessment.upper()


if __name__ == "__main__":

    test_extract_product_version()
    test_agent6_run()
    test_llm_assessment()

    print("All Agent 6 tests passed.")
