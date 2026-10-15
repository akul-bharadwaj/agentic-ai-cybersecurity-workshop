from tools.cve_lookup import lookup_cve, search_product_version


def test_known_cve():

    result = lookup_cve("CVE-2021-41773")

    assert result["status"] == "success"
    assert result["cve_id"] == "CVE-2021-41773"

    assert result["cvss"] is not None
    assert result["cvss"]["score"] == 9.8
    assert result["cvss"]["severity"] == "CRITICAL"


def test_unknown_cve():

    result = lookup_cve("CVE-0000-0000")

    assert result["status"] == "not_found"


def test_product_version_search():

    result = search_product_version(
        "Apache_HTTP_Server",
        "2.4.49"
    )

    assert result["status"] == "success"
    assert result["product"] == "Apache_HTTP_Server"
    assert result["version"] == "2.4.49"

    assert result["total_results"] > 0

    cve_ids = [
        item["cve_id"]
        for item in result["results"]
    ]

    assert "CVE-2021-41773" in cve_ids


def test_product_version_has_cvss():

    result = search_product_version(
        "Apache_HTTP_Server",
        "2.4.49"
    )

    for finding in result["results"]:

        assert finding["cve_id"]
        assert finding["description"]

        if finding["cvss"]:
            assert finding["cvss"]["score"] is not None
            assert finding["cvss"]["severity"] is not None


if __name__ == "__main__":

    test_known_cve()
    test_unknown_cve()
    test_product_version_search()
    test_product_version_has_cvss()

    print("All CVE lookup tests passed.")
