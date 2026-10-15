import requests


NVD_CVE_API = "https://services.nvd.nist.gov/rest/json/cves/2.0"


def extract_cvss(cve):
    """
    Extract the highest-priority CVSS metric available.
    """

    metrics = cve.get("metrics", {})

    if metrics.get("cvssMetricV40"):
        metric = metrics["cvssMetricV40"][0]
        cvss = metric.get("cvssData", {})

        return {
            "version": "4.0",
            "score": cvss.get("baseScore"),
            "severity": cvss.get("baseSeverity"),
            "vector": cvss.get("vectorString"),
        }

    if metrics.get("cvssMetricV31"):
        metric = metrics["cvssMetricV31"][0]
        cvss = metric.get("cvssData", {})

        return {
            "version": "3.1",
            "score": cvss.get("baseScore"),
            "severity": cvss.get("baseSeverity"),
            "vector": cvss.get("vectorString"),
        }

    if metrics.get("cvssMetricV30"):
        metric = metrics["cvssMetricV30"][0]
        cvss = metric.get("cvssData", {})

        return {
            "version": "3.0",
            "score": cvss.get("baseScore"),
            "severity": cvss.get("baseSeverity"),
            "vector": cvss.get("vectorString"),
        }

    return None


def extract_affected_products(cve):
    """
    Extract affected CPE information from the NVD record.
    """

    affected = []

    for configuration in cve.get("configurations", []):

        for node in configuration.get("nodes", []):

            for match in node.get("cpeMatch", []):

                if not match.get("vulnerable"):
                    continue

                criteria = match.get("criteria")

                if criteria:
                    affected.append(criteria)

    return affected


def normalize_cve(cve):
    """
    Convert an NVD CVE record into a smaller structure
    suitable for use by Agent 6.
    """

    description = ""

    for item in cve.get("descriptions", []):
        if item.get("lang") == "en":
            description = item.get("value", "")
            break

    references = []

    for ref in cve.get("references", []):
        url = ref.get("url")

        if url and url not in references:
            references.append(url)

    return {
        "cve_id": cve.get("id"),
        "published": cve.get("published"),
        "last_modified": cve.get("lastModified"),
        "description": description,
        "cvss": extract_cvss(cve),
        "affected_products": extract_affected_products(cve),
        "references": references[:10],
    }


def lookup_cve(cve_id):
    """
    Look up a specific CVE ID.
    """

    response = requests.get(
        NVD_CVE_API,
        params={"cveId": cve_id},
        timeout=15
    )

    response.raise_for_status()

    data = response.json()

    if data.get("totalResults", 0) == 0:
        return {
            "status": "not_found",
            "cve_id": cve_id
        }

    cve = data["vulnerabilities"][0]["cve"]

    return {
        "status": "success",
        **normalize_cve(cve)
    }


def search_product_version(product, version):
    """
    Search NVD for CVEs affecting an exact product/version.

    This workshop implementation currently supports
    Apache HTTP Server.
    """

    if product != "Apache_HTTP_Server":
        return {
            "status": "unsupported_product",
            "product": product,
            "version": version,
            "total_results": 0,
            "results": []
        }

    cpe_name = (
        f"cpe:2.3:a:apache:http_server:"
        f"{version}:*:*:*:*:*:*:*"
    )

    response = requests.get(
        NVD_CVE_API,
        params={
            "cpeName": cpe_name,
            "resultsPerPage": 100
        },
        timeout=15
    )

    response.raise_for_status()

    data = response.json()

    results = []

    for item in data.get("vulnerabilities", []):

        cve = item.get("cve", {})

        affected_products = extract_affected_products(cve)

        # Keep only records that explicitly reference
        # the exact Apache HTTP Server CPE we searched for.
        if cpe_name not in affected_products:
            continue

        normalized = normalize_cve(cve)

        results.append(normalized)

    # Sort by CVSS score, highest first.
    results.sort(
        key=lambda item: (
            item.get("cvss") or {}
        ).get("score") or 0,
        reverse=True
    )

    return {
        "status": "success",
        "product": product,
        "version": version,
        "total_results": len(results),
        "results": results[:10]
    }


if __name__ == "__main__":

    print("=== CVE Lookup Tool Test ===")

    test_cve = "CVE-2021-41773"

    print(f"\nLooking up CVE: {test_cve}")

    result = lookup_cve(test_cve)

    print("\nCVE Result")
    print("=" * 60)

    for key, value in result.items():
        print(f"{key}: {value}")

    print("\n" + "=" * 60)
    print("Product / Version Search")
    print("=" * 60)

    product_result = search_product_version(
        "Apache_HTTP_Server",
        "2.4.49"
    )

    print(f"Product: {product_result['product']}")
    print(f"Version: {product_result['version']}")
    print(f"Total CVEs: {product_result['total_results']}")

    for finding in product_result["results"]:

        print("\nCVE:", finding["cve_id"])

        if finding["cvss"]:
            print(
                "Severity:",
                finding["cvss"]["severity"]
            )

            print(
                "Score:",
                finding["cvss"]["score"]
            )
