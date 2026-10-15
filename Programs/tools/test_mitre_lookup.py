from mitre_lookup import lookup_technique


def test_known_technique():

    result = lookup_technique("T1190")

    assert result["status"] == "success"
    assert result["technique_id"] == "T1190"
    assert result["name"] == "Exploit Public-Facing Application"
    assert result["description"]


def test_unknown_technique():

    result = lookup_technique("T9999")

    assert result["status"] == "not_found"
    assert result["technique_id"] == "T9999"


if __name__ == "__main__":

    test_known_technique()
    test_unknown_technique()

    print("All MITRE lookup tests passed.")
