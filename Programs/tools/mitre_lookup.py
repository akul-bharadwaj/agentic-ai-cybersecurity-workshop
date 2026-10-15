import requests


ATTACK_API_URL = (
    "https://raw.githubusercontent.com/mitre-attack/"
    "attack-stix-data/master/enterprise-attack/"
    "enterprise-attack.json"
)


def lookup_technique(technique_id):

    response = requests.get(
        ATTACK_API_URL,
        timeout=20
    )

    response.raise_for_status()

    data = response.json()

    for obj in data.get("objects", []):

        if obj.get("type") != "attack-pattern":
            continue

        external_references = obj.get(
            "external_references",
            []
        )

        for reference in external_references:

            if (
                reference.get("source_name")
                == "mitre-attack"
                and reference.get("external_id")
                == technique_id
            ):

                return {
                    "status": "success",
                    "technique_id": technique_id,
                    "name": obj.get("name"),
                    "description": obj.get("description"),
                    "url": reference.get(
                        "url"
                    )
                }

    return {
        "status": "not_found",
        "technique_id": technique_id
    }


def main():

    technique_id = "T1190"

    print(
        f"Looking up MITRE ATT&CK technique: "
        f"{technique_id}"
    )

    result = lookup_technique(technique_id)

    print("\nMITRE ATT&CK Result")
    print("=" * 60)

    for key, value in result.items():
        print(f"{key}: {value}")


if __name__ == "__main__":
    main()
