from mitreattack.stix20 import MitreAttackData
from pprint import pprint
import requests
import json
import os


def download_enterprise_attack_data():
    """Download the latest Enterprise ATT&CK STIX data from MITRE's GitHub repository."""
    url = "https://raw.githubusercontent.com/mitre/cti/master/enterprise-attack/enterprise-attack.json"
    filename = "raw_data/enterprise-attack.json"

    print("Downloading Enterprise ATT&CK data...")
    try:
        response = requests.get(url, timeout=30)
        response.raise_for_status()

        with open(filename, "w", encoding="utf-8") as f:
            f.write(response.text)

        print(f"✓ Successfully downloaded {filename}")
        return filename
    except requests.exceptions.RequestException as e:
        print(f"✗ Error downloading data: {e}")
        return None


def main():
    if not os.path.exists("raw_data"):
        os.makedirs("raw_data")

    if not os.path.exists("raw_data/techniques.json"):
        download_enterprise_attack_data()

    # Initialize the data
    mitre_attack_data = MitreAttackData("raw_data/enterprise-attack.json")

    # Get all techniques
    techniques = mitre_attack_data.get_techniques(remove_revoked_deprecated=True)

    # Extract important fields for each technique
    technique_data = []

    for technique in techniques:
        # Get the ATT&CK ID from external references
        attack_id = None
        if "external_references" in technique:
            for ref in technique["external_references"]:
                if ref.get("source_name") == "mitre-attack":
                    attack_id = ref.get("external_id")
                    break

        # Extract important fields
        tech_info = {
            "attack_id": attack_id,
            "name": technique.get("name"),
            "description": technique.get("description"),
            "is_subtechnique": technique.get("x_mitre_is_subtechnique", False),
            "platforms": technique.get("x_mitre_platforms", []),
            "tactics": [
                phase.phase_name for phase in technique.get("kill_chain_phases", [])
            ],
            "detection": technique.get("x_mitre_detection", ""),
            "mitigations": [],
        }

        # get mitigations
        mitigations = mitre_attack_data.get_mitigations_mitigating_technique(
            technique.id
        )

        for mitigation in mitigations:
            tech_info["mitigations"].append(
                f"{mitigation['object'].name}: {mitigation['object'].description}"
            )

        technique_data.append(tech_info)

    print(f"Extracted {len(technique_data)} techniques")

    with open("raw_data/techniques.json", "w", encoding="utf-8") as f:
        json.dump(technique_data, f, indent=4, ensure_ascii=False)

    print("Techniques saved to raw_data/techniques.json")


if __name__ == "__main__":
    main()
