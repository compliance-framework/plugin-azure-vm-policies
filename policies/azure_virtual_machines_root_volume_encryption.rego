package compliance_framework.template.azure_virtual_machines._deny_unencrypted_root_volume

controls := [
    # SAMA Cyber Security Framework v1.0
    # https://rulebook.sama.gov.sa/en/cyber-security-framework-2
    # Class: SAMA_CSF_1.0
    #
    # 3.3: Cyber Security Operations and Technology
    {
        "class": "SAMA_CSF_1.0",
        "control-id": "3.3.8", # Infrastructure Security
        "statement-ids": [
            "4",
            "5",
            "6.a",
            "6.c",
            "6.d",
        ],
    },
    {
        "class": "SAMA_CSF_1.0",
        "control-id": "3.3.9", # Cryptography
        "statement-ids": [
            "2",
            "3",
            "4.a",
            "4.b",
            "4.c",
        ],
    },
    # SAMA Cyber Resilience Fundamental Requirements v1.0
    # https://rulebook.sama.gov.sa/en/cyber-security-operations-and-technology
    # Class: SAMA_CRFR_1.0
    #
    # 3.2: Cyber Security Operations and Technology
    {
        "class": "SAMA_CRFR_1.0",
        "control-id": "3.2.4",
    },
    {
        "class": "SAMA_CRFR_1.0",
        "control-id": "3.2.8",
    },
]

violation[{
  "title": "Root volume is not encrypted",
  "description": sprintf("VM '%v' has an unencrypted root volume.", [input.Name]),
  "remarks": "Ensure the root volume of the Azure VM is encrypted."
}] if {
  input.Properties.diskDetails.azureDiskEncryption == false
}
