"""Network identifiers supported by the gateway connector layer."""

IMPLEMENTED_NETWORKS = {
    "ABHA",
    "NABIDH",
}

SCAFFOLDED_NETWORKS = {
    "NHS_SPINE",
    "MY_HEALTH_RECORD",
    "EHEALTH_EXCHANGE",
    "CANADA_HEALTH_INFOWAY",
    "NEHR",
    "KANTA",
    "DANISH_NHDN",
}

ALL_KNOWN_NETWORKS = IMPLEMENTED_NETWORKS | SCAFFOLDED_NETWORKS

