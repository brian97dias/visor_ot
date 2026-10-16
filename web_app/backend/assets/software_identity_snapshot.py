"""Technical identity snapshots used for installation provenance and corrections."""
FIELDS = ("software_type", "manufacturer", "product", "version")


def snapshot_software(software, *, source="installation"):
    return {
        **{key: getattr(software, key) for key in FIELDS},
        "_source": source,
    }
