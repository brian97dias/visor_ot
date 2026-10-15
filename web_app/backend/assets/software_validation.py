"""Pure software identification rules, independent of the database."""


def compact_spaces(value):
    return " ".join((value or "").split())


def normalize_software_fields(manufacturer, product, version):
    return tuple(compact_spaces(item) for item in (manufacturer, product, version))


def software_identity(manufacturer, product, version):
    """A known manufacturer+product+version identity, otherwise None.

    An incomplete software record must NEVER be auto-merged based on name.
    """
    manufacturer, product, version = normalize_software_fields(
        manufacturer, product, version
    )
    if not manufacturer or not product or not version:
        return None
    return manufacturer.casefold(), product.casefold(), version.casefold()
