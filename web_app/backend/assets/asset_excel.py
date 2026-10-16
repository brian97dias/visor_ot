"""Export the existing asset inventory to a two-sheet XLSX workbook.

No external spreadsheet dependencies: emits a small, standards-compliant
Office Open XML workbook using the Python standard library. Read-only: the
export neither creates/changes Asset rows nor invents Hardware identifiers.
"""
from decimal import Decimal
from io import BytesIO
from zipfile import ZIP_DEFLATED, ZipFile
from xml.etree import ElementTree as ET

from .models import Asset

HARDWARE_COLUMNS = (
    ("id_visor_ot", "id"),
    ("nombre_activo", "name"),
    ("descripcion", "description"),
    ("fabricante", "manufacturer"),
    ("modelo", "model"),
    ("rol", "role"),
    ("numero_serie", "serial_number"),
    ("ubicacion_fisica", "physical_location"),
    ("criticidad", "criticality"),
    ("impacto_indisponibilidad", "impact"),
    ("costo_reposicion", "replacement_cost"),
    ("moneda", "replacement_currency"),
    ("estado_inventario", "inventory_status"),
)
SOFTWARE_COLUMNS = (
    ("id_visor_ot", "id"),
    ("nombre_activo", "name"),
    ("descripcion", "description"),
    ("tipo_software", "software_type"),
    ("fabricante", "manufacturer"),
    ("producto", "product"),
    ("version", "version"),
    ("criticidad", "criticality"),
    ("impacto_indisponibilidad", "impact"),
    ("costo_reposicion", "replacement_cost"),
    ("moneda", "replacement_currency"),
    ("estado_inventario", "inventory_status"),
)

MAIN_NS = "http://schemas.openxmlformats.org/spreadsheetml/2006/main"
REL_NS = "http://schemas.openxmlformats.org/officeDocument/2006/relationships"
PKG_REL_NS = "http://schemas.openxmlformats.org/package/2006/relationships"
CONTENT_NS = "http://schemas.openxmlformats.org/package/2006/content-types"
ET.register_namespace("", MAIN_NS)


def column_letter(index):
    """Zero-based position to Excel column reference."""
    result = ""
    while index >= 0:
        result = chr(65 + index % 26) + result
        index = index // 26 - 1
    return result


def asset_values(asset):
    base = {
        "id": asset.pk,
        "name": asset.name,
        "description": asset.description,
        "criticality": asset.criticality,
        "impact": asset.impact,
        "replacement_cost": asset.replacement_cost,
        "replacement_currency": asset.replacement_currency,
        "inventory_status": asset.inventory_status,
    }
    if asset.asset_type == Asset.AssetType.HARDWARE:
        hardware = asset.hardware
        fields = {
            "manufacturer": hardware.manufacturer,
            "model": hardware.model,
            "role": hardware.role,
            "serial_number": hardware.serial_number,
            "physical_location": hardware.physical_location,
        }
        columns = HARDWARE_COLUMNS
    else:
        software = asset.software
        fields = {
            "software_type": software.software_type,
            "manufacturer": software.manufacturer,
            "product": software.product,
            "version": software.version,
        }
        columns = SOFTWARE_COLUMNS
    fields.update(base)
    return [fields[key] for _, key in columns]


def _sheet_xml(columns, rows):
    tag = lambda local: f"{{{MAIN_NS}}}{local}"
    worksheet = ET.Element(tag("worksheet"))
    dimension_end = column_letter(len(columns) - 1) + str(max(1, len(rows) + 1))
    ET.SubElement(worksheet, tag("dimension"), ref=f"A1:{dimension_end}")
    views = ET.SubElement(worksheet, tag("sheetViews"))
    view = ET.SubElement(views, tag("sheetView"), workbookViewId="0")
    ET.SubElement(view, tag("pane"), ySplit="1", topLeftCell="A2",
                  activePane="bottomLeft", state="frozen")
    widths = ET.SubElement(worksheet, tag("cols"))
    for i, (header, _) in enumerate(columns, 1):
        width = 40 if header in ("descripcion", "impacto_indisponibilidad") else max(16, min(30, len(header) + 5))
        ET.SubElement(widths, tag("col"), min=str(i), max=str(i),
                      width=str(width), customWidth="1")
    data = ET.SubElement(worksheet, tag("sheetData"))

    def add_cell(row, col_index, value, *, header=False, currency=False):
        if value is None or value == "":
            return
        address = column_letter(col_index) + str(row.attrib["r"])
        is_number = isinstance(value, (int, float, Decimal)) and not isinstance(value, bool)
        attrs = {"r": address}
        if header:
            attrs["s"] = "1"
        elif currency and is_number:
            attrs["s"] = "2"
        if is_number:
            cell = ET.SubElement(row, tag("c"), attrs)
            ET.SubElement(cell, tag("v")).text = str(value)
        else:
            attrs["t"] = "inlineStr"
            cell = ET.SubElement(row, tag("c"), attrs)
            inline = ET.SubElement(cell, tag("is"))
            text = ET.SubElement(inline, tag("t"))
            text.text = str(value)
            if str(value).strip() != str(value):
                text.set("{http://www.w3.org/XML/1998/namespace}space", "preserve")

    header_row = ET.SubElement(data, tag("row"), r="1", ht="27", customHeight="1")
    for i, (header, _) in enumerate(columns):
        add_cell(header_row, i, header, header=True)
    for n, values in enumerate(rows, 2):
        row = ET.SubElement(data, tag("row"), r=str(n))
        for i, value in enumerate(values):
            add_cell(row, i, value, currency=columns[i][0] == "costo_reposicion")

    ET.SubElement(worksheet, tag("autoFilter"), ref=f"A1:{dimension_end}")
    return ET.tostring(worksheet, encoding="utf-8", xml_declaration=True)


def _package():
    """Static OOXML workbook metadata for exactly two worksheets."""
    workbook = (
        '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
        f'<workbook xmlns="{MAIN_NS}" xmlns:r="{REL_NS}">'
        '<sheets><sheet name="Hardware" sheetId="1" r:id="rId1"/>'
        '<sheet name="Software" sheetId="2" r:id="rId2"/></sheets></workbook>'
    )
    rels = (
        '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
        f'<Relationships xmlns="{PKG_REL_NS}">'
        f'<Relationship Id="rId1" Type="{REL_NS}/worksheet" Target="worksheets/sheet1.xml"/>'
        f'<Relationship Id="rId2" Type="{REL_NS}/worksheet" Target="worksheets/sheet2.xml"/>'
        f'<Relationship Id="rId3" Type="{REL_NS}/styles" Target="styles.xml"/>'
        '</Relationships>'
    )
    package_rels = (
        '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
        f'<Relationships xmlns="{PKG_REL_NS}">'
        f'<Relationship Id="rId1" Type="{REL_NS}/officeDocument" Target="xl/workbook.xml"/>'
        '</Relationships>'
    )
    contents = (
        '<?xml version="1.0" encoding="UTF-8"?>'
        f'<Types xmlns="{CONTENT_NS}">'
        '<Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/>'
        '<Default Extension="xml" ContentType="application/xml"/>'
        '<Override PartName="/xl/workbook.xml" ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet.main+xml"/>'
        '<Override PartName="/xl/styles.xml" ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.styles+xml"/>'
        '<Override PartName="/xl/worksheets/sheet1.xml" ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.worksheet+xml"/>'
        '<Override PartName="/xl/worksheets/sheet2.xml" ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.worksheet+xml"/>'
        '</Types>'
    )
    styles = (
        '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
        f'<styleSheet xmlns="{MAIN_NS}">'
        '<fonts count="2"><font><sz val="11"/><name val="Calibri"/></font>'
        '<font><b/><sz val="11"/><color rgb="FFFFFFFF"/><name val="Calibri"/></font></fonts>'
        '<fills count="3"><fill><patternFill patternType="none"/></fill>'
        '<fill><patternFill patternType="gray125"/></fill>'
        '<fill><patternFill patternType="solid"><fgColor rgb="FF164E63"/><bgColor indexed="64"/></patternFill></fill></fills>'
        '<borders count="1"><border><left/><right/><top/><bottom/><diagonal/></border></borders>'
        '<cellStyleXfs count="1"><xf numFmtId="0" fontId="0" fillId="0" borderId="0"/></cellStyleXfs>'
        '<cellXfs count="3"><xf numFmtId="0" fontId="0" fillId="0" borderId="0" xfId="0"/>'
        '<xf numFmtId="0" fontId="1" fillId="2" borderId="0" xfId="0" applyFill="1" applyFont="1"/>'
        '<xf numFmtId="2" fontId="0" fillId="0" borderId="0" xfId="0" applyNumberFormat="1"/></cellXfs>'
        '<cellStyles count="1"><cellStyle name="Normal" xfId="0" builtinId="0"/></cellStyles>'
        '</styleSheet>'
    )
    return {
        "[Content_Types].xml": contents,
        "_rels/.rels": package_rels,
        "xl/workbook.xml": workbook,
        "xl/_rels/workbook.xml.rels": rels,
        "xl/styles.xml": styles,
    }


def export_inventory_workbook(assets):
    """Return XLSX bytes containing all supplied assets (no database writes)."""
    hardware_rows, software_rows = [], []
    for asset in assets:
        row = asset_values(asset)
        if asset.asset_type == Asset.AssetType.HARDWARE:
            hardware_rows.append(row)
        elif asset.asset_type == Asset.AssetType.SOFTWARE:
            software_rows.append(row)
    data = BytesIO()
    with ZipFile(data, mode="w", compression=ZIP_DEFLATED) as archive:
        for path, contents in _package().items():
            archive.writestr(path, contents)
        archive.writestr("xl/worksheets/sheet1.xml", _sheet_xml(HARDWARE_COLUMNS, hardware_rows))
        archive.writestr("xl/worksheets/sheet2.xml", _sheet_xml(SOFTWARE_COLUMNS, software_rows))
    return data.getvalue()
