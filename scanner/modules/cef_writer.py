from pathlib import Path
from datetime import datetime

# CEF treats backslash and the equals sign as special inside a value, so both need a backslash placed in front of them before the value goes into the line.
# Backslash has to be escaped first - otherwise the backslash placed in front of the equals sign on the next line would get caught and escaped a second time.
# Newlines are escaped too, since a real line break would cut the CEF event short.
def escape_cef_value(field_value):
    
    field_value = str(field_value)
    field_value = field_value.replace("\\", "\\\\")
    field_value = field_value.replace("=", "\\=")
    field_value = field_value.replace("\n", "\\n")
    field_value = field_value.replace("\r", "\\r")

    return field_value

# CEF severity runs on a 0 to 10 scale. The scanner's severity labels are four named words instead - this is the fixed mapping between the two.
def map_severity_to_cef(severity_label):

    severity_lookup = { "CRITICAL": 10, "HIGH": 7, "MEDIUM": 4, "LOW": 1}

    # Falls back to 0 if a label outside these four ever shows up
    return severity_lookup.get(severity_label, 0)

# Builds one full CEF line out of a single finding. Header fields first, then a space-separated list of key=value extension fields at the end.
def build_cef_event(finding):

    cef_version = "0"
    device_vendor = "PQC-SOC"
    device_product = "Readiness Scanner"
    device_version = "0.1"
    signature_id = finding.get("algorithm", "unknown")
    cef_severity = map_severity_to_cef(finding.get("severity", "LOW"))

    # The event name reads differently depending on which quantum threat this finding actually represents
    if finding.get("threat_category") == "confidentiality_harvest":
        event_name = "Quantum-vulnerable key exchange detected"
    else:
        event_name = "Quantum-vulnerable signature scheme detected"

    header = f"CEF:{cef_version}|{device_vendor}|{device_product}|{device_version}|{signature_id}|{event_name}|{cef_severity}"

    # Each extension field is key=value, with the value made CEF-safe first
    extension_fields = [
        f"target={escape_cef_value(finding.get('target', 'unknown'))}",
        f"algorithm={escape_cef_value(finding.get('algorithm', 'unknown'))}",
        f"score={escape_cef_value(finding.get('quantum_exposure_score', 0))}",
        f"threatCategory={escape_cef_value(finding.get('threat_category', 'unknown'))}",
        f"nistStandard={escape_cef_value(finding.get('nist_standard', 'unknown'))}",
        f"msg={escape_cef_value(finding.get('rationale', ''))}"
    ]

    extension = " ".join(extension_fields)

    return f"{header}|{extension}"

# Writes one CEF line per finding into a single output file.
def save_cef_report(filename, all_findings):

    timestamp = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
    filename = f"{Path(filename).stem}_{timestamp}.cef"

    # Landing in the same output folder JSON reports already use
    output_folder = Path(__file__).parent.parent/ "output"
    output_folder.mkdir(exist_ok=True)
    full_output_path = output_folder/filename

    with open(full_output_path, "w") as output_file:
        for finding in all_findings:
            cef_line = build_cef_event(finding)
            output_file.write(cef_line + "\n")

    return full_output_path

