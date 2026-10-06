# NDJSON writer for the PQC-SOC Readiness Scanner.
# NDJSON means one complete JSON object per line, separated by newlines.
# so an analyst in a SIEM can interpret any single event without reading a separate report.

import json
from datetime import datetime, timezone
from pathlib import Path

# Urgency-first ordering already lives in cef_writer.
from modules.cef_writer import sort_findings_by_priority

def save_ndjson_report(filename, all_findings, scan_id, data_sensitivity, data_lifetime, exposure_surface):

    # Local-time filename suffix - matches the JSON and CEF naming pattern on disk.
    local_suffix = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
    filename = f"{Path(filename).stem}_{local_suffix}.ndjson"

    output_folder = Path(__file__).parent.parent / "output"
    output_folder.mkdir(exist_ok=True)
    full_output_path = output_folder / filename

     # One UTC timestamp for the whole scan run.
    # The Z suffix tells any downstream parser "this is UTC, no timezone offset needed".
    scan_timestamp = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")

    # Urgency-first order so the most severe findings land at the top of the file.
    sorted_findings = sort_findings_by_priority(all_findings)

    # newline="\n" stops Python from quietly turning every newline into \r\n on Windows.
    # Every SIEM parser prefers plain \n line endings, and CRLF can trip the LINE_BREAKER regex.
    with open(full_output_path, "w", newline="\n") as output_file:

        for finding in sorted_findings:

            # Build a brand new dictionary for this line.
            # Scan context first - these are the fields a SIEM analyst needs to interpret the event.
            event_line = {
                "scan_id": scan_id,
                "scan_timestamp": scan_timestamp,
                "scanner_version": "0.1",
                "data_sensitivity": data_sensitivity,
                "data_lifetime": data_lifetime,
                "exposure_surface": exposure_surface,
            }

            # Then every field from the original finding, as long as it is not already set.
            # The original finding dictionary itself is never modified.
            for key, value in finding.items():
                if key not in event_line:
                    event_line[key] = value

            output_file.write(json.dumps(event_line) + "\n")

    return full_output_path