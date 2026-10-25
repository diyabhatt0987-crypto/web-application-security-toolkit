import os
import json
import shutil
from datetime import datetime


# Project root
PROJECT_ROOT = os.path.dirname(
    os.path.dirname(
        os.path.dirname(os.path.abspath(__file__)) 
    )
)

REPORTS_DIR = os.path.join(PROJECT_ROOT, "reports")
HISTORY_FILE = os.path.join(PROJECT_ROOT, "scan_history.json")
LATEST_REPORT = os.path.join(PROJECT_ROOT, "security_report.txt")


def analyze_findings(data):
    counts = {
        "PASS": 0,
        "WARNING": 0,
        "INFO": 0,
        "MISSING": 0
    }

    def walk(value):
        if isinstance(value, dict):
            for item in value.values():
                walk(item)

        elif isinstance(value, list):
            for item in value:
                walk(item)

        elif isinstance(value, str):
            text = value.strip().upper()

            if text in counts:
                counts[text] += 1

            else:
                for status in counts:
                    if text.startswith(status + " "):
                        counts[status] += 1
                        break

    walk(data)

    return counts


def calculate_score(counts):
    total = (
        counts["PASS"]
        + counts["WARNING"]
        + counts["MISSING"]
    )

    if total == 0:
        return 100

    score = (
        counts["PASS"] * 100
        + counts["MISSING"] * 50
        + counts["WARNING"] * 10
    ) / total

    return max(0, min(100, round(score)))


def format_value(value, indent=0):
    prefix = " " * indent

    if isinstance(value, dict):
        lines = []

        for key, item in value.items():

            if isinstance(item, (dict, list)):
                lines.append(f"{prefix}{key}:")
                lines.append(format_value(item, indent + 4))

            else:
                lines.append(f"{prefix}{key}: {item}")

        return "\n".join(lines)

    if isinstance(value, list):

        if not value:
            return f"{prefix}None"

        lines = []

        for item in value:
            lines.append(
                f"{prefix}- {format_value(item, indent + 2).lstrip()}"
            )

        return "\n".join(lines)

    return f"{prefix}{value}"


def write_report(
    file_path,
    target_url,
    data,
    counts,
    score,
    timestamp
):

    with open(file_path, "w", encoding="utf-8") as file:

        file.write("=" * 70 + "\n")
        file.write("WEB APPLICATION SECURITY ASSESSMENT REPORT\n")
        file.write("=" * 70 + "\n\n")

        file.write(f"Target: {target_url}\n")
        file.write(f"Date/Time: {timestamp}\n")
        file.write(f"Security Posture Score: {score}%\n\n")

        file.write("SUMMARY\n")
        file.write("-" * 70 + "\n")

        file.write(f"PASS: {counts['PASS']}\n")
        file.write(f"WARNING: {counts['WARNING']}\n")
        file.write(f"INFO: {counts['INFO']}\n")
        file.write(f"MISSING: {counts['MISSING']}\n\n")

        file.write("STATUS MEANINGS\n")
        file.write("-" * 70 + "\n")

        file.write("PASS = Check satisfied.\n")
        file.write(
            "WARNING = Potentially concerning configuration; review it.\n"
        )
        file.write(
            "INFO = Informational finding; not automatically a vulnerability.\n"
        )
        file.write(
            "MISSING = Control/header was not detected; review it.\n\n"
        )

        for section, results in data.items():

            file.write("=" * 70 + "\n")
            file.write(section.upper() + "\n")
            file.write("=" * 70 + "\n")

            file.write(format_value(results))
            file.write("\n\n")


def load_history():

    if not os.path.exists(HISTORY_FILE):
        return []

    try:

        with open(
            HISTORY_FILE,
            "r",
            encoding="utf-8"
        ) as file:

            data = json.load(file)

        if isinstance(data, list):
            return data

        return []

    except (json.JSONDecodeError, OSError):

        return []


def save_history(history):

    with open(
        HISTORY_FILE,
        "w",
        encoding="utf-8"
    ) as file:

        json.dump(
            history,
            file,
            indent=4
        )


def generate_report(target_url, data):

    os.makedirs(
        REPORTS_DIR,
        exist_ok=True
    )

    timestamp = datetime.now().strftime(
        "%Y-%m-%d %H:%M:%S"
    )

    filename_stamp = datetime.now().strftime(
        "%Y%m%d_%H%M%S"
    )

    report_path = os.path.join(
        REPORTS_DIR,
        f"security_report_{filename_stamp}.txt"
    )

    counts = analyze_findings(data)

    score = calculate_score(counts)

    write_report(
        report_path,
        target_url,
        data,
        counts,
        score,
        timestamp
    )

    # Copy latest report
    shutil.copyfile(
        report_path,
        LATEST_REPORT
    )

    # Save scan history
    history = load_history()

    history.insert(
        0,
        {
            "target": target_url,
            "timestamp": timestamp,
            "score": score,
            "PASS": counts["PASS"],
            "WARNING": counts["WARNING"],
            "INFO": counts["INFO"],
            "MISSING": counts["MISSING"],
            "report_file": report_path
        }
    )

    save_history(history)

    print("\n" + "=" * 50)
    print("SECURITY ASSESSMENT COMPLETE")
    print("=" * 50)

    print(f"\nTarget: {target_url}")

    print(f"PASS     : {counts['PASS']}")
    print(f"WARNING  : {counts['WARNING']}")
    print(f"INFO     : {counts['INFO']}")
    print(f"MISSING  : {counts['MISSING']}")

    print(f"\nSecurity posture score: {score}%")

    print("\nSecurity report generated successfully.")
    print(f"File: {report_path}")

    return report_path


def load_scan_history():

    return load_history()


def get_report_path(path):

    return path


if __name__ == "__main__":

    print("Reporting module loaded successfully.")
    print("Run the full assessment from main.py or gui/app.py.")