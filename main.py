
from modules.recon.recon import scan_target
from modules.security_config.security_config import check_security_config
from modules.vulnerability_assessment.vulnerability_assessment import vulnerability_assessment
from modules.reporting.reporting import generate_report


def main():

    print("=" * 60)
    print("WEB APPLICATION PENETRATION TESTING TOOLKIT")
    print("=" * 60)

    print("\n1. Reconnaissance")
    print("2. Security Configuration Analysis")
    print("3. Vulnerability Assessment")
    print("4. Full Security Assessment & Reporting")
    print("5. Exit")

    choice = input(
        "\nEnter your choice: "
    ).strip()

    # --------------------------------------------------
    # Reconnaissance
    # --------------------------------------------------

    if choice == "1":

        print("\n--- Reconnaissance Module ---")

        target_url = input(
            "Enter target URL: "
        ).strip()

        if target_url:

            scan_target(target_url)

        else:

            print(
                "Please enter a valid URL."
            )

    # --------------------------------------------------
    # Security Configuration
    # --------------------------------------------------

    elif choice == "2":

        print(
            "\n--- Security Configuration Analysis ---"
        )

        target_url = input(
            "Enter target URL: "
        ).strip()

        if target_url:

            check_security_config(target_url)

        else:

            print(
                "Please enter a valid URL."
            )

    # --------------------------------------------------
    # Vulnerability Assessment
    # --------------------------------------------------

    elif choice == "3":

        print(
            "\n--- Vulnerability Assessment ---"
        )

        target_url = input(
            "Enter target URL: "
        ).strip()

        if target_url:

            vulnerability_assessment(target_url)

        else:

            print(
                "Please enter a valid URL."
            )

    # --------------------------------------------------
    # Full Assessment
    # --------------------------------------------------

    elif choice == "4":

        print(
            "\n--- FULL SECURITY ASSESSMENT ---"
        )

        target_url = input(
            "Enter target URL: "
        ).strip()

        if not target_url:

            print(
                "Please enter a valid URL."
            )

            return

        print(
            "\n[1/3] Running Reconnaissance..."
        )

        recon_results = scan_target(
            target_url
        )

        if recon_results is None:

            print(
                "\n[!] Reconnaissance failed."
            )

            return

        print(
            "\n[2/3] Running Security Configuration Analysis..."
        )

        security_results = check_security_config(
            target_url
        )

        if security_results is None:

            print(
                "\n[!] Security Configuration Analysis failed."
            )

            return

        print(
            "\n[3/3] Running Vulnerability Assessment..."
        )

        vulnerability_results = vulnerability_assessment(
            target_url
        )

        if vulnerability_results is None:

            print(
                "\n[!] Vulnerability Assessment failed."
            )

            return

        print(
            "\n[+] Generating Security Report..."
        )

        report_data = {
            "Reconnaissance": recon_results,
            "Security Configuration": security_results,
            "Vulnerability Assessment": vulnerability_results
        }

        generate_report(
            target_url,
            report_data
        )

    # --------------------------------------------------
    # Exit
    # --------------------------------------------------

    elif choice == "5":

        print(
            "\nExiting Toolkit..."
        )

    else:

        print(
            "\nInvalid choice."
        )


if __name__ == "__main__":

    main()

