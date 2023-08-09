# gh0stapp3num
Thick Client Enumeration Tool 

## Introduction

This tool is designed to perform comprehensive security assessments on thick client applications. It includes various scanning techniques to identify vulnerabilities, potential sensitive data storage, third-party dependencies, and more.

## Usage

1. Install the required Python packages:
	pip install psutil

2. Run the `gh0stapp3num.py` script:

	python gh0stapp3num.py

3. The tool will present a menu of scan options. Choose the desired scan type by entering the corresponding number.

4. For each scan type, you can specify the target application or directory path.

5. You can enable verbose mode to see detailed output during the scan.

6. After completing the scans, the tool will generate comprehensive reports for each scan type conducted.

## Updates

- Added support for running scans against .exe files and capturing their outputs.
- Improved process management and error handling to prevent hanging and crashes.
- Enhanced verbose mode to display real-time scan progress.
- Added the ability to perform a "Run All Scans" option, which conducts all available scans in sequence.
- Created comprehensive and detailed summary reports for each scan conducted.
- Implemented a more robust approach to detect vulnerabilities, sensitive strings, dependencies, and tiers.
- Added options to scan specific DLL vulnerabilities, sensitive strings, third-party dependencies, and identify thick client tiers.

## Disclaimer

This tool is provided for educational and informational purposes only. Use it responsibly and with proper authorization. The authors are not responsible for any misuse or damage caused by this tool.
