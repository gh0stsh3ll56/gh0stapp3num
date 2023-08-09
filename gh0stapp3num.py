import os
import platform
import psutil
import ctypes
import re
import hashlib
import time
import subprocess
import pkg_resources

def detect_dll_vulnerabilities(path, verbose=False):
    if not os.path.exists(path):
        return "Path not found."

    if os.path.isfile(path):
        if platform.system() == "Windows":
            return detect_windows_dll_vulnerabilities(path, verbose)
        elif platform.system() == "Linux":
            return detect_linux_dll_vulnerabilities(path, verbose)
        else:
            return "Unsupported platform."
    elif os.path.isdir(path):
        return detect_dll_hijacking_vulnerabilities(path, verbose)
    else:
        return "Invalid path."

def is_path_writable(path):
    try:
        test_file = os.path.join(path, 'test.txt')
        with open(test_file, 'w') as f:
            f.write('test')
        os.remove(test_file)
        return True
    except:
        return False

def verify_digital_signature(file_path):
    try:
        cert = ctypes.windll.Crypt32.CertFindCertificateInStore(
            None,
            ctypes.c_wchar_p(7),  # CERT_SYSTEM_STORE_CURRENT_USER
            0,
            ctypes.c_wchar_p(2),  # CERT_FIND_ANY
            ctypes.byref(ctypes.c_byte_p(0)),
            None
        )
        if cert:
            dw_encoding = ctypes.c_ulong(0)
            dw_data = ctypes.c_ulong(0)
            is_valid = ctypes.windll.Crypt32.CryptVerifyCertificateSignature(
                None,
                0,
                cert,
                ctypes.c_wchar_p(file_path),
                0,
                ctypes.byref(dw_encoding),
                ctypes.byref(dw_data)
            )
            return is_valid
    except Exception as e:
        pass
    return False

def detect_windows_dll_vulnerabilities(application_path, verbose=False):
    legitimate_paths = [
        r"C:\Windows\System32\kernel32.dll",
        r"C:\Windows\System32\user32.dll",
        # Add more legitimate DLL paths here
    ]

    suspicious_dlls = []

    try:
        process = subprocess.Popen(application_path)
        process.wait()

        app_dir = os.path.dirname(application_path)
        app_dlls = [dll for dll in os.listdir(app_dir) if dll.lower().endswith(".dll")]
        for dll in app_dlls:
            dll_path = os.path.join(app_dir, dll)
            if not any(legit_path.lower() in dll_path.lower() for legit_path in legitimate_paths):
                if not is_path_writable(app_dir) and not verify_digital_signature(dll_path):
                    suspicious_dlls.append((dll_path, "Potential DLL hijacking"))

                if verbose:
                    print(f"Suspicious DLL in app directory: {dll_path}")

        for module in process.memory_maps():
            dll_path = module.path
            if dll_path.lower().endswith(".dll"):
                if not any(legit_path.lower() in dll_path.lower() for legit_path in legitimate_paths):
                    if not is_path_writable(os.path.dirname(dll_path)) and not verify_digital_signature(dll_path):
                        suspicious_dlls.append((dll_path, "Potential DLL hijacking"))

                    if verbose:
                        print(f"Suspicious DLL in loaded module: {dll_path}")

    except Exception as e:
        print(f"Error during DLL vulnerability scan: {e}")

    finally:
        try:
            process.terminate()
        except psutil.NoSuchProcess:
            pass

    return suspicious_dlls

def detect_linux_dll_vulnerabilities(application_path, verbose=False):
    legitimate_paths = [
        "/lib/x86_64-linux-gnu/libc.so.6",
        "/lib/x86_64-linux-gnu/libm.so.6",
        # Add more legitimate shared library paths here
    ]

    suspicious_libraries = []

    process = psutil.Popen(application_path)
    process.wait()

    # Search for library vulnerabilities in the application directory
    app_dir = os.path.dirname(application_path)
    app_libs = [lib for lib in os.listdir(app_dir) if lib.lower().endswith(".so")]
    for lib in app_libs:
        lib_path = os.path.join(app_dir, lib)
        if not any(legit_path.lower() in lib_path.lower() for legit_path in legitimate_paths):
            suspicious_libraries.append(lib_path)
            if verbose:
                print(f"Suspicious library in app directory: {lib_path}")

    # Search for library vulnerabilities in loaded modules
    for module in process.memory_maps():
        lib_path = module.path
        if lib_path.lower().endswith(".so"):
            if not any(legit_path.lower() in lib_path.lower() for legit_path in legitimate_paths):
                suspicious_libraries.append(lib_path)
                if verbose:
                    print(f"Suspicious library in loaded module: {lib_path}")

    process.terminate()

    return suspicious_libraries

def detect_dll_hijacking_vulnerabilities(directory_path, verbose=False):
    suspicious_dlls = []

    for root, _, files in os.walk(directory_path):
        for file_name in files:
            file_path = os.path.join(root, file_name)
            if file_name.lower().endswith(".dll") and not verify_digital_signature(file_path):
                if not is_path_writable(os.path.dirname(file_path)):
                    suspicious_dlls.append((file_path, "Potential DLL hijacking"))

                if verbose:
                    print(f"Suspicious DLL in directory: {file_path}")

    return suspicious_dlls




def determine_local_data_storage(target_path, verbose=False):
    local_storage_info = []

    if not os.path.exists(target_path):
        return "Path not found."

    if os.path.isfile(target_path):
        if platform.system() == "Windows":
            local_storage_info = determine_windows_local_data_storage(target_path, verbose)
        elif platform.system() == "Linux":
            local_storage_info = determine_linux_local_data_storage(target_path, verbose)
    elif os.path.isdir(target_path):
        local_storage_info = determine_local_data_storage_in_directory(target_path, verbose)
    else:
        return "Unsupported path."

    return local_storage_info

def determine_windows_local_data_storage(application_path, verbose=False):
    local_storage_info = []

    process = psutil.Popen(application_path)
    process.wait()

    app_dir = os.path.dirname(application_path)

    # Search for files in the application directory
    for root, _, files in os.walk(app_dir):
        for file_name in files:
            file_path = os.path.join(root, file_name)
            local_storage_info.append(("File", file_path))

    # Search for databases (assuming SQLite)
    for root, _, files in os.walk(app_dir):
        for file_name in files:
            if file_name.lower().endswith(".db") or file_name.lower().endswith(".sqlite"):
                db_path = os.path.join(root, file_name)
                local_storage_info.append(("Database", db_path))

    process.terminate()

    return local_storage_info

def determine_linux_local_data_storage(application_path, verbose=False):
    local_storage_info = []

    process = psutil.Popen(application_path)
    process.wait()

    app_dir = os.path.dirname(application_path)

    # Search for files in the application directory
    for root, _, files in os.walk(app_dir):
        for file_name in files:
            file_path = os.path.join(root, file_name)
            local_storage_info.append(("File", file_path))

    # Search for databases (assuming SQLite)
    for root, _, files in os.walk(app_dir):
        for file_name in files:
            if file_name.lower().endswith(".db") or file_name.lower().endswith(".sqlite"):
                db_path = os.path.join(root, file_name)
                local_storage_info.append(("Database", db_path))

    process.terminate()

    return local_storage_info

def determine_local_data_storage_in_directory(directory_path, verbose=False):
    local_storage_info = []

    for root, _, files in os.walk(directory_path):
        for file_name in files:
            file_path = os.path.join(root, file_name)
            local_storage_info.append(("File", file_path))

    return local_storage_info


def determine_dependencies(target_path, verbose=False):
    dependencies_info = []

    if not os.path.exists(target_path):
        return "Path not found."

    if os.path.isfile(target_path):
        if platform.system() == "Windows":
            dependencies_info = determine_windows_dependencies(target_path, verbose)
        elif platform.system() == "Linux":
            dependencies_info = determine_linux_dependencies(target_path, verbose)
    elif os.path.isdir(target_path):
        dependencies_info = determine_dependencies_in_directory(target_path, verbose)
    else:
        return "Unsupported path."

    return dependencies_info

def determine_windows_dependencies(application_path, verbose=False):
    dependencies_info = []

    try:
        process = subprocess.Popen(application_path)
        process.wait()

        app_dir = os.path.dirname(application_path)

        for root, _, files in os.walk(app_dir):
            for file_name in files:
                file_path = os.path.join(root, file_name)
                if file_name.lower().endswith((".dll", ".ocx")):
                    dependencies_info.append(("Dependency", file_path))
    except Exception as e:
        print(f"Error during Windows dependencies scan: {e}")

    finally:
        try:
            process.terminate()
        except psutil.NoSuchProcess:
            pass

    return dependencies_info

def determine_linux_dependencies(application_path, verbose=False):
    dependencies_info = []

    process = psutil.Popen(application_path)
    process.wait()

    app_dir = os.path.dirname(application_path)

    # Search for shared libraries and third-party components in the application directory
    for root, _, files in os.walk(app_dir):
        for file_name in files:
            file_path = os.path.join(root, file_name)
            if file_name.lower().endswith(".so"):
                dependencies_info.append(("Dependency", file_path))

    process.terminate()

    return dependencies_info

def determine_dependencies_in_directory(directory_path, verbose=False):
    dependencies_info = []

    for root, _, files in os.walk(directory_path):
        for file_name in files:
            file_path = os.path.join(root, file_name)
            if file_name.lower().endswith((".dll", ".ocx", ".so")):
                dependencies_info.append(("Dependency", file_path))

    return dependencies_info


def identify_vulnerable_strings(directory_path):
    sensitive_patterns = [
        r"\b(?:password|pass|secret|token|api_key)\b",
        r"\b(?:private_key|access_key|confidential)\b",
        r"\b(?:admin|username|login|credential)\b",
        r"\b(?:api|database)\b",
        r"\b(?:port|ip_address|hostname)\b",
        r"\b(?:auth_token|session_token)\b",
        r"\b(?:api_secret|api_token|api_key)\b",
        r"\b(?:encryption_key|encryption_password)\b",
        r"\b(?:jwt|json_web_token)\b"
        # Add more sensitive patterns as needed
    ]

    vulnerable_strings = []

    for root, _, files in os.walk(directory_path):
        for file_name in files:
            file_path = os.path.join(root, file_name)
            try:
                with open(file_path, "r", encoding="utf-8", errors="ignore") as file:
                    lines = file.readlines()
                    for line_number, line in enumerate(lines, start=1):
                        for pattern in sensitive_patterns:
                            matches = re.finditer(pattern, line, re.IGNORECASE)
                            for match in matches:
                                vulnerable_strings.append((file_path, line_number, line.strip()))
            except Exception as e:
                pass
    
    return vulnerable_strings

def identify_tier_type(target_application):
    tier_type = "unknown"
    tier_reason = "Unknown"
    keyword = ""

    try:
        with open(target_application, "r", errors="replace") as f:
            application_content = f.read()

        if "database" in application_content.lower():
            tier_type = "Two-Tier (Database)"
            keyword = "database"
        elif "app_server" in application_content.lower() and "db_server" in application_content.lower():
            tier_type = "Three-Tier (Separate App and DB Servers)"
            keyword = "app_server and db_server"
        elif any(keyword in application_content.lower() for keyword in ["web", "http", "url"]):
            tier_type = "Three-Tier (Web Server)"
            keyword = "web, http, or url"
        elif any(keyword in application_content.lower() for keyword in ["app", "application"]):
            tier_type = "Three-Tier (Application Server)"
            keyword = "app or application"
            
        if keyword:
            tier_reason = f"The application content contains keywords related to: {keyword}"
    except PermissionError:
        print(f"Error: Permission denied. Make sure you have read access to '{target_application}'.")
    except FileNotFoundError:
        print(f"Error: The file '{target_application}' does not exist.")

    return tier_type, tier_reason


def generate_dependencies_report(dependencies_info):
    report = "Dependencies and Third-Party Components:\n\n"
    if dependencies_info:
        for dependency_type, dependency_path in dependencies_info:
            report += f"- {dependency_type}: {dependency_path}\n"
    else:
        report += "No dependencies found.\n"
    report += "\n"
    return report


def generate_tier_report(tier_type, tier_reason):
    report = f"Thick Client Tier Analysis Report:\n\n"
    report += f"Tier Type: {tier_type}\n"
    report += f"Reason for Tier Type:\n{tier_reason}\n\n"
    return report

def generate_report(scan_results, scan_type, dependencies_info=None):
    report = "\nComprehensive Scanning Report:\n\n"
    report += f"Scan Type: {scan_type}\n\n"

    if scan_type == "DLL Vulnerability Scan":
        if scan_results:
            report += "DLL Vulnerabilities:\n"
            for vulnerability in scan_results:
                report += f"- {vulnerability}\n"
            report += "\n"
        else:
            report += "No DLL vulnerabilities found.\n\n"
    elif scan_type == "Sensitive String Scan":
        if scan_results:
            report += "Sensitive Strings:\n"
            for file_path, line_number, line, context_lines in scan_results:
                report += f"- File: {file_path}, Line: {line_number}, Content: {line}\n"
                report += "  Context:\n"
                for ctx_line in context_lines:
                    report += f"    {ctx_line.strip()}\n"
            report += "\n"
        else:
            report += "No sensitive strings found.\n\n"
    elif scan_type == "Thick Client Tier and Database/Server Scan":
        report += f"Thick Client Tier Type: {scan_results['Tier Type']}\n"
        report += f"Database/Server Type: {scan_results['Database/Server Type']}\n\n"

    if dependencies_info is not None:
        report += generate_dependencies_report(dependencies_info)

    return report

def display_menu():
    menu = """
               ('-. .-.              .-')     .-') _    
             ( OO )  /             ( OO ).  (  OO) )   
  ,----.     ,--. ,--.   .----.   (_)---\_) /     '._  
 '  .-./-')  |  | |  |  /  ..  \  /    _ |  |'--...__) 
 |  |_( O- ) |   .|  | .  /  \  . \  :` `.  '--.  .--' 
 |  | .--, \ |       | |  |  '  |  '..`''.)    |  |    
(|  | '. (_/ |  .-.  | '  \  /  ' .-._)   \    |  |    
 |  '--'  |  |  | |  |  \  `'  /  \       /    |  |    
  `------'   `--' `--'   `---''    `-----'     `--'    
   ('-.        _ (`-.     _ (`-.                   .-') _                _   .-')    
  ( OO ).-.   ( (OO  )   ( (OO  )                 ( OO ) )              ( '.( OO )_  
  / . --. /  _.`     \  _.`     \    .-----.  ,--./ ,--,'   ,--. ,--.    ,--.   ,--.)
  | \-.  \  (__...--'' (__...--''   /  -.   \ |   \ |  |\   |  | |  |    |   `.'   | 
.-'-'  |  |  |  /  | |  |  /  | |   '-' _'  | |    \|  | )  |  | | .-')  |         | 
 \| |_.'  |  |  |_.' |  |  |_.' |      |_  <  |  .     |/   |  |_|( OO ) |  |'.'|  | 
  |  .-.  |  |  .___.'  |  .___.'   .-.  |  | |  |\    |    |  | | `-' / |  |   |  | 
  |  | |  |  |  |       |  |        \ `-'   / |  | \   |   ('  '-'(_.-'  |  |   |  | 
  `--' `--'  `--'       `--'         `----''  `--'  `--'     `-----'     `--'   `--' 

    Thick Client Enumeration Tool
    
    Select a scan to conduct:
    1. DLL Vulnerability Scan
    2. Sensitive String Scan
    3. Thick Client Tier and Database/Server Scan
    4. Third-Party Dependencies Scan
    5. Run All Scans
    0. Exit
    """
    print(menu)

def main():
    while True:
        display_menu()

        choice = input("Enter your choice: ")

        if choice == "0":
            print("Exiting.")
            break
        elif choice == "1":
            app_path = input("Enter the application path to scan DLL vulnerabilities: ")
            verbose = input("Enable verbose mode? (y/n): ").lower() == 'y'
            vulnerabilities = detect_dll_vulnerabilities(app_path, verbose)
            report = generate_report(vulnerabilities, "DLL Vulnerability Scan")
            report_file_name = f"dll_vulnerability_scan_{int(time.time())}.txt"
            with open(report_file_name, "w", encoding="utf-8") as report_file:
                report_file.write(report)
            print(report)
        elif choice == "2":
            directory_path = input("Enter the directory path to scan for sensitive strings: ")
            verbose = input("Enable verbose mode? (y/n): ").lower() == 'y'
            sensitive_strings = identify_vulnerable_strings(directory_path)
            sensitive_strings_verbose = []

            if verbose:
                print("Scanning for sensitive strings...\n")

            for file_path, line_number, line in sensitive_strings:
                with open(file_path, "r", encoding="utf-8", errors="ignore") as file:
                    lines = file.readlines()
                    sensitive_strings_verbose.append(
                        (file_path, line_number, line.strip(), lines[max(0, line_number - 3):line_number + 2])
                    )

            report = generate_report(sensitive_strings_verbose, "Sensitive String Scan")
            report_file_name = f"sensitive_string_scan_{int(time.time())}.txt"
            with open(report_file_name, "w", encoding="utf-8") as report_file:
                report_file.write(report)
            print(report)
        elif choice == "3":
            app_path = input("Enter the application path for Thick Client Tier and Database/Server Scan: ")
            verbose = input("Enable verbose mode? (y/n): ").lower() == 'y'
            tier_type, tier_reason = identify_tier_type(app_path, verbose)
            database_type = "Unknown"  # Placeholder, you can enhance this based on your analysis

            print(f"\nThick Client Tier Type: {tier_type}")
            print(f"Reason: {tier_reason}")

            report = generate_tier_report(tier_type, tier_reason)
            report_file_name = f"tier_analysis_{int(time.time())}.txt"
            with open(report_file_name, "w") as report_file:
                report_file.write(report)

            print("\nTier Analysis Report:")
            print(report)
        elif choice == "4":
            target_path = input("Enter the application path or directory to scan for third-party dependencies: ")
            verbose = input("Enable verbose mode? (y/n): ").lower() == 'y'
            dependencies_info = determine_dependencies(target_path, verbose)
            report = generate_report([], "Third-Party Dependencies Scan", dependencies_info)
            report_file_name = f"dependencies_scan_{int(time.time())}.txt"
            with open(report_file_name, "w", encoding="utf-8") as report_file:
                report_file.write(report)
            print(report)
        elif choice == "5":
            target_path = input("Enter the application path or directory to run all scans: ")
            verbose = input("Enable verbose mode? (y/n): ").lower() == 'y'
            
            vulnerabilities = detect_dll_vulnerabilities(target_path, verbose)
            sensitive_strings = identify_vulnerable_strings(target_path)
            tier_type, tier_reason = identify_tier_type(target_path)
            dependencies_info = determine_dependencies(target_path, verbose)
            
            reports = []

            if vulnerabilities:
                vulnerabilities_report = generate_report(vulnerabilities, "DLL Vulnerability Scan")
                reports.append(vulnerabilities_report)

            if sensitive_strings:
                sensitive_strings_verbose = []
                for file_path, line_number, line in sensitive_strings:
                    with open(file_path, "r", encoding="utf-8", errors="ignore") as file:
                        lines = file.readlines()
                        sensitive_strings_verbose.append(
                            (file_path, line_number, line.strip(), lines[max(0, line_number - 3):line_number + 2])
                        )
                sensitive_strings_report = generate_report(sensitive_strings_verbose, "Sensitive String Scan")
                reports.append(sensitive_strings_report)

            tier_report = generate_tier_report(tier_type, tier_reason)
            reports.append(tier_report)

            if dependencies_info:
                dependencies_report = generate_report([], "Third-Party Dependencies Scan", dependencies_info)
                reports.append(dependencies_report)

            summary_report = "\n".join(reports)
            summary_report_file_name = f"comprehensive_scan_{int(time.time())}.txt"
            with open(summary_report_file_name, "w", encoding="utf-8") as report_file:
                report_file.write(summary_report)

            print("\nComprehensive Scan Summary Report:")
            print(summary_report)
        else:
            print("Invalid choice. Please select a valid option.")

if __name__ == "__main__":
    main()
