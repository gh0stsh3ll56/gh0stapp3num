import os
import platform
import psutil
import ctypes
import re
import hashlib
import time
import subprocess
import pkg_resources
import threading
from tqdm import tqdm
from datetime import datetime
from colorama import Fore, Back, Style, init

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

def scan_dll_vulnerabilities(app_path, verbose, enable_progress_bar):
    vulnerabilities, writable_dirs = detect_dll_hijacking_vulnerabilities(app_path, verbose)
    total_steps = len(vulnerabilities) + len(writable_dirs)
    progress_bar = tqdm(total=total_steps, unit=' step', desc="DLL Vulnerability Scan")
    if enable_progress_bar:
        for vulnerability in vulnerabilities:
            time.sleep(0.1)  # Simulate processing time
            progress_bar.update(1)
        for writable_dir in writable_dirs:
            time.sleep(0.1)  # Simulate processing time
            progress_bar.update(1)
    progress_bar.close()
    return vulnerabilities, writable_dirs




def detect_windows_dll_vulnerabilities(application_path, verbose=False):
    legitimate_paths = [
        r"C:\Windows\System32\kernel32.dll",
        r"C:\Windows\System32\user32.dll",
        # Add more legitimate DLL paths here
    ]

    suspicious_dlls = []

    process = psutil.Popen(application_path, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    stdout, stderr = process.communicate()
    process.wait()

    if verbose:
        print("Application Output (stdout):")
        print(stdout.decode("utf-8"))

        print("Application Errors (stderr):")
        print(stderr.decode("utf-8"))

    app_dir = os.path.dirname(application_path)
    app_dlls = [dll for dll in os.listdir(app_dir) if dll.lower().endswith(".dll")]
    for dll in app_dlls:
        dll_path = os.path.join(app_dir, dll)
        if not any(legit_path.lower() in dll_path.lower() for legit_path in legitimate_paths):
            if not is_path_writable(app_dir) and not verify_digital_signature(dll_path):
                suspicious_dlls.append((dll_path, "Potential DLL hijacking"))

            if verbose:
                print(f"Suspicious DLL in app directory: {dll_path}")

    return suspicious_dlls

def detect_linux_dll_vulnerabilities(application_path, verbose=False):
    legitimate_paths = [
        "/lib/x86_64-linux-gnu/libc.so.6",
        "/lib/x86_64-linux-gnu/libm.so.6",
        # Add more legitimate shared library paths here
    ]

    suspicious_libraries = []

    process = psutil.Popen(application_path, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    stdout, stderr = process.communicate()
    process.wait()

    if verbose:
        print("Application Output (stdout):")
        print(stdout.decode("utf-8"))

        print("Application Errors (stderr):")
        print(stderr.decode("utf-8"))

    app_dir = os.path.dirname(application_path)
    app_libs = [lib for lib in os.listdir(app_dir) if lib.lower().endswith(".so")]
    for lib in app_libs:
        lib_path = os.path.join(app_dir, lib)
        if not any(legit_path.lower() in lib_path.lower() for legit_path in legitimate_paths):
            suspicious_libraries.append(lib_path)
            if verbose:
                print(f"Suspicious library in app directory: {lib_path}")

    process.terminate()

    return suspicious_libraries

def detect_dll_hijacking_vulnerabilities(directory_path, verbose=False):
    suspicious_dlls = []
    writable_dirs = []

    for root, _, files in os.walk(directory_path):
        for file_name in files:
            file_path = os.path.join(root, file_name)
            if file_name.lower().endswith(".dll") and not verify_digital_signature(file_path):
                parent_dir = os.path.dirname(file_path)
                if is_path_writable(parent_dir):
                    writable_dirs.append(parent_dir)
                    suspicious_dlls.append((file_path, "Potential DLL hijacking"))

                if verbose:
                    print(f"Suspicious DLL in directory: {file_path}")

    return suspicious_dlls, writable_dirs




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


def determine_dependencies(target_path, verbose=True, enable_progress_bar=True):
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

def determine_windows_dependencies(application_path, verbose=True):
    dependencies_info = []

    try:
        process = subprocess.Popen(application_path)
        process.wait()

        app_dir = os.path.dirname(application_path)

        for root, _, files in os.walk(app_dir):
            for file_name in files:
                file_path = os.path.join(root, file_name)
                if file_name.lower().endswith((".dll", ".ocx")):
                    version_info = get_version_info(file_path)
                    if version_info:
                        dependencies_info.append({
                            "Type": "Dependency",
                            "Path": file_path,
                            "Version": version_info
                        })
    except Exception as e:
        print(f"Error during Windows dependencies scan: {e}")
    finally:
        try:
            process.terminate()
        except psutil.NoSuchProcess:
            pass

    return dependencies_info

def determine_linux_dependencies(application_path, verbose=True):
    dependencies_info = []

    process = subprocess.Popen(application_path)
    process.wait()

    app_dir = os.path.dirname(application_path)

    for root, _, files in os.walk(app_dir):
        for file_name in files:
            file_path = os.path.join(root, file_name)
            if file_name.lower().endswith(".so"):
                version_info = get_version_info(file_path)
                if version_info:
                    dependencies_info.append({
                        "Type": "Dependency",
                        "Path": file_path,
                        "Version": version_info
                    })

    process.terminate()

    return dependencies_info

def determine_dependencies_in_directory(directory_path, verbose=True):
    dependencies_info = []

    for root, _, files in os.walk(directory_path):
        for file_name in files:
            file_path = os.path.join(root, file_name)
            if file_name.lower().endswith((".dll", ".ocx", ".so")):
                version_info = get_version_info(file_path)
                if version_info:
                    dependencies_info.append({
                        "Type": "Dependency",
                        "Path": file_path,
                        "Version": version_info
                    })

    return dependencies_info

def get_version_info(file_path):
    try:
        info = pkg_resources.get_distribution(file_path)
        return info.version
    except Exception:
        return None


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
        r"\b(?:jwt|json_web_token)\b",
        r"\b(?:[0-9A-Fa-f]{8}-(?:[0-9A-Fa-f]{4}-){3}[0-9A-Fa-f]{12})\b",  # GUID pattern
        r"\b(?:S-\d+-\d+-\d+-\d+-\d+(?:-\d+)?(?:-\d+)?)\b",  # SID pattern
        r"\b(?:0x[0-9A-Fa-f]+)\b",  # Hexadecimal value
        r"\b(?:[A-Za-z_]+\([A-Za-z_]+(?:, [A-Za-z_]+)*\))\b"  # API call pattern (e.g., function_name(param1, param2))
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

def identify_tier_type(application_content):
    tier_type = "unknown"
    tier_reason = "Unknown"
    keyword = ""

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

    return tier_type, tier_reason


def detect_thick_client_vulnerabilities(application_path, verbose=False):
    suspicious_actions = [
        "CreateFile", "WriteFile", "ReadFile", "DeleteFile", "CopyFile", "MoveFile", "ShellExecute",
        # Add more suspicious actions or API calls here
    ]

    suspicious_activities = []

    process = psutil.Popen(application_path, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    stdout, stderr = process.communicate()
    process.wait()

    if verbose:
        print("Application Output (stdout):")
        print(stdout.decode("utf-8"))

        print("Application Errors (stderr):")
        print(stderr.decode("utf-8"))

    app_dir = os.path.dirname(application_path)

    # Check for suspicious API calls in the application output
    for action in suspicious_actions:
        if any(action.lower() in line.lower() for line in stdout.decode("utf-8").split("\n")):
            suspicious_activities.append((f"Suspicious API Call: {action}", ""))

    # Search for files created or modified by the application
    for root, _, files in os.walk(app_dir):
        for file_name in files:
            file_path = os.path.join(root, file_name)
            try:
                file_stat = os.stat(file_path)
                create_time = file_stat.st_ctime
                modify_time = file_stat.st_mtime

                if create_time > process.create_time() or modify_time > process.create_time():
                    suspicious_activities.append((f"File Created/Modified: {file_path}", ""))
            except Exception as e:
                pass

    process.terminate()

    return suspicious_activities


def check_privileges():
    try:
        return ctypes.windll.shell32.IsUserAnAdmin()
    except:
        return False

def check_weak_passwords(line, verbose):
    """
    Check if a line from a file contains weak passwords.
    """
    weak_passwords = ["password", "123456", "admin", "qwerty"]  # Example weak passwords
    matches = []

    for password in weak_passwords:
        if password in line:
            matches.append(password)
    
    if matches and verbose:
        print(f"Found weak passwords in line: {line.strip()}")
    
    return matches


def check_sensitive_files(scan_dir):
    sensitive_files = []

    print("Scanning for sensitive files...")
    for root, _, files in os.walk(scan_dir):
        for file in files:
            file_path = os.path.join(root, file)
            file_size = os.path.getsize(file_path)
            if file_size > 1024 * 1024:  # Check if file size is greater than 1MB
                sensitive_files.append(file_path)

    return sensitive_files



def scan_dll_vulnerabilities(app_path, verbose, enable_progress_bar):
    vulnerabilities, writable_dirs = detect_dll_hijacking_vulnerabilities(app_path, verbose)
    total_steps = len(vulnerabilities) + len(writable_dirs)
    progress_bar = tqdm(total=total_steps, unit=' step', desc="DLL Vulnerability Scan")
    if enable_progress_bar:
        for vulnerability in vulnerabilities:
            time.sleep(0.1)  # Simulate processing time
            progress_bar.update(1)
        for writable_dir in writable_dirs:
            time.sleep(0.1)  # Simulate processing time
            progress_bar.update(1)
    progress_bar.close()
    return vulnerabilities, writable_dirs

def scan_sensitive_strings(directory_path, verbose, enable_progress_bar):
    sensitive_strings = identify_vulnerable_strings(directory_path)
    total_steps = len(sensitive_strings)
    progress_bar = tqdm(total=total_steps, unit=' string', desc="Sensitive String Scan")
    sensitive_strings_verbose = []

    for file_path, line_number, line in sensitive_strings:
        try:
            with open(file_path, "r", encoding="utf-8", errors="ignore") as file:
                lines = file.readlines()
                context_lines = lines[max(0, line_number - 3):line_number + 2]
                sensitive_strings_verbose.append(
                    (file_path, line_number, line.strip(), context_lines))
        except Exception as e:
            pass
        
        if enable_progress_bar:
            time.sleep(0.1)  # Simulate processing time
            progress_bar.update(1)

    progress_bar.close()

    for file_path, _, line, _ in sensitive_strings_verbose:
        print(f"Checking {file_path} for sensitive files and weak passwords...")
        check_sensitive_files(file_path)
        check_weak_passwords(line)

    return sensitive_strings_verbose
    
def run_scan(scan_func, scan_name, *args):
    try:
        scan_results = scan_func(*args)
        return scan_results
    except Exception as e:
        return f"Error during {scan_name}: {e}"

def run_scan_with_progress(scan_function, scan_type, target, verbose, enable_progress_bar):
    print(f"Starting {scan_type}...")
    time.sleep(1)  # Simulating some initial processing
    scan_results = scan_function(target, verbose, enable_progress_bar)  # Pass the missing arguments
    
    # Display a progress bar while processing
    for _ in tqdm(range(10), desc=f"{scan_type} Progress", dynamic_ncols=True):
        time.sleep(0.2)
    
    print(f"{scan_type} completed.")
    return scan_results

def run_all_scans(app_path, verbose, enable_progress_bar):
    vulnerabilities = []
    writable_dirs = []
    sensitive_strings = []
    tier_results = ("unknown", "Unknown")
    dependencies_info = []

    vulnerabilities, writable_dirs = run_scan_with_progress(
        scan_dll_vulnerabilities, "DLL Vulnerability Scan", app_path, verbose, enable_progress_bar=True
    )

    sensitive_strings = run_scan_with_progress(
        scan_sensitive_strings, "Sensitive String Scan", app_path, verbose, enable_progress_bar=True
    )

    tier_results = run_scan_with_progress(
        identify_tier_type, "Thick Client Tier and Database/Server Scan", app_path, verbose, enable_progress_bar=True
    )
    dependencies_info = run_scan_with_progress(
        determine_dependencies, "Third-Party Dependencies Scan", app_path, verbose, enable_progress_bar=True
    )

    return vulnerabilities, writable_dirs, sensitive_strings, tier_results, dependencies_info




def generate_report(scan_results, scan_type, dependencies_info=None):
    report = f"\nComprehensive Scanning Report - {scan_type}\n\n"
    
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
        report += f"Thick Client Tier Type: {scan_results[0]}\n"
        report += f"Database/Server Type: {scan_results[1]}\n\n"

    if dependencies_info is not None:
        report += generate_dependencies_report(dependencies_info)

    return report

def save_report_to_file(report, file_name):
    try:
        with open(file_name, "w", encoding="utf-8") as report_file:
            report_file.write(report)
        return f"Report saved to {file_name}"
    except Exception as e:
        return f"Error while saving report: {e}"

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
    init()  # Initialize colorama

    while True:
        display_menu()

        choice = input("Enter your choice: ")

        if choice == "0":
            print("Exiting.")
            break
        elif choice == "1":
            app_path = input("Enter the application path to scan for DLL vulnerabilities: ")
            verbose = input("Enable verbose mode? (y/n): ").lower() == "y"

            vulnerabilities, writable_dirs = run_scan_with_progress(
                scan_dll_vulnerabilities, "DLL Vulnerability Scan", app_path, verbose, enable_progress_bar=True
            )

            report = generate_report(vulnerabilities, "DLL Vulnerability Scan")
            file_name = f"dll_vulnerability_scan_{datetime.now().strftime('%Y-%m-%d_%H-%M-%S')}.txt"
            print(save_report_to_file(report, file_name))

        elif choice == "2":
            directory_path = input("Enter the directory path to scan for sensitive strings: ")
            verbose = input("Enable verbose mode? (y/n): ").lower() == "y"

            sensitive_strings = run_scan_with_progress(
                scan_sensitive_strings, "Sensitive String Scan", directory_path, enable_progress_bar=True
            )

            # Check weak passwords
            check_weak_passwords(sensitive_strings)

            # Check sensitive files
            check_sensitive_files(directory_path)

            sensitive_strings_report = generate_report(sensitive_strings, "Sensitive String Scan")
            file_name = f"sensitive_string_scan_{datetime.now().strftime('%Y-%m-%d_%H-%M-%S')}.txt"
            print(save_report_to_file(sensitive_strings_report, file_name))


        elif choice == "3":
            app_path = input("Enter the application path to scan for thick client vulnerabilities: ")
            verbose = input("Enable verbose mode? (y/n): ").lower() == "y"

            print("Analyzing thick client tier and database/server type...")
            tier_results = run_scan_with_progress(
                identify_tier_type, "Thick Client Tier and Database/Server Scan", app_path, verbose, enable_progress_bar=True
            )
            tier_report = generate_report([tier_results], "Thick Client Tier and Database/Server Scan")

            dependencies_info = run_scan_with_progress(
                determine_dependencies, "Third-Party Dependencies Scan", app_path, verbose, enable_progress_bar=True
            )
            dependencies_report = generate_dependencies_report(dependencies_info)

            full_report = tier_report + "\n\n" + dependencies_report
            file_name = f"thick_client_analysis_{datetime.now().strftime('%Y-%m-%d_%H-%M-%S')}.txt"
            print(save_report_to_file(full_report, file_name))
            
        elif choice == "4":
            app_path = input("Enter the application path to scan for third-party dependencies: ")
            verbose = input("Enable verbose mode? (y/n): ").lower() == "y"

            dependencies_info = run_scan_with_progress(
               determine_dependencies, "Third-Party Dependencies Scan", app_path, verbose, enable_progress_bar=True
            )

            report = generate_report(dependencies_info, "Third-Party Dependencies Scan")
            file_name = f"dependencies_scan_{datetime.now().strftime('%Y-%m-%d_%H-%M-%S')}.txt"
            print(save_report_to_file(report, file_name))
            
        elif choice == "5":
            app_path = input("Enter the application path to run all scans: ")
            verbose = input("Enable verbose mode? (y/n): ").lower() == "y"

            vulnerabilities, writable_dirs, sensitive_strings = run_all_scans(
                app_path, verbose, enable_progress_bar=True
            )

            dll_vulnerability_report = generate_report(vulnerabilities, "DLL Vulnerability Scan")
            sensitive_string_report = generate_report(sensitive_strings, "Sensitive String Scan")

            tier_results = run_scan(identify_tier_type, app_path, verbose)
            tier_report = generate_report([tier_results], "Thick Client Tier and Database/Server Scan")

            dependencies_info = run_scan(determine_dependencies, app_path, verbose)
            dependencies_report = generate_dependencies_report(dependencies_info)

            full_report = (
                dll_vulnerability_report
                + "\n\n"
                + sensitive_string_report
                + "\n\n"
                + tier_report
                + "\n\n"
                + dependencies_report
            )
            file_name = f"comprehensive_scan_{datetime.now().strftime('%Y-%m-%d_%H-%M-%S')}.txt"
            print(save_report_to_file(full_report, file_name))
            
        else:
            print("Invalid choice. Please select a valid option.")

if __name__ == "__main__":
    main()
