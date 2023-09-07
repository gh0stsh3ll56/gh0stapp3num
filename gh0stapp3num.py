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
import pymssql
from tqdm import tqdm
from datetime import datetime
from colorama import Fore, Back, Style, init
from pathlib import Path



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

def scan_dll_vulnerabilities(file_path, verbose):
    vulnerabilities = []

    # Use the "dumpbin" utility to get a list of imported DLLs
    try:
        output = subprocess.check_output(["dumpbin", "/DEPENDENTS", file_path], stderr=subprocess.STDOUT, text=True)

        # Parse the output to extract imported DLLs
        imported_dlls = set()
        lines = output.split("\n")
        for line in lines:
            line = line.strip()
            if line.startswith("Image has the following dependencies:"):
                # Start of the list of DLL dependencies
                break
            if line:
                imported_dlls.add(line.split()[0])

        if imported_dlls:
            vulnerabilities.append("Imported DLLs:")
            for dll in imported_dlls:
                vulnerabilities.append(f"- {dll}")
    except subprocess.CalledProcessError as e:
        if verbose:
            vulnerabilities.append(f"Error while scanning DLLs: {e.output.strip()}")
    except Exception as e:
        if verbose:
            vulnerabilities.append(f"Error while scanning DLLs: {str(e)}")

    return vulnerabilities




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
    process = None  # Initialize process as None

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
        if process is not None:  # Check if process is not None before terminating
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
        with open(file_path, 'rb') as file:
            content = file.read()
            # Define a regular expression pattern to match version information
            version_pattern = r'(\d+\.\d+\.\d+\.\d+)'  # You may need to adjust this pattern
            version_match = re.search(version_pattern, content.decode('utf-8'))

            if version_match:
                return version_match.group(1)
            else:
                return None
    except Exception:
        return None

def check_dependencies_vulnerabilities(dependencies_info):
    vulnerabilities = []
    outdated_versions_db = {
        "dependency_name": {"vulnerable_versions": ["1.0", "1.1"], "latest_version": "2.0"},
        # Add more entries
    }

    for dependency in dependencies_info:
        version_info = dependency.get("Version")
        dependency_name = os.path.basename(dependency.get("Path"))

        if version_info:
            # Check if the version is vulnerable or outdated based on your database
            if dependency_name in outdated_versions_db:
                vulnerable_versions = outdated_versions_db[dependency_name]["vulnerable_versions"]
                latest_version = outdated_versions_db[dependency_name]["latest_version"]

                if version_info in vulnerable_versions:
                    vulnerabilities.append({
                        "Dependency": dependency_name,
                        "Version": version_info,
                        "Status": "Vulnerable"
                    })
                elif version_info != latest_version:
                    vulnerabilities.append({
                        "Dependency": dependency_name,
                        "Version": version_info,
                        "Status": "Outdated"
                    })

    return vulnerabilities


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

    # Use pathlib to handle file paths
    root_path = Path(directory_path)

    for file_path in root_path.rglob("*"):
        if file_path.is_file():
            try:
                with open(file_path, "r", encoding="utf-8", errors="ignore") as file:
                    lines = file.readlines()
                    for line_number, line in enumerate(lines, start=1):
                        for pattern in sensitive_patterns:
                            matches = re.finditer(pattern, line, re.IGNORECASE)
                            for match in matches:
                                vulnerable_strings.append((str(file_path), line_number, line.strip()))
            except Exception as e:
                pass
    
    return vulnerable_strings

def identify_tier_type(app_path, verbose=False):
    tier_type = "unknown"
    tier_reason = "Unknown"
    keyword = ""

    try:
        with open(app_path, "rb") as app_file:
            application_content = app_file.read().decode("utf-8", errors="ignore")
    except Exception as e:
        print(f"Error reading file {app_path}: {str(e)}")
        application_content = ""

    database_keywords = {
        "mysql": "MySQL",
        "postgresql": "PostgreSQL",
        "sql server": "SQL Server",
        "oracle": "Oracle",
    }

    for keyword, db_type in database_keywords.items():
        if keyword in application_content.lower():
            tier_type = "Two-Tier (Database)"
            keyword = db_type
            break

    if "app_server" in application_content.lower() and "db_server" in application_content.lower():
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

    # Ensure that a tuple with two elements is always returned
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

def check_weak_passwords(lines, verbose=False):
    """
    Check if a line from a list of lines contains weak passwords.
    """
    weak_passwords = ["password", "123456", "admin", "qwerty"]  # Example weak passwords
    weak_password_matches = []

    for line in lines:
        for password in weak_passwords:
            if password in line:
                weak_password_matches.append((line.strip(), password))

    if weak_password_matches and verbose:
        print("Weak passwords found:")
        for line, password in weak_password_matches:
            print(f"Line: {line}, Weak Password: {password}")

    return weak_password_matches


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



def scan_dll_vulnerabilities(app_path, verbose=False, enable_progress_bar=False):
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
        check_weak_passwords(line, verbose)  # Pass verbose argument here

    return sensitive_strings_verbose

    
def run_scan(scan_func, scan_name, *args):
    try:
        scan_results = scan_func(*args)
        return scan_results
    except Exception as e:
        return f"Error during {scan_name}: {e}"

def get_dotnet_framework_info(app_path):
    try:
        # Specify the directory where the .NET Core SDK is located
        dotnet_sdk_dir = "C:\Program Files\dotnet"
        
        # Run the dotnet command to get the list of installed runtimes
        output = subprocess.check_output(["dotnet", "--list-runtimes"], cwd=dotnet_sdk_dir, stderr=subprocess.STDOUT, text=True)
        
        # Extract and return the .NET runtime information including vulnerability status
        runtime_info = parse_dotnet_runtime_info(output)
        return runtime_info
    except subprocess.CalledProcessError as e:
        return f"Error: {e.output.strip()}"
    except Exception as e:
        return f"Error: {str(e)}"


def parse_dotnet_runtime_info(output):
    runtime_info = []

    lines = output.strip().split('\n')
    for line in lines:
        parts = line.strip().split(' ')
        if len(parts) >= 2:
            version = parts[0]
            description = ' '.join(parts[1:])
            runtime_info.append({
                "Version": version,
                "Description": description,
                "Vulnerable": False,  # Initialize as not vulnerable
                "VulnerabilityReason": None
            })

    # Check for vulnerable versions and add a flag if found
    vulnerable_versions = ["4.5", "4.5.1", "4.5.2"]  # Add your list of vulnerable versions
    for version_info in runtime_info:
        if version_info["Version"] in vulnerable_versions:
            version_info["Vulnerable"] = True
            version_info["VulnerabilityReason"] = "This version is known to have vulnerabilities."

    return runtime_info


def run_custom_scan(app_path, verbose):
    custom_scan_results = []

    # Check .NET version
    dotnet_version = get_dotnet_framework_info(app_path)
    custom_scan_results.append(f".NET Version: {dotnet_version}")

    try:
        # Add your custom scanning logic here
        process = subprocess.Popen(app_path, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        stdout, stderr = process.communicate()
        process.wait()

        if verbose:
            print("Custom Scan Output (stdout):")
            print(stdout.decode("utf-8"))

            print("Custom Scan Errors (stderr):")
            print(stderr.decode("utf-8"))

        if process.is_running():
            process.terminate()

        # Example custom scanning logic
        if "vulnerability" in stdout.decode("utf-8").lower():
            custom_scan_results.append("Custom Vulnerability Detected")

    except Exception as e:
        custom_scan_results.append(f"Error during custom scan: {e}")

    return custom_scan_results


def is_sensitive_file(file_name, sensitive_file_extensions):
    """
    Check if a file may contain sensitive data based on its name and extension.
    """
    for ext in sensitive_file_extensions:
        if file_name.lower().endswith(ext):
            return True
    return False

def is_sensitive_directory(directory_name, sensitive_directory_keywords):
    """
    Check if a directory may contain sensitive data based on its name or keywords.
    """
    for keyword in sensitive_directory_keywords:
        if keyword.lower() in directory_name.lower():
            return True
    return False

def scan_directory(directory_path, verbose, sensitive_file_extensions=None, sensitive_directory_keywords=None):
    scan_results = []

    if sensitive_file_extensions is None:
        sensitive_file_extensions = ['.pem', '.key', '.password', '.secret', '.confidential']

    if sensitive_directory_keywords is None:
        sensitive_directory_keywords = ['private', 'confidential', 'secret']

    # Define regular expressions to search for sensitive data patterns
    sensitive_patterns = [
        r'password\s*=\s*[\'"](.*?)[\'"]',  # Matches passwords in configuration files
        r'api[_]?key\s*:\s*[\'"](.*?)[\'"]',  # Matches API keys
        # Add more patterns as needed for your specific use case
    ]

    for root, _, files in os.walk(directory_path):
        for file in files:
            file_path = os.path.join(root, file)
            if os.access(file_path, os.X_OK):  # Check if the file is executable
                scan_results.append(f"Scanning: {file_path}")
                custom_scan_results = run_custom_scan(file_path, verbose)
                scan_results.extend(custom_scan_results)
                scan_results.append("-" * 50)

            if is_sensitive_file(file, sensitive_file_extensions):
                scan_results.append(f"Sensitive file found: {file_path}")
                # Scan for sensitive data in text files
                if file_path.lower().endswith(('.txt', '.conf', '.config', '.ini', '.json', '.xml', '.yaml', '.yml')):
                    with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                        file_contents = f.read()
                        for pattern in sensitive_patterns:
                            matches = re.findall(pattern, file_contents, re.IGNORECASE)
                            if matches:
                                scan_results.append(f"Sensitive data pattern found: {matches}")
                                # You can customize the handling of matches here

    return scan_results
        


def run_scan_with_progress(scan_function, scan_name, target, verbose=False, enable_progress_bar=False):
    print(f"Running {scan_name}...")
    with tqdm(total=100, disable=not enable_progress_bar) as pbar:
        pbar.set_description(scan_name)
        scan_results = scan_function(target, verbose, enable_progress_bar)  # Correctly pass the arguments here
        pbar.update(100)
    print(f"{scan_name} completed.")
    return scan_results

def run_all_directory_scans(directory_path, verbose, enable_progress_bar):
    vulnerabilities = []
    sensitive_strings = []

    vulnerabilities, sensitive_strings = run_scan_with_progress(
        scan_dll_vulnerabilities, "DLL Vulnerability Scan", directory_path, verbose, enable_progress_bar
    )

    sensitive_strings = run_scan_with_progress(
        scan_sensitive_strings, "Sensitive String Scan", directory_path, verbose, enable_progress_bar
    )

    return vulnerabilities, sensitive_strings

def run_all_application_scans(app_path, verbose, enable_progress_bar):
    vulnerabilities = []
    writable_dirs = []
    sensitive_strings = []
    tier_results = ("unknown", "Unknown")
    dependencies_info = []

    vulnerabilities, writable_dirs = run_scan_with_progress(
        scan_dll_vulnerabilities, "DLL Vulnerability Scan", app_path, verbose, enable_progress_bar
    )

    try:
        with open(app_path, "r", encoding="utf-8") as app_file:
            application_content = app_file.read()
    except UnicodeDecodeError:
        try:
            with open(app_path, "r", encoding="latin-1") as app_file:
                application_content = app_file.read()
        except Exception as e:
            print(f"Error reading file: {str(e)} for file: {app_path}")
            application_content = ""

    tier_results = identify_tier_type(application_content, verbose)

    sensitive_strings = run_scan_with_progress(
        scan_sensitive_strings, "Sensitive String Scan", app_path, verbose, enable_progress_bar
    )

    dependencies_info = run_scan_with_progress(
        determine_dependencies, "Third-Party Dependencies Scan", app_path, verbose, enable_progress_bar
    )

    dotnet_framework_info = get_dotnet_framework_info(app_path)
    tier_results = (*tier_results, f".NET Framework: {dotnet_framework_info}")  # Add .NET Framework info

    return vulnerabilities, writable_dirs, sensitive_strings, tier_results, dependencies_info



def run_all_scans(directory_path, app_path, verbose, enable_progress_bar, loot_directory):
    directory_vulnerabilities = []
    directory_sensitive_strings = []
    app_vulnerabilities = []
    app_writable_dirs = []
    app_sensitive_strings = []
    app_tier_results = []
    app_dependencies_info = []

    directory_vulnerabilities, directory_sensitive_strings = run_all_directory_scans(
        directory_path, verbose, enable_progress_bar
    )

    app_vulnerabilities, app_writable_dirs, app_sensitive_strings, app_tier_results, app_dependencies_info = run_all_application_scans(
        app_path, verbose, enable_progress_bar
    )

    return (
        directory_vulnerabilities, directory_sensitive_strings,
        app_vulnerabilities, app_writable_dirs, app_sensitive_strings, app_tier_results, app_dependencies_info
    )


def generate_dependencies_report(dependencies_info):
    report = "\nThird-Party Dependencies Scan Results:\n"
    for dependency in dependencies_info:
        report += f"- Type: {dependency['Type']}\n"
        report += f"  Path: {dependency['Path']}\n"
        report += f"  Version: {dependency['Version']}\n"
    report += "\n"
    return report



def generate_report(scan_results, scan_type, dependencies_info=None, database_summary=None):
    report = f"\nComprehensive Scanning Report - {scan_type}\n\n"

    if scan_type == "DLL Vulnerability Scan":
        if scan_results:
            report += f"Number of Findings: {len(scan_results)}\n\n"
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
        if len(scan_results) >= 2:  # Check if there are at least two elements in scan_results
            report += f"Thick Client Tier Type: {scan_results[0]}\n"
            report += f"Database/Server Type: {scan_results[1]}\n"
        else:
            report += "Thick Client and Database/Server information not available.\n"

        if len(scan_results) >= 3:  # Check if there are at least three elements in scan_results
            report += f"{scan_results[2]}\n"  # .NET Framework info

        if database_summary:
            report += f"Database Identified: {database_summary}\n"

    elif scan_type == ".NET Framework Version Scan":
        report += f".NET Framework Version Scan Results:\n"
        vulnerable_versions = []

        for version_info in scan_results:
            report += f"- Version: {version_info['Version']}\n"
            report += f"  Vulnerable: {'Yes' if version_info.get('Vulnerable') else 'No'}\n"
            if version_info.get('Vulnerable'):
                report += f"  Vulnerability Reason: {version_info['VulnerabilityReason']}\n"
                vulnerable_versions.append(version_info['Version'])

        if vulnerable_versions:
            report += "\n"
            report += "Vulnerable Versions:\n"
            report += ", ".join(vulnerable_versions) + "\n"

    if dependencies_info is not None:
        report += "Third-Party Dependencies Scan Results:\n"
        for dependency in dependencies_info:
            report += f"- Type: {dependency['Type']}\n"
            report += f"  Path: {dependency['Path']}\n"
            report += f"  Version: {dependency['Version']}\n"
        report += "\n"

    return report


def save_report_to_file(report, file_name, loot_directory):
    try:
        loot_directory = os.path.abspath(loot_directory)
        os.makedirs(loot_directory, exist_ok=True)

        file_path = os.path.join(loot_directory, file_name)
        with open(file_path, "w", encoding="utf-8") as report_file:
            report_file.write(report)
        return file_path  # Return the full path of the saved report
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
    6. .Net Version 
    0. Exit
    """
    print(menu)

def main():
    init()  # Initialize colorama
    # Initialize the loot directory
    loot_directory = os.path.join(os.getcwd(), "loot")
    os.makedirs(loot_directory, exist_ok=True)

    while True:
        display_menu()

        choice = input("Enter your choice: ")

        if choice == "0":
            print("Exiting.")
            break
        elif choice == "1":
            # Option 1 code (DLL Vulnerability Scan)
            app_path = input("Enter the application directory path to scan for DLL vulnerabilities: ")
            verbose = input("Enable verbose mode? (y/n): ").lower() == "y"

            vulnerabilities, writable_dirs = run_scan_with_progress(
                scan_dll_vulnerabilities, "DLL Vulnerability Scan", app_path, verbose, enable_progress_bar=True
            )

            report = generate_report(vulnerabilities, "DLL Vulnerability Scan")
            file_name = f"dll_vulnerability_scan_{datetime.now().strftime('%Y-%m-%d_%H-%M-%S')}.txt"
            print(save_report_to_file(report, file_name, loot_directory))  # Add 'loot_directory' argument

        elif choice == "2":
            directory_path = input("Enter the directory path to scan for sensitive strings: ")
            verbose = input("Enable verbose mode? (y/n): ").lower() == "y"

            sensitive_strings = run_scan_with_progress(
                scan_sensitive_strings, "Sensitive String Scan", directory_path, enable_progress_bar=True
            )

            # Check weak passwords
            check_weak_passwords(sensitive_strings, verbose)

            # Check sensitive files
            check_sensitive_files(directory_path)

            sensitive_strings_report = generate_report(sensitive_strings, "Sensitive String Scan")
            file_name = f"sensitive_string_scan_{datetime.now().strftime('%Y-%m-%d_%H-%M-%S')}.txt"
            print(save_report_to_file(sensitive_strings_report, file_name, loot_directory))  # Pass loot_directory here

        elif choice == "3":
            # Option 3 code (Thick Client Tier and Database/Server Scan)
            target_path = input("Enter the application or directory path to scan: ")
            verbose = input("Enable verbose mode? (y/n): ").lower() == "y"
            loot_directory = os.path.join(os.getcwd(), "loot")

            if os.path.isfile(target_path):
                # If the input is a file, scan the single application
                print("Analyzing thick client tier and database/server type...")
                tier_type, tier_reason = identify_tier_type(target_path, verbose)
                tier_report = f"Target Path: {target_path}\nTier Type: {tier_type}\nReason: {tier_reason}\n"

                file_name = f"thick_client_analysis_{datetime.now().strftime('%Y-%m-%d_%H-%M-%S')}.txt"
                print(save_report_to_file(tier_report, file_name, loot_directory))
            elif os.path.isdir(target_path):
                # If the input is a directory, scan each application in the directory
                summary = {"Two-Tier": 0, "Three-Tier": 0}
                comprehensive_report = "Comprehensive Report:\n\n"
                for root, dirs, files in os.walk(target_path):
                    for app_file in files:
                        app_path = os.path.join(root, app_file)
                        if os.path.isfile(app_path):  # Check if it's a file before analyzing
                            print(f"Analyzing thick client tier and database/server type for: {app_path}")
                            tier_type, tier_reason = identify_tier_type(app_path, verbose)
                            tier_label = "Two-Tier" if tier_type == "2-tier" else "Three-Tier"
                            tier_report = (
                                f"Application Path: {app_path}\nTier Type: {tier_label}\nReason: {tier_reason}\n\n"
                            )
                            comprehensive_report += tier_report
                            summary[tier_label] += 1

                summary_report = f"Summary of Findings:\n\n"
                for label, count in summary.items():
                    summary_report += f"{label}: {count} applications\n"
                
                if comprehensive_report:
                    full_report = summary_report + "\n" + comprehensive_report
                    file_name = f"thick_client_analysis_{datetime.now().strftime('%Y-%m-%d_%H-%M-%S')}.txt"
                    print(save_report_to_file(full_report, file_name, loot_directory))
                else:
                    print("No applications found in the specified directory.")

            else:
                print("Invalid path. Please provide a valid application file or directory.")
            
        elif choice == "4":
            # Option 4 code (Third-Party Dependencies Scan)
            target_path = input("Enter the application or directory path to scan for third-party dependencies: ")
            verbose = input("Enable verbose mode? (y/n): ").lower() == "y"
            loot_directory = os.path.join(os.getcwd(), "loot")

            dependencies_info = run_scan_with_progress(
                determine_dependencies, "Third-Party Dependencies Scan", target_path, verbose, enable_progress_bar=True
            )

            app_dependencies_report = generate_report(dependencies_info, "Third-Party Dependencies Scan")  # Use generate_report

            file_name = f"dependencies_scan_{datetime.now().strftime('%Y-%m-%d_%H-%M-%S')}.txt"
            print(save_report_to_file(app_dependencies_report, file_name, loot_directory))  # Use app_dependencies_report

        elif choice == "5":
            # Option 5 code (Run All Scans)
            directory_path = input("Enter the directory path to scan for directory-based scans: ")
            app_path = input("Enter the application path to run application-based scans: ")
            verbose = input("Enable verbose mode? (y/n): ").lower() == "y"
            loot_directory = os.path.join(os.getcwd(), "loot")

            (
                directory_vulnerabilities, directory_sensitive_strings,
                app_vulnerabilities, app_writable_dirs, app_sensitive_strings, app_tier_results, app_dependencies_info
            ) = run_all_scans(directory_path, app_path, verbose, enable_progress_bar=True, loot_directory=loot_directory)

            # Generate and save reports for directory scans
            directory_vulnerabilities_report = generate_report(directory_vulnerabilities, "DLL Vulnerability Scan")
            directory_sensitive_strings_report = generate_report(directory_sensitive_strings, "Sensitive String Scan")
            directory_reports = directory_vulnerabilities_report + "\n\n" + directory_sensitive_strings_report
            directory_file_name = f"directory_scans_{datetime.now().strftime('%Y-%m-%d_%H-%M-%S')}.txt"
            print(save_report_to_file(directory_reports, directory_file_name, loot_directory))

            # Generate and save reports for application scans
            app_vulnerabilities_report = generate_report(app_vulnerabilities, "DLL Vulnerability Scan")
            app_sensitive_strings_report = generate_report(app_sensitive_strings, "Sensitive String Scan")
            
            # This part identifies the tier type and provides default values if needed
            app_tier_results = identify_tier_type(app_path, verbose)
            if len(app_tier_results) < 2:
                app_tier_results = ("unknown", "Unknown")
                
            app_tier_report = generate_report([app_tier_results], "Thick Client Tier and Database/Server Scan")
            app_dependencies_report = generate_dependencies_report(app_dependencies_info)
                
            app_reports = (
                app_vulnerabilities_report
                + "\n\n"
                + app_sensitive_strings_report
                + "\n\n"
                + app_tier_report
                + "\n\n"
                + app_dependencies_report
            )
            app_file_name = f"application_scans_{datetime.now().strftime('%Y-%m-%d_%H-%M-%S')}.txt"
            print(save_report_to_file(app_reports, app_file_name, loot_directory))
            
         

        elif choice == "6":
            # Option 6 code (.NET Version Scan)
            app_path = input("Enter the application path to scan for .NET version: ")
            verbose = input("Enable verbose mode? (y/n): ").lower() == "y"
            
            dotnet_version = get_dotnet_framework_info(app_path)
            
            report = f".NET Framework Version: {dotnet_version}"

            # Save the report to a file in the loot folder
            loot_directory = os.path.join(os.getcwd(), "loot")
            os.makedirs(loot_directory, exist_ok=True)  # Create the loot folder if it doesn't exist
            report_file_name = f"dotnet_version_scan_{datetime.now().strftime('%Y-%m-%d_%H-%M-%S')}.txt"
            report_file_path = os.path.join(loot_directory, report_file_name)

            with open(report_file_path, "w") as report_file:
                report_file.write(report)

            print(save_report_to_file(report, report_file_name, loot_directory))

if __name__ == "__main__":
    main()
