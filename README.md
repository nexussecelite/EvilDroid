# EvilDroid: Automated Exploit for CVE-2024-0044

**EvilDroid** is a sophisticated tool designed for automated exploitation of CVE-2024-0044 vulnerabilities. This script streamlines the process of exploiting vulnerable Android applications by automating the payload deployment and APK installation.

## Overview

EvilDroid automates the exploitation of CVE-2024-0044, installing malicious payloads on a target device and extracting sensitive data. It features automated ADB connection checks, APK pushing, UID extraction, payload generation, and real-time progress updates, providing a seamless and professional user experience.

## Features

- **Automated APK Installation**: Pushes and installs the APK file onto the target device.
- **Payload Execution**: Generates and executes payloads based on the application's UID.
- **ADB Device Detection**: Checks for connected ADB devices and verifies connectivity.
- **User-Friendly Interface**: Command-line arguments for easy configuration and execution.

## Prerequisites

- **ADB (Android Debug Bridge)**: Ensure ADB is installed and properly configured on your system.
- **Python 3.x**: This script is compatible with Python 3.x versions.

## Installation

1. **Clone the Repository**:

    ```bash
    git clone https://github.com/yourusername/evildroid.git
    cd evildroid
    ```

2. **Install Dependencies**:

    Ensure you have Python 3.x installed and then install any required Python packages (if needed):

    ```bash
    pip install -r requirements.txt
    ```

## Usage

1. **Connect Your Device**:

    Make sure your Android device is connected and ADB is properly set up:

    ```bash
    adb devices
    ```

2. **Run the Exploit**:

    Use the following command to start the exploit. Replace `com.whatsapp` with the target package name and provide the path to your APK file:

    ```bash
    python evildroid.py -p com.whatsapp -a /path/to/your.apk
    ```

    - `-p, --package`: Target package name (e.g., `com.whatsapp`).
    - `-a, --apk`: Path to the APK file to install.

## Example

```bash
python evildroid.py -p com.whatsapp -a /path/to/whatsapp.apk
```

## Acknowledgments

- **CVE-2024-0044**: The vulnerability discovered by Meta Security.

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## Disclaimer

This tool is for educational purposes only. The author and contributors are not responsible for any misuse or illegal activities performed using this tool. Use responsibly and only on devices and systems you own or have explicit permission to test.

## Contact

For any issues or questions, please open an issue on the GitHub repository or contact the maintainer at `contact@nexussec.in`.

---

**EvilDroid** - A powerful tool for educational exploitation purposes. Always use responsibly and ensure compliance with local laws and regulations.

---
