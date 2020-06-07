<img src="report/images/logo.png" />

# HawkEye

HawkEye is a dynamic malware analysis tool based on [frida.re](https://www.frida.re/) framework. It will hook common functions to log malware activities and output the results in a nice web page report.

This is not a sandbox so please use it in a safe sandboxed environment.

# Installation

- Install the prerequisites 

```
pip install frida
pip install psutil
```

- Clone this repository

```
git clone https://github.com/N1ght-W0lf/HawkEye.git
```

# Usage

```
usage: HawkEye.py [-h] [--path PATH] [--pid PID]

optional arguments:
  -h, --help   show this help message and exit
  --path PATH  File path
  --pid PID    Process PID
```

HawkEye runs in 2 modes:

- spawn a malware sample in a new process given its path.
- hook a running process given its PID.

# Hooked Functions

#### Processes:

- CreateProcessInternalW
- OpenProcess
- VirtualAllocEx

#### Files:

- CreateFile
- WriteFile
- MoveFile
- CopyFile
- DeleteFile

#### Registry:

- RegCreateKey
- RegOpenKey
- RegQueryValueEx
- RegSetValueEx
- RegDeleteValue

#### Network:

- InternetOpenUrl
- GetAddrInfo

#### General:

- LoadLibrary

- GetProcAddress
- CreateMutex

# Example Report

<img src="report/images/report.gif" />

I've also uploaded a video for a full report from analysis to final results.

 [https://www.youtube.com/watch?v=DnCj2Dt6OcE]( https://www.youtube.com/watch?v=DnCj2Dt6OcE)