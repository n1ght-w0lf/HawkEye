/*
BOOL WINAPI CreateProcessInternalW(
  IN HANDLE                hUserToken,
  IN LPCWSTR               lpApplicationName,
  IN LPWSTR                lpCommandLine,
  IN LPSECURITY_ATTRIBUTES lpProcessAttributes,
  IN LPSECURITY_ATTRIBUTES lpThreadAttributes,
  IN BOOL                  bInheritHandles,
  IN DWORD                 dwCreationFlags,
  IN LPVOID                lpEnvironment,
  IN LPCWSTR               lpCurrentDirectory,
  IN LPSTARTUPINFOW        lpStartupInfo,
  IN LPPROCESS_INFORMATION lpProcessInformation,
  OUT PHANDLE              hNewToken 
);
typedef struct _PROCESS_INFORMATION {
  HANDLE hProcess;
  HANDLE hThread;
  DWORD  dwProcessId;
  DWORD  dwThreadId;
} PROCESS_INFORMATION, *PPROCESS_INFORMATION, *LPPROCESS_INFORMATION;
*/
var pCreateProcessInternalW = Module.findExportByName(null, "CreateProcessInternalW");
Interceptor.attach(pCreateProcessInternalW, {
	onEnter: function(args) {
		this.app = args[1].readUtf16String();
		this.cmd = args[2].readUtf16String();
		if(null == this.app)
			this.app = "c:\\windows\\system32\\cmd.exe";
		this.procinfo = args[10];
	},
	onLeave: function(retval) {
		send({
			'hook': 'CreateProcessInternalW',
			'app': this.app,
			'cmd': this.cmd,
			'handle': this.procinfo.readPointer().toInt32(),
			'pid': this.procinfo.add(2 * Process.pointerSize).readPointer().toInt32()
		});
	}
});

/*
HANDLE OpenProcess(
  DWORD dwDesiredAccess,
  BOOL  bInheritHandle,
  DWORD dwProcessId
);
*/
var pOpenProcess = Module.findExportByName(null, "OpenProcess");
Interceptor.attach(pOpenProcess, {
	onEnter: function(args) {
		this.pid = args[2].toInt32();
	},
	onLeave: function(retval) {
		send({
			'hook': 'OpenProcess',
			'handle': retval.toInt32(),
			'pid': this.pid
		});
	}
});

/*
LPVOID VirtualAllocEx(
  HANDLE hProcess,
  LPVOID lpAddress,
  SIZE_T dwSize,
  DWORD  flAllocationType,
  DWORD  flProtect
);
*/
var pVirtualAllocEx = Module.findExportByName(null, "VirtualAllocEx");
Interceptor.attach(pVirtualAllocEx, {
	onEnter: function(args) {
		send({
			'hook': 'VirtualAllocEx',
			'handle': args[0].toInt32()
		});
	}
});
