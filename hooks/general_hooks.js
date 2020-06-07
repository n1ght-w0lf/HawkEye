/*
FARPROC GetProcAddress(
  HMODULE hModule,
  LPCSTR  lpProcName
);
*/
var pGetProcAddress = Module.findExportByName(null, "GetProcAddress");
Interceptor.attach(pGetProcAddress, {
	onEnter: function(args) {
		send({
			'hook': 'GetProcAddress',
			'func': args[1].readUtf8String()
		});
	}
});


/*
HANDLE CreateMutexW(
  LPSECURITY_ATTRIBUTES lpMutexAttributes,
  BOOL                  bInitialOwner,
  LPCWSTR               lpName
);
HANDLE CreateMutexExW(
  LPSECURITY_ATTRIBUTES lpMutexAttributes,
  LPCWSTR               lpName,
  DWORD                 dwFlags,
  DWORD                 dwDesiredAccess
);
*/
function instrumentCreateMutex(opts) {
	if(opts.ex) {
		var pCreateMutex = opts.unicode ? Module.findExportByName(null, "CreateMutexExW")
                                    	: Module.findExportByName(null, "CreateMutexExA");
    } else {
		var pCreateMutex = opts.unicode ? Module.findExportByName(null, "CreateMutexW")
                                    	: Module.findExportByName(null, "CreateMutexA");
    }
	Interceptor.attach(pCreateMutex, {
		onEnter: function(args) {
			if(opts.ex) {
				var mutex = opts.unicode ? args[1].readUtf16String() : args[1].readUtf8String();
			} else {
				var mutex = opts.unicode ? args[2].readUtf16String() : args[2].readUtf8String();
			}
			send({
				'hook': 'CreateMutex',
				'mutex': mutex
			});
		}
	});
}
instrumentCreateMutex({unicode: 0, ex: 0});
instrumentCreateMutex({unicode: 1, ex: 0});
instrumentCreateMutex({unicode: 0, ex: 1});
instrumentCreateMutex({unicode: 1, ex: 1});