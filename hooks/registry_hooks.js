const REG_KEYS = {
	0x80000000: "HKEY_CLASSES_ROOT",
	0x80000001: "HKEY_CURRENT_USER",
	0x80000002: "HKEY_LOCAL_MACHINE",
	0x80000003: "HKEY_USERS",
	0x80000004: "HKEY_PERFORMANCE_DATA",
	0x80000005: "HKEY_CURRENT_CONFIG",
	0x80000006: "HKEY_DYN_DATA",
	0x80000050: "HKEY_PERFORMANCE_TEXT",
	0x80000060: "HKEY_PERFORMANCE_NLSTEXT"
}

/*
LSTATUS RegCreateKeyW(
  HKEY    hKey,
  LPCWSTR lpSubKey,
  PHKEY   phkResult
);
LSTATUS RegCreateKeyExW(
  HKEY                        hKey,
  LPCWSTR                     lpSubKey,
  DWORD                       Reserved,
  LPWSTR                      lpClass,
  DWORD                       dwOptions,
  REGSAM                      samDesired,
  const LPSECURITY_ATTRIBUTES lpSecurityAttributes,
  PHKEY                       phkResult,
  LPDWORD                     lpdwDisposition
);
*/
function instrumentRegCreateKey(opts) {
	if(opts.ex) {
		var pRegCreateKey = opts.unicode ? Module.findExportByName(null, "RegCreateKeyExW")
                                         : Module.findExportByName(null, "RegCreateKeyExA");
    } else {
		var pRegCreateKey = opts.unicode ? Module.findExportByName(null, "RegCreateKeyW")
                                         : Module.findExportByName(null, "RegCreateKeyA");    	
    }
	Interceptor.attach(pRegCreateKey, {
		onEnter: function(args) {
			this.regkey = opts.unicode ? args[1].readUtf16String() : args[1].readUtf8String();
			var regclass = REG_KEYS[args[0].toInt32()>>>0];
			if(regclass != undefined)
				this.regkey = regclass + "\\" + this.regkey;
			else
				this.regkey = "\\" + this.regkey;

			this.handle = opts.ex ? args[7] : args[2];
		},
		onLeave: function(retval) {
			send({
				'hook': 'RegCreateKey',
				'regkey': this.regkey,
				'handle': this.handle.readPointer().toInt32()
			});
		}
	});
}
instrumentRegCreateKey({unicode: 0, ex: 0});
instrumentRegCreateKey({unicode: 1, ex: 0});
instrumentRegCreateKey({unicode: 0, ex: 1});
instrumentRegCreateKey({unicode: 1, ex: 1});


/*
LSTATUS RegOpenKeyW(
  HKEY    hKey,
  LPCWSTR lpSubKey,
  PHKEY   phkResult
);
LSTATUS RegOpenKeyExW(
  HKEY    hKey,
  LPCWSTR lpSubKey,
  DWORD   ulOptions,
  REGSAM  samDesired,
  PHKEY   phkResult
);
*/
function instrumentRegOpenKey(opts) {
	if(opts.ex) {
		var pRegOpenKey = opts.unicode ? Module.findExportByName(null, "RegOpenKeyExW")
                                       : Module.findExportByName(null, "RegOpenKeyExA");
    } else {
		var pRegOpenKey = opts.unicode ? Module.findExportByName(null, "RegOpenKeyW")
                                       : Module.findExportByName(null, "RegOpenKeyA");    	
    }
	Interceptor.attach(pRegOpenKey, {
		onEnter: function(args) {
			this.regkey = opts.unicode ? args[1].readUtf16String() : args[1].readUtf8String();
			var regclass = REG_KEYS[args[0].toInt32()>>>0];
			if(regclass != undefined)
				this.regkey = regclass + "\\" + this.regkey;
			else
				this.regkey = "\\" + this.regkey;

			this.handle = opts.ex ? args[4] : args[2];
		},
		onLeave: function(retval) {
			send({
				'hook': 'RegOpenKey',
				'regkey': this.regkey,
				'handle': this.handle.readPointer().toInt32()
			});
		}
	});
}
instrumentRegOpenKey({unicode: 0, ex: 0});
instrumentRegOpenKey({unicode: 1, ex: 0});
instrumentRegOpenKey({unicode: 0, ex: 1});
instrumentRegOpenKey({unicode: 1, ex: 1});


/*
LSTATUS RegQueryValueExW(
  HKEY    hKey,
  LPCWSTR lpValueName,
  LPDWORD lpReserved,
  LPDWORD lpType,
  LPBYTE  lpData,
  LPDWORD lpcbData
);
*/
function instrumentRegQueryValueEx(opts) {
	var pRegQueryValueEx = opts.unicode ? Module.findExportByName(null, "RegQueryValueExW")
                                        : Module.findExportByName(null, "RegQueryValueExA");
	Interceptor.attach(pRegQueryValueEx, {
		onEnter: function(args) {
			var regvalue = opts.unicode ? args[1].readUtf16String() : args[1].readUtf8String();
			var handle = args[0].toInt32();
			send({
				'hook': 'RegQueryValueEx',
				'regvalue': regvalue,
				'handle': handle
			});
		}
	});
}
instrumentRegQueryValueEx({unicode: 0});
instrumentRegQueryValueEx({unicode: 1});


/*
LSTATUS RegSetValueExW(
  HKEY       hKey,
  LPCWSTR    lpValueName,
  DWORD      Reserved,
  DWORD      dwType,
  const BYTE *lpData,
  DWORD      cbData
);
*/
function instrumentRegSetValueEx(opts) {
	var pRegSetValueEx = opts.unicode ? Module.findExportByName(null, "RegSetValueExW")
                                      : Module.findExportByName(null, "RegSetValueExA");
	Interceptor.attach(pRegSetValueEx, {
		onEnter: function(args) {
			var regvalue = opts.unicode ? args[1].readUtf16String() : args[1].readUtf8String();
			var handle = args[0].toInt32();
			send({
				'hook': 'RegSetValueEx',
				'regvalue': regvalue,
				'handle': handle
			});
		}
	});
}
instrumentRegSetValueEx({unicode: 0});
instrumentRegSetValueEx({unicode: 1});


/*
LSTATUS RegDeleteValueW(
  HKEY    hKey,
  LPCWSTR lpValueName
);
*/
function instrumentRegDeleteValue(opts) {
	var pRegDeleteValue = opts.unicode ? Module.findExportByName(null, "RegDeleteValueW")
                                       : Module.findExportByName(null, "RegDeleteValueA");
	Interceptor.attach(pRegDeleteValue, {
		onEnter: function(args) {
			var regvalue = opts.unicode ? args[1].readUtf16String() : args[1].readUtf8String();
			var handle = args[0].toInt32();
			send({
				'hook': 'RegDeleteValue',
				'regvalue': regvalue,
				'handle': handle
			});
		}
	});
}
instrumentRegDeleteValue({unicode: 0});
instrumentRegDeleteValue({unicode: 1});
