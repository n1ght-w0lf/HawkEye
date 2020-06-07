/*
void InternetOpenUrlW(
  HINTERNET hInternet,
  LPCWSTR   lpszUrl,
  LPCWSTR   lpszHeaders,
  DWORD     dwHeadersLength,
  DWORD     dwFlags,
  DWORD_PTR dwContext
);
*/
function instrumentInternetOpenUrl(opts) {
	var pInternetOpenUrl = opts.unicode ? Module.findExportByName("wininet.dll", "InternetOpenUrlW")
                                        : Module.findExportByName("wininet.dll", "InternetOpenUrlA");
	if(null == pInternetOpenUrl)
		return 0;

	Interceptor.attach(pInternetOpenUrl, {
		onEnter: function(args) {
			var url = opts.unicode ? args[1].readUtf16String() : args[1].readUtf8String();
			send({
				'hook': 'InternetOpenUrl',
				'url': url
			});
		}
	});
	return 1;
}

/*
INT WSAAPI GetAddrInfoW(
  PCWSTR          pNodeName,
  PCWSTR          pServiceName,
  const ADDRINFOW *pHints,
  PADDRINFOW      *ppResult
);
INT WSAAPI GetAddrInfoExW(
  PCWSTR                             pName,
  PCWSTR                             pServiceName,
  DWORD                              dwNameSpace,
  LPGUID                             lpNspId,
  const ADDRINFOEXW                  *hints,
  PADDRINFOEXW                       *ppResult,
  timeval                            *timeout,
  LPOVERLAPPED                       lpOverlapped,
  LPLOOKUPSERVICE_COMPLETION_ROUTINE lpCompletionRoutine,
  LPHANDLE                           lpHandle
);
*/
function instrumentGetAddrInfo(opts) {
	if(opts.ex) {
		var pGetAddrInfo = opts.unicode ? Module.findExportByName("ws2_32.dll", "GetAddrInfoExW")
                                        : Module.findExportByName("ws2_32.dll", "GetAddrInfoExA");
    } else {
		var pGetAddrInfo = opts.unicode ? Module.findExportByName("ws2_32.dll", "GetAddrInfoW")
                                        : Module.findExportByName("ws2_32.dll", "getaddrinfo");
    }

	if(null == pGetAddrInfo)
		return 0;

	Interceptor.attach(pGetAddrInfo, {
		onEnter: function(args) {
			var domain = opts.unicode ? args[0].readUtf16String() : args[0].readUtf8String();
			send({
				'hook': 'GetAddrInfo',
				'domain': domain
			});
		}
	});
	return 1;
}


var InternetOpenUrl_Instrumented = 0;
var GetAddrInfo_Instrumented = 0;

/*
HMODULE LoadLibraryW(
  LPCWSTR lpLibFileName
);
*/
function instrumentLoadLibrary(opts) {
	var pLoadLibrary = opts.unicode ? Module.findExportByName(null, "LoadLibraryW")
	                                : Module.findExportByName(null, "LoadLibraryA")
	Interceptor.attach(pLoadLibrary, {
		onEnter: function(args) {
			this.wininet = 0;
			this.ws2_32  = 0;
			var libName = (opts.unicode ? args[0].readUtf16String() : args[0].readUtf8String()).toLowerCase();
			if(libName.startsWith("wininet"))
				this.wininet = 1;
			else if(libName.startsWith("ws2_32"))
				this.ws2_32 = 1;
		},
		onLeave: function(retval) {
			if(this.wininet == 1 && !InternetOpenUrl_Instrumented) {
				instrumentInternetOpenUrl({unicode: 0});
				instrumentInternetOpenUrl({unicode: 1});
			} else if(this.ws2_32 == 1 && !GetAddrInfo_Instrumented) {
				instrumentGetAddrInfo({unicode: 0, ex: 0});
				instrumentGetAddrInfo({unicode: 1, ex: 0});
				instrumentGetAddrInfo({unicode: 0, ex: 1});
				instrumentGetAddrInfo({unicode: 1, ex: 1});
			}
		}
	});
}

InternetOpenUrl_Instrumented = (instrumentInternetOpenUrl({unicode: 0}) && 
	                            instrumentInternetOpenUrl({unicode: 1}));

GetAddrInfo_Instrumented = (instrumentGetAddrInfo({unicode: 0, ex: 0}) && 
	                        instrumentGetAddrInfo({unicode: 1, ex: 0}) && 
	                        instrumentGetAddrInfo({unicode: 0, ex: 1}) && 
	                        instrumentGetAddrInfo({unicode: 1, ex: 1}));

if(!InternetOpenUrl_Instrumented || !GetAddrInfo_Instrumented) {        // (wininet.dll | ws2_32.dll) not imported yet
	instrumentLoadLibrary({unicode: 0});
	instrumentLoadLibrary({unicode: 1});
}

