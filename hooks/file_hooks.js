const FILE_ACCESS_MASKS = {
	"GENERIC_ALL": 0x10000000,
	"GENERIC_EXECUTE": 0x20000000,	
	"GENERIC_WRITE": 0x40000000,
	"GENERIC_READ": 0x80000000
};

const FILE_CREATION_ACTIONS = {
	"CREATE_ALWAYS": 2,
	"CREATE_NEW": 1,
	"OPEN_ALWAYS": 4,
	"OPEN_EXISTING": 3,
	"TRUNCATE_EXISTING": 5
};

/*
HANDLE CreateFileW(
  LPCWSTR               lpFileName,
  DWORD                 dwDesiredAccess,
  DWORD                 dwShareMode,
  LPSECURITY_ATTRIBUTES lpSecurityAttributes,
  DWORD                 dwCreationDisposition,
  DWORD                 dwFlagsAndAttributes,
  HANDLE                hTemplateFile
);
*/
function instrumentCreateFile(opts) {
	var pCreateFile = opts.unicode ? Module.findExportByName(null, "CreateFileW")
                                   : Module.findExportByName(null, "CreateFileA");
	Interceptor.attach(pCreateFile, {
		onEnter: function(args) {
			this.path = opts.unicode ? args[0].readUtf16String() : args[0].readUtf8String();
			var mask = args[1].toInt32();
			var action = args[4].toInt32();

			this.new = 0;
			if(action == FILE_CREATION_ACTIONS["CREATE_ALWAYS"] || action == FILE_CREATION_ACTIONS["CREATE_NEW"])
				this.new = 1;
		},
		onLeave: function(retval) {
			send({
				'hook': 'CreateFile',
				'handle': retval.toInt32(),   // file handle
				'path': this.path,
				'new': this.new
			});
		}
	});
}
instrumentCreateFile({unicode: 0});
instrumentCreateFile({unicode: 1});

/*
BOOL WriteFile(
  HANDLE       hFile,
  LPCVOID      lpBuffer,
  DWORD        nNumberOfBytesToWrite,
  LPDWORD      lpNumberOfBytesWritten,
  LPOVERLAPPED lpOverlapped
);
*/
var pWriteFile = Module.getExportByName(null, "WriteFile");
Interceptor.attach(pWriteFile, {
	onEnter: function(args) {
		send({
			'hook': 'WriteFile',
			'handle': args[0].toInt32()
		});
	}
});

/*
BOOL MoveFileW(
  LPCWSTR lpExistingFileName,
  LPCWSTR lpNewFileName
);
BOOL MoveFileExW(
  LPCWSTR lpExistingFileName,
  LPCWSTR lpNewFileName,
  DWORD   dwFlags
);
*/
function instrumentMoveFile(opts) {
	if(opts.ex) {
		var pMoveFile = opts.unicode ? Module.findExportByName(null, "MoveFileExW")
                                     : Module.findExportByName(null, "MoveFileExA");
    } else {
		var pMoveFile = opts.unicode ? Module.findExportByName(null, "MoveFileW")
                                     : Module.findExportByName(null, "MoveFileA");
    }
	Interceptor.attach(pMoveFile, {
		onEnter: function(args) {
			var oldpath = opts.unicode ? args[0].readUtf16String() : args[0].readUtf8String();
			var newpath = opts.unicode ? args[1].readUtf16String() : args[1].readUtf8String();
			send({
				'hook': 'MoveFile',
				'oldpath': oldpath,
				'newpath': newpath
			});
		}
	});
}
instrumentMoveFile({unicode: 0, ex: 0});
instrumentMoveFile({unicode: 1, ex: 0});
instrumentMoveFile({unicode: 0, ex: 1});
instrumentMoveFile({unicode: 1, ex: 1});

/*
BOOL CopyFileW(
  LPCWSTR lpExistingFileName,
  LPCWSTR lpNewFileName,
  BOOL    bFailIfExists
);
BOOL CopyFileExW(
  LPCWSTR            lpExistingFileName,
  LPCWSTR            lpNewFileName,
  LPPROGRESS_ROUTINE lpProgressRoutine,
  LPVOID             lpData,
  LPBOOL             pbCancel,
  DWORD              dwCopyFlags
);
*/
function instrumentCopyFile(opts) {
	if(opts.ex) {
		var pCopyFile = opts.unicode ? Module.findExportByName(null, "CopyFileExW")
                                     : Module.findExportByName(null, "CopyFileExA");
    } else {
		var pCopyFile = opts.unicode ? Module.findExportByName(null, "CopyFileW")
                                     : Module.findExportByName(null, "CopyFileA");
    }
	Interceptor.attach(pCopyFile, {
		onEnter: function(args) {
			var oldpath = opts.unicode ? args[0].readUtf16String() : args[0].readUtf8String();
			var newpath = opts.unicode ? args[1].readUtf16String() : args[1].readUtf8String();
			send({
				'hook': 'CopyFile',
				'oldpath': oldpath,
				'newpath': newpath
			});
		}
	});
}
instrumentCopyFile({unicode: 0, ex: 0});
instrumentCopyFile({unicode: 1, ex: 0});
instrumentCopyFile({unicode: 0, ex: 1});
instrumentCopyFile({unicode: 1, ex: 1});

/*
BOOL DeleteFileW(
  LPCWSTR lpFileName
);
*/
function instrumentDeleteFile(opts) {
	var pDeleteFile = opts.unicode ? Module.findExportByName(null, "DeleteFileW")
                                   : Module.findExportByName(null, "DeleteFileA");
	Interceptor.attach(pDeleteFile, {
		onEnter: function(args) {
			var path = opts.unicode ? args[0].readUtf16String() : args[0].readUtf8String();
			send({
				'hook': 'DeleteFile',
				'path': path
			});
		}
	});
}
instrumentDeleteFile({unicode: 0});
instrumentDeleteFile({unicode: 1});