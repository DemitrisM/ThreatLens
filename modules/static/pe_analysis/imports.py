"""Import / export extraction, suspicious-API tagging, dynamic resolution."""


# Suspicious imports that indicate potentially malicious behaviour.
_SUSPICIOUS_IMPORTS = {
    # Memory allocation / process injection
    "VirtualAlloc", "VirtualAllocEx", "VirtualProtect", "VirtualProtectEx",
    "WriteProcessMemory", "ReadProcessMemory",
    "CreateRemoteThread", "CreateRemoteThreadEx",
    "NtWriteVirtualMemory", "NtCreateThreadEx",
    "QueueUserAPC", "NtQueueApcThread",
    "RtlCreateUserThread",
    # Process hollowing / thread manipulation (modern injection)
    "OpenProcess", "OpenThread",
    "SetThreadContext", "GetThreadContext",
    "Wow64SetThreadContext", "Wow64GetThreadContext",
    "ResumeThread", "SuspendThread",
    "NtUnmapViewOfSection", "ZwUnmapViewOfSection",
    "NtMapViewOfSection", "ZwMapViewOfSection",
    "NtCreateSection", "ZwCreateSection",
    # Code execution
    "WinExec", "ShellExecuteA", "ShellExecuteW",
    "ShellExecuteExA", "ShellExecuteExW",
    "CreateProcessA", "CreateProcessW",
    "CreateProcessInternalA", "CreateProcessInternalW",
    # DLL injection / dynamic resolution
    "LoadLibraryA", "LoadLibraryW",
    "LoadLibraryExA", "LoadLibraryExW",
    "GetProcAddress", "LdrLoadDll", "LdrGetProcedureAddress",
    # Privilege / token manipulation
    "OpenProcessToken", "AdjustTokenPrivileges",
    "LookupPrivilegeValueA", "LookupPrivilegeValueW",
    "ImpersonateLoggedOnUser", "DuplicateTokenEx",
    # Anti-debug / anti-analysis
    "IsDebuggerPresent", "CheckRemoteDebuggerPresent",
    "NtQueryInformationProcess", "NtSetInformationThread",
    "OutputDebugStringA", "OutputDebugStringW",
    "FindWindowA", "FindWindowW",  # used to detect analysis windows
    # Crypto (often used for payload encryption)
    "CryptEncrypt", "CryptDecrypt",
    "CryptAcquireContextA", "CryptAcquireContextW",
    "BCryptEncrypt", "BCryptDecrypt", "BCryptGenRandom",
    # Networking
    "InternetOpenA", "InternetOpenW",
    "InternetOpenUrlA", "InternetOpenUrlW",
    "HttpOpenRequestA", "HttpOpenRequestW",
    "HttpSendRequestA", "HttpSendRequestW",
    "URLDownloadToFileA", "URLDownloadToFileW",
    "WSAStartup", "WSASocketA", "WSASocketW",
    "connect", "send", "recv", "WSAConnect",
    "WinHttpOpen", "WinHttpConnect", "WinHttpSendRequest",
    # Registry persistence
    "RegOpenKeyExA", "RegOpenKeyExW",
    "RegSetValueExA", "RegSetValueExW",
    "RegCreateKeyExA", "RegCreateKeyExW",
    # Keylogging / hooking
    "SetWindowsHookExA", "SetWindowsHookExW",
    "GetAsyncKeyState", "GetKeyState",
    "GetForegroundWindow", "GetWindowTextA", "GetWindowTextW",
    # File-system staging
    "CreateFileMappingA", "CreateFileMappingW",
    "MapViewOfFile", "UnmapViewOfFile",
}

# APIs that, when present *together*, almost guarantee a process-hollowing
# / shellcode-injection routine. We award an extra bonus if any TWO of
# these are imported (the combo is rare in benign software).
_HOLLOWING_API_INDICATORS = frozenset({
    "SetThreadContext", "Wow64SetThreadContext",
    "NtUnmapViewOfSection", "ZwUnmapViewOfSection",
    "NtMapViewOfSection", "ZwMapViewOfSection",
    "WriteProcessMemory", "NtWriteVirtualMemory",
    "VirtualAllocEx",
    "CreateRemoteThread", "CreateRemoteThreadEx",
    "QueueUserAPC", "NtQueueApcThread",
    "ResumeThread",  # combined with SetThreadContext = classic hollowing
})

# Buckets used to score behaviour-category diversity. A binary that
# imports across many distinct buckets (e.g. anti-debug + persistence
# + execution + network) is performing classic multi-stage malware
# behaviour even if no single bucket has many entries.
_API_CATEGORIES: dict[str, frozenset[str]] = {
    "injection": frozenset({
        "VirtualAlloc", "VirtualAllocEx", "VirtualProtect", "VirtualProtectEx",
        "WriteProcessMemory", "ReadProcessMemory",
        "CreateRemoteThread", "CreateRemoteThreadEx",
        "NtWriteVirtualMemory", "NtCreateThreadEx",
        "QueueUserAPC", "NtQueueApcThread", "RtlCreateUserThread",
        "OpenProcess", "OpenThread",
        "SetThreadContext", "GetThreadContext",
        "Wow64SetThreadContext", "Wow64GetThreadContext",
        "ResumeThread", "SuspendThread",
        "NtUnmapViewOfSection", "ZwUnmapViewOfSection",
        "NtMapViewOfSection", "ZwMapViewOfSection",
        "NtCreateSection", "ZwCreateSection",
    }),
    "execution": frozenset({
        "WinExec", "ShellExecuteA", "ShellExecuteW",
        "ShellExecuteExA", "ShellExecuteExW",
        "CreateProcessA", "CreateProcessW",
        "CreateProcessInternalA", "CreateProcessInternalW",
    }),
    "loader": frozenset({
        "LoadLibraryA", "LoadLibraryW", "LoadLibraryExA", "LoadLibraryExW",
        "GetProcAddress", "LdrLoadDll", "LdrGetProcedureAddress",
    }),
    "antidebug": frozenset({
        "IsDebuggerPresent", "CheckRemoteDebuggerPresent",
        "NtQueryInformationProcess", "NtSetInformationThread",
        "OutputDebugStringA", "OutputDebugStringW",
        "FindWindowA", "FindWindowW",
    }),
    "network": frozenset({
        "InternetOpenA", "InternetOpenW",
        "InternetOpenUrlA", "InternetOpenUrlW",
        "HttpOpenRequestA", "HttpOpenRequestW",
        "HttpSendRequestA", "HttpSendRequestW",
        "URLDownloadToFileA", "URLDownloadToFileW",
        "WSAStartup", "WSASocketA", "WSASocketW",
        "connect", "send", "recv", "WSAConnect",
        "WinHttpOpen", "WinHttpConnect", "WinHttpSendRequest",
    }),
    "persistence": frozenset({
        "RegOpenKeyExA", "RegOpenKeyExW",
        "RegSetValueExA", "RegSetValueExW",
        "RegCreateKeyExA", "RegCreateKeyExW",
    }),
    "keylog": frozenset({
        "SetWindowsHookExA", "SetWindowsHookExW",
        "GetAsyncKeyState", "GetKeyState",
        "GetForegroundWindow", "GetWindowTextA", "GetWindowTextW",
    }),
    "crypto": frozenset({
        "CryptEncrypt", "CryptDecrypt",
        "CryptAcquireContextA", "CryptAcquireContextW",
        "BCryptEncrypt", "BCryptDecrypt", "BCryptGenRandom",
    }),
    "privilege": frozenset({
        "OpenProcessToken", "AdjustTokenPrivileges",
        "LookupPrivilegeValueA", "LookupPrivilegeValueW",
        "ImpersonateLoggedOnUser", "DuplicateTokenEx",
    }),
}

# Win32 APIs that, if seen as raw strings inside the file but missing
# from the import table, indicate runtime resolution via GetProcAddress.
# Drawn from the suspicious-imports list intersected with names that
# are realistically resolvable at runtime.
_DYNAMIC_API_CANDIDATES = frozenset({
    "VirtualAlloc", "VirtualAllocEx", "VirtualProtect",
    "WriteProcessMemory", "ReadProcessMemory",
    "CreateRemoteThread", "NtCreateThreadEx",
    "SetThreadContext", "ResumeThread",
    "NtUnmapViewOfSection", "ZwUnmapViewOfSection",
    "LoadLibraryA", "LoadLibraryW", "LoadLibraryExA", "LoadLibraryExW",
    "GetProcAddress",
    "WinExec", "ShellExecuteA", "ShellExecuteW",
    "CreateProcessA", "CreateProcessW",
    "InternetOpenA", "InternetOpenW",
    "URLDownloadToFileA", "URLDownloadToFileW",
    "WSAStartup", "connect",
    "RegOpenKeyExA", "RegOpenKeyExW",
    "RegSetValueExA", "RegSetValueExW",
    "IsDebuggerPresent", "CheckRemoteDebuggerPresent",
    "SetWindowsHookExA", "SetWindowsHookExW",
})


def _extract_imports(pe: "pefile.PE") -> tuple[dict, set]:
    """Extract imported DLLs and functions, flag suspicious ones.

    Returns:
        (imports_dict, set_of_suspicious_function_names)
    """
    imports: dict[str, list[str]] = {}
    suspicious: set[str] = set()

    if not hasattr(pe, "DIRECTORY_ENTRY_IMPORT"):
        return imports, suspicious

    for entry in pe.DIRECTORY_ENTRY_IMPORT:
        dll_name = entry.dll.decode("utf-8", errors="replace")
        functions = []
        for imp in entry.imports:
            if imp.name:
                func_name = imp.name.decode("utf-8", errors="replace")
                functions.append(func_name)
                if func_name in _SUSPICIOUS_IMPORTS:
                    suspicious.add(func_name)
            else:
                functions.append(f"ordinal_{imp.ordinal}")
        imports[dll_name] = functions

    return imports, suspicious


def _extract_exports(pe: "pefile.PE") -> list[str]:
    """Extract exported function names."""
    exports = []
    if not hasattr(pe, "DIRECTORY_ENTRY_EXPORT"):
        return exports

    for exp in pe.DIRECTORY_ENTRY_EXPORT.symbols:
        if exp.name:
            exports.append(exp.name.decode("utf-8", errors="replace"))
        else:
            exports.append(f"ordinal_{exp.ordinal}")
    return exports


def _classify_import_footprint(imports: dict, is_dotnet: bool) -> dict:
    """Classify the import-table footprint at a high level.

    The defining mark of a packed/shellcode-loader binary is a tiny
    import table — usually a single DLL (kernel32) with just a handful
    of functions (LoadLibrary, GetProcAddress, VirtualAlloc, …) so the
    real imports can be resolved at runtime.
    """
    info = {
        "dll_count": len(imports),
        "is_kernel32_only": False,
        "loader_only": False,
    }
    if is_dotnet:
        return info
    dll_names = {dll.lower() for dll in imports.keys()}
    if dll_names == {"kernel32.dll"}:
        info["is_kernel32_only"] = True
        funcs = {f.lower() for f in imports.get("kernel32.dll", [])
                 if isinstance(f, str)}
        loader_set = {"loadlibrarya", "loadlibraryw", "getprocaddress",
                      "virtualalloc", "virtualprotect", "exitprocess"}
        if funcs and funcs.issubset(loader_set | {"getmodulehandlea",
                                                  "getmodulehandlew"}):
            info["loader_only"] = True
    return info


def _detect_dynamic_api_resolution(
    pe: "pefile.PE", suspicious_imports: set[str]
) -> dict:
    """Find suspicious APIs that appear as raw strings but not as imports.

    A binary that contains the *string* "VirtualAllocEx" but does not
    import it is almost certainly resolving the function at runtime via
    GetProcAddress / hash-based resolution — a packer / shellcode
    loader hallmark.
    """
    info = {"count": 0, "apis": []}
    try:
        raw = pe.__data__
    except Exception:  # noqa: BLE001
        return info
    candidates = _DYNAMIC_API_CANDIDATES - suspicious_imports
    found: list[str] = []
    for api in candidates:
        # Use a quick byte search; the API names are ASCII-only.
        if api.encode("ascii") in raw:
            found.append(api)
    info["count"] = len(found)
    info["apis"] = sorted(found)[:10]
    return info


def _count_forwarded_exports(pe: "pefile.PE") -> int:
    """Count export entries that forward to another DLL.

    Forwarded exports are how Windows API set DLLs (api-ms-win-*)
    redirect calls to their real implementation. On a normal EXE
    they're suspicious because they suggest a proxy / hijack DLL.
    """
    if not hasattr(pe, "DIRECTORY_ENTRY_EXPORT"):
        return 0
    count = 0
    try:
        for sym in pe.DIRECTORY_ENTRY_EXPORT.symbols:
            if getattr(sym, "forwarder", None):
                count += 1
    except Exception:  # noqa: BLE001
        return 0
    return count
