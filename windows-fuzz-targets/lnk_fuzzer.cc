/*
 * Windows Shell Link (LNK) Fuzzer
 *
 * LNK files (shortcuts) are parsed by Windows Explorer and can trigger
 * code execution. The famous Stuxnet worm exploited an LNK vulnerability.
 *
 * Target areas:
 * - LNK file structure parsing
 * - Shell link interface
 * - Icon location parsing
 * - Path resolution
 *
 * Past CVEs: CVE-2017-8464 (Stuxnet-style), CVE-2020-0729
 */

#include <windows.h>
#include <shlobj.h>
#include <shobjidl.h>
#include <stdint.h>
#include <stddef.h>

#pragma comment(lib, "shell32.lib")
#pragma comment(lib, "ole32.lib")
#pragma comment(lib, "uuid.lib")

extern "C" int LLVMFuzzerInitialize(int *argc, char ***argv) {
    CoInitialize(NULL);
    return 0;
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size) {
    if (Size < 0x4C || Size > 1000000) {  // LNK header is 0x4C bytes
        return 0;
    }

    // Write data to temporary file
    wchar_t tempPath[MAX_PATH];
    wchar_t tempFile[MAX_PATH];

    GetTempPathW(MAX_PATH, tempPath);
    GetTempFileNameW(tempPath, L"lnk", 0, tempFile);

    // Change extension to .lnk
    wcscat_s(tempFile, L".lnk");

    HANDLE hFile = CreateFileW(
        tempFile,
        GENERIC_WRITE,
        0,
        NULL,
        CREATE_ALWAYS,
        FILE_ATTRIBUTE_NORMAL,
        NULL
    );

    if (hFile != INVALID_HANDLE_VALUE) {
        DWORD written;
        WriteFile(hFile, Data, (DWORD)Size, &written, NULL);
        CloseHandle(hFile);

        // Try to load the LNK file through IShellLink
        IShellLinkW* pShellLink = NULL;
        HRESULT hr = CoCreateInstance(
            CLSID_ShellLink,
            NULL,
            CLSCTX_INPROC_SERVER,
            IID_IShellLinkW,
            (LPVOID*)&pShellLink
        );

        if (SUCCEEDED(hr) && pShellLink) {
            IPersistFile* pPersistFile = NULL;
            hr = pShellLink->QueryInterface(IID_IPersistFile, (LPVOID*)&pPersistFile);

            if (SUCCEEDED(hr) && pPersistFile) {
                // Load the link file
                hr = pPersistFile->Load(tempFile, STGM_READ);

                if (SUCCEEDED(hr)) {
                    // Get various properties from the link
                    WCHAR szPath[MAX_PATH];
                    WCHAR szDescription[MAX_PATH];
                    WCHAR szArguments[MAX_PATH];
                    WCHAR szIconLocation[MAX_PATH];
                    int iIcon = 0;

                    // Get target path
                    WIN32_FIND_DATAW wfd;
                    pShellLink->GetPath(szPath, MAX_PATH, &wfd, SLGP_RAWPATH);

                    // Get description
                    pShellLink->GetDescription(szDescription, MAX_PATH);

                    // Get arguments
                    pShellLink->GetArguments(szArguments, MAX_PATH);

                    // Get icon location
                    pShellLink->GetIconLocation(szIconLocation, MAX_PATH, &iIcon);

                    // Get working directory
                    WCHAR szWorkingDir[MAX_PATH];
                    pShellLink->GetWorkingDirectory(szWorkingDir, MAX_PATH);

                    // Get show command
                    int nShowCmd;
                    pShellLink->GetShowCmd(&nShowCmd);

                    // Get hotkey
                    WORD wHotkey;
                    pShellLink->GetHotkey(&wHotkey);

                    // Get ID list (tests PIDL parsing)
                    LPITEMIDLIST pidl = NULL;
                    if (SUCCEEDED(pShellLink->GetIDList(&pidl)) && pidl) {
                        CoTaskMemFree(pidl);
                    }
                }

                pPersistFile->Release();
            }

            pShellLink->Release();
        }

        DeleteFileW(tempFile);
    }

    return 0;
}
