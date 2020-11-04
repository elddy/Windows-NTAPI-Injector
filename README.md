# Native-WinAPI-ShellcodeLoader
Inject shellcode from memory to process using Windows NTAPI for bypassing EDRs and Antiviruses

## Usage
Enter a valid shellcode:

```C
// Put your shellcode here
char shellcode[] = "/xfc/xff.......";
```

compile using gcc/g++ or visual studio and run:

```shell
injector.exe <PID>
```
