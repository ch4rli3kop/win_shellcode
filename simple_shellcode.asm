.code
	;
	; Simple SHELLCODE
	;
	; This Simple Shellcode run only when user knows WinExec's address 
	;
	SIMPLE_SHELLCODE proc
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
		mov rax, 7ffed6325f80h      ; WinExec's address
		call rax
	; call ExitProcess(1)
	;		mov rcx, 1
	;		mov rax, 7ffcf37b5f80h
	;		call rax
	; function epilogue
		mov rsp, rbp		
		pop rbp
		ret
	SIMPLE_SHELLCODE endp
end
