.code

extern exit_constructed_space:qword
extern handler: proc
extern g_info_page:qword

;
;   Helper functions
;
get_proc_number proc
    push rcx
    push rdx

    rdtscp
    mov eax, ecx

    pop rdx
    pop rcx

    ret
get_proc_number endp

; Assembly wrapper for the main handler
asm_handler proc
    
	; Allocate stack memory for our handler 
	; (Allocate quite some memory to account for msvc compiler stupidity)
    ; and align to a 16 byte boundary
	sub rsp, 40h
	call handler
	add rsp, 40h

    jmp qword ptr [exit_constructed_space]
asm_handler endp

end