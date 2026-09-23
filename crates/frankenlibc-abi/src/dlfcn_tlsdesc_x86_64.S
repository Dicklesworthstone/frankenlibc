/* Native x86-64 GNU2 TLS descriptor bridge. Spec-derived, not a C ABI entry.
 * RAX -> (entry, argument); return RAX = TLS address - thread pointer.
 * Preserve every other GPR and all enabled user xstate. The helper may allocate
 * and call ordinary C/Rust functions, including on an existing thread's first
 * access to a newly loaded module. No SIMD instruction may precede the save.
 *
 * The helper symbol is supplied by Rust global_asm!'s `resolver = sym ...`.
 * A C harness can substitute its own normal-ABI helper to stress preservation.
 */
.text
.p2align 4
.globl frankenlibc_native_tlsdesc
.hidden frankenlibc_native_tlsdesc
.type frankenlibc_native_tlsdesc, @function
frankenlibc_native_tlsdesc:
    .cfi_startproc
    endbr64
    pushq %rbp
    .cfi_def_cfa_offset 16
    .cfi_offset %rbp, -16
    movq %rsp, %rbp
    .cfi_def_cfa_register %rbp
    pushq %rbx
    .cfi_offset %rbx, -24
    pushq %rcx
    .cfi_offset %rcx, -32
    pushq %rdx
    .cfi_offset %rdx, -40
    pushq %rsi
    .cfi_offset %rsi, -48
    pushq %rdi
    .cfi_offset %rdi, -56
    pushq %r8
    .cfi_offset %r8, -64
    pushq %r9
    .cfi_offset %r9, -72
    pushq %r10
    .cfi_offset %r10, -80
    pushq %r11
    .cfi_offset %r11, -88
    pushq %r12
    .cfi_offset %r12, -96
    pushq %r13
    .cfi_offset %r13, -104
    pushq %r14
    .cfi_offset %r14, -112
    pushq %r15
    .cfi_offset %r15, -120
    movq %rax, %r12

    /* Probe the current OS-enabled state, not just the CPU's AVX capability.
     * CPUID.0D.0.EBX sizes the standard XSAVE layout for the current XCR0.
     * FXSAVE is sufficient only when the OS has not enabled XSAVE at all.
     */
    movl $1, %eax
    cpuid
    andl $0x0c000000, %ecx
    cmpl $0x0c000000, %ecx
    jne .Lfl_tlsdesc_fx
    xorl %ecx, %ecx
    xgetbv
    movl %eax, %r14d
    movl %edx, %r15d
    movl $13, %eax
    xorl %ecx, %ecx
    cpuid
    movl $1, %r13d
    jmp .Lfl_tlsdesc_frame
.Lfl_tlsdesc_fx:
    movl $512, %ebx
    xorl %r13d, %r13d
.Lfl_tlsdesc_frame:
    /* Align the state area to 64 bytes. Probe EVERY crossed page: extended
     * state can exceed a page (e.g. AVX-512/AMX), so one large stack decrement
     * must not jump across a stack guard into a different mapping.
     */
    movq %rsp, %rcx
    subq %rbx, %rcx
    andq $-64, %rcx
.Lfl_tlsdesc_probe:
    movq %rsp, %rax
    subq %rcx, %rax
    cmpq $4096, %rax
    jbe .Lfl_tlsdesc_tail
    subq $4096, %rsp
    orq $0, (%rsp)
    jmp .Lfl_tlsdesc_probe
.Lfl_tlsdesc_tail:
    movq %rcx, %rsp
    orq $0, (%rsp)
    /* XSAVE does not initialize reserved header bytes. XRSTOR requires them
     * to be zero; clearing only XSTATE_BV is not sufficient.
     */
    movq %rsp, %rdi
    movq %rbx, %rcx
    xorl %eax, %eax
    rep stosb
    testl %r13d, %r13d
    jz .Lfl_tlsdesc_save_fx
    movl %r14d, %eax
    movl %r15d, %edx
    xsave64 (%rsp)
    jmp .Lfl_tlsdesc_call
.Lfl_tlsdesc_save_fx:
    fxsave64 (%rsp)
.Lfl_tlsdesc_call:
    /* The transparent caller may have a live x87 stack. Ordinary C calls
     * expect it empty. Its complete contents/control/status were saved above.
     */
    fninit
    movq 8(%r12), %rdi
    call {resolver}
    movq %rax, %r12
    testl %r13d, %r13d
    jz .Lfl_tlsdesc_restore_fx
    movl %r14d, %eax
    movl %r15d, %edx
    xrstor64 (%rsp)
    jmp .Lfl_tlsdesc_return
.Lfl_tlsdesc_restore_fx:
    fxrstor64 (%rsp)
.Lfl_tlsdesc_return:
    movq %r12, %rax
    subq %fs:0, %rax
    leaq -104(%rbp), %rsp
    popq %r15
    .cfi_restore %r15
    popq %r14
    .cfi_restore %r14
    popq %r13
    .cfi_restore %r13
    popq %r12
    .cfi_restore %r12
    popq %r11
    .cfi_restore %r11
    popq %r10
    .cfi_restore %r10
    popq %r9
    .cfi_restore %r9
    popq %r8
    .cfi_restore %r8
    popq %rdi
    .cfi_restore %rdi
    popq %rsi
    .cfi_restore %rsi
    popq %rdx
    .cfi_restore %rdx
    popq %rcx
    .cfi_restore %rcx
    popq %rbx
    .cfi_restore %rbx
    popq %rbp
    .cfi_def_cfa %rsp, 8
    .cfi_restore %rbp
    ret
    .cfi_endproc
.size frankenlibc_native_tlsdesc, .-frankenlibc_native_tlsdesc
.section .note.GNU-stack,"",@progbits
