/* Execute an opaque TLSDESC with live GPR, x87, SIMD and opmask state.
 * expected_address == NULL checks value 7 without warming TLS via dlsym. */
.text
.globl probe_state
.type probe_state,@function
probe_state:
    pushq %rbp
    pushq %rbx
    pushq %r12
    pushq %r13
    pushq %r14
    pushq %r15
    subq $3656, %rsp
    movq %rdi, 0(%rsp)
    movl %esi, 8(%rsp)
    movq %rdx, 16(%rsp)
    leaq 32(%rsp), %rdi
    movl $3104, %ecx
    xorl %eax, %eax
    rep stosb
    fxsave64 3136(%rsp)
    fninit
    fld1
    fldpi
    fld1
    fldpi
    fld1
    fldpi
    fld1
    fldpi
    fxsave64 32(%rsp)
    cmpl $512, 8(%rsp)
    je .Lseed512
    cmpl $256, 8(%rsp)
    je .Lseed256
    movdqu .Lpattern(%rip), %xmm0
    movdqu .Lpattern(%rip), %xmm1
    movdqu .Lpattern(%rip), %xmm2
    movdqu .Lpattern(%rip), %xmm3
    movdqu .Lpattern(%rip), %xmm4
    movdqu .Lpattern(%rip), %xmm5
    movdqu .Lpattern(%rip), %xmm6
    movdqu .Lpattern(%rip), %xmm7
    movdqu .Lpattern(%rip), %xmm8
    movdqu .Lpattern(%rip), %xmm9
    movdqu .Lpattern(%rip), %xmm10
    movdqu .Lpattern(%rip), %xmm11
    movdqu .Lpattern(%rip), %xmm12
    movdqu .Lpattern(%rip), %xmm13
    movdqu .Lpattern(%rip), %xmm14
    movdqu .Lpattern(%rip), %xmm15
    jmp .Lseed_gp
.Lseed256:
    vmovdqu .Lpattern(%rip), %ymm0
    vmovdqu .Lpattern(%rip), %ymm1
    vmovdqu .Lpattern(%rip), %ymm2
    vmovdqu .Lpattern(%rip), %ymm3
    vmovdqu .Lpattern(%rip), %ymm4
    vmovdqu .Lpattern(%rip), %ymm5
    vmovdqu .Lpattern(%rip), %ymm6
    vmovdqu .Lpattern(%rip), %ymm7
    vmovdqu .Lpattern(%rip), %ymm8
    vmovdqu .Lpattern(%rip), %ymm9
    vmovdqu .Lpattern(%rip), %ymm10
    vmovdqu .Lpattern(%rip), %ymm11
    vmovdqu .Lpattern(%rip), %ymm12
    vmovdqu .Lpattern(%rip), %ymm13
    vmovdqu .Lpattern(%rip), %ymm14
    vmovdqu .Lpattern(%rip), %ymm15
    jmp .Lseed_gp
.Lseed512:
    vmovdqu64 .Lpattern(%rip), %zmm0
    vmovdqu64 .Lpattern(%rip), %zmm1
    vmovdqu64 .Lpattern(%rip), %zmm2
    vmovdqu64 .Lpattern(%rip), %zmm3
    vmovdqu64 .Lpattern(%rip), %zmm4
    vmovdqu64 .Lpattern(%rip), %zmm5
    vmovdqu64 .Lpattern(%rip), %zmm6
    vmovdqu64 .Lpattern(%rip), %zmm7
    vmovdqu64 .Lpattern(%rip), %zmm8
    vmovdqu64 .Lpattern(%rip), %zmm9
    vmovdqu64 .Lpattern(%rip), %zmm10
    vmovdqu64 .Lpattern(%rip), %zmm11
    vmovdqu64 .Lpattern(%rip), %zmm12
    vmovdqu64 .Lpattern(%rip), %zmm13
    vmovdqu64 .Lpattern(%rip), %zmm14
    vmovdqu64 .Lpattern(%rip), %zmm15
    vmovdqu64 .Lpattern(%rip), %zmm16
    vmovdqu64 .Lpattern(%rip), %zmm17
    vmovdqu64 .Lpattern(%rip), %zmm18
    vmovdqu64 .Lpattern(%rip), %zmm19
    vmovdqu64 .Lpattern(%rip), %zmm20
    vmovdqu64 .Lpattern(%rip), %zmm21
    vmovdqu64 .Lpattern(%rip), %zmm22
    vmovdqu64 .Lpattern(%rip), %zmm23
    vmovdqu64 .Lpattern(%rip), %zmm24
    vmovdqu64 .Lpattern(%rip), %zmm25
    vmovdqu64 .Lpattern(%rip), %zmm26
    vmovdqu64 .Lpattern(%rip), %zmm27
    vmovdqu64 .Lpattern(%rip), %zmm28
    vmovdqu64 .Lpattern(%rip), %zmm29
    vmovdqu64 .Lpattern(%rip), %zmm30
    vmovdqu64 .Lpattern(%rip), %zmm31
    movl $0x5a5a, %eax
    kmovw %eax, %k0
    kmovw %eax, %k1
    kmovw %eax, %k2
    kmovw %eax, %k3
    kmovw %eax, %k4
    kmovw %eax, %k5
    kmovw %eax, %k6
    kmovw %eax, %k7
.Lseed_gp:
    movabsq $6510516211317473381, %rbx
    movabsq $6510516211317473382, %rcx
    movabsq $6510516211317473383, %rdx
    movabsq $6510516211317473384, %rsi
    movabsq $6510516211317473385, %rdi
    movabsq $6510516211317473386, %r8
    movabsq $6510516211317473387, %r9
    movabsq $6510516211317473388, %r10
    movabsq $6510516211317473389, %r11
    movabsq $6510516211317473390, %r12
    movabsq $6510516211317473391, %r13
    movabsq $6510516211317473392, %r14
    movabsq $6510516211317473393, %r15
    movabsq $6510516211317473394, %rbp
    movq 0(%rsp), %rax
    call *(%rax)
    addq %fs:0, %rax
    cmpq $0, 16(%rsp)
    je .Lcheck_cold_value
    cmpq 16(%rsp), %rax
    jne .Lbad_address
    jmp .Lcheck_gprs
.Lcheck_cold_value:
    testq %rax, %rax
    jz .Lbad_address
    cmpq $7, (%rax)
    jne .Lbad_address
.Lcheck_gprs:
    movabsq $6510516211317473381, %rax
    cmpq %rax, %rbx
    jne .Lbad_gpr
    movabsq $6510516211317473382, %rax
    cmpq %rax, %rcx
    jne .Lbad_gpr
    movabsq $6510516211317473383, %rax
    cmpq %rax, %rdx
    jne .Lbad_gpr
    movabsq $6510516211317473384, %rax
    cmpq %rax, %rsi
    jne .Lbad_gpr
    movabsq $6510516211317473385, %rax
    cmpq %rax, %rdi
    jne .Lbad_gpr
    movabsq $6510516211317473386, %rax
    cmpq %rax, %r8
    jne .Lbad_gpr
    movabsq $6510516211317473387, %rax
    cmpq %rax, %r9
    jne .Lbad_gpr
    movabsq $6510516211317473388, %rax
    cmpq %rax, %r10
    jne .Lbad_gpr
    movabsq $6510516211317473389, %rax
    cmpq %rax, %r11
    jne .Lbad_gpr
    movabsq $6510516211317473390, %rax
    cmpq %rax, %r12
    jne .Lbad_gpr
    movabsq $6510516211317473391, %rax
    cmpq %rax, %r13
    jne .Lbad_gpr
    movabsq $6510516211317473392, %rax
    cmpq %rax, %r14
    jne .Lbad_gpr
    movabsq $6510516211317473393, %rax
    cmpq %rax, %r15
    jne .Lbad_gpr
    movabsq $6510516211317473394, %rax
    cmpq %rax, %rbp
    jne .Lbad_gpr
    fxsave64 544(%rsp)
    cmpl $512, 8(%rsp)
    je .Lsave512
    cmpl $256, 8(%rsp)
    je .Lsave256
    movdqu %xmm0, 1056(%rsp)
    movdqu %xmm1, 1072(%rsp)
    movdqu %xmm2, 1088(%rsp)
    movdqu %xmm3, 1104(%rsp)
    movdqu %xmm4, 1120(%rsp)
    movdqu %xmm5, 1136(%rsp)
    movdqu %xmm6, 1152(%rsp)
    movdqu %xmm7, 1168(%rsp)
    movdqu %xmm8, 1184(%rsp)
    movdqu %xmm9, 1200(%rsp)
    movdqu %xmm10, 1216(%rsp)
    movdqu %xmm11, 1232(%rsp)
    movdqu %xmm12, 1248(%rsp)
    movdqu %xmm13, 1264(%rsp)
    movdqu %xmm14, 1280(%rsp)
    movdqu %xmm15, 1296(%rsp)
    movl $256, %ecx
    jmp .Lcheck_vectors
.Lsave256:
    vmovdqu %ymm0, 1056(%rsp)
    vmovdqu %ymm1, 1088(%rsp)
    vmovdqu %ymm2, 1120(%rsp)
    vmovdqu %ymm3, 1152(%rsp)
    vmovdqu %ymm4, 1184(%rsp)
    vmovdqu %ymm5, 1216(%rsp)
    vmovdqu %ymm6, 1248(%rsp)
    vmovdqu %ymm7, 1280(%rsp)
    vmovdqu %ymm8, 1312(%rsp)
    vmovdqu %ymm9, 1344(%rsp)
    vmovdqu %ymm10, 1376(%rsp)
    vmovdqu %ymm11, 1408(%rsp)
    vmovdqu %ymm12, 1440(%rsp)
    vmovdqu %ymm13, 1472(%rsp)
    vmovdqu %ymm14, 1504(%rsp)
    vmovdqu %ymm15, 1536(%rsp)
    movl $512, %ecx
    jmp .Lcheck_vectors
.Lsave512:
    vmovdqu64 %zmm0, 1056(%rsp)
    vmovdqu64 %zmm1, 1120(%rsp)
    vmovdqu64 %zmm2, 1184(%rsp)
    vmovdqu64 %zmm3, 1248(%rsp)
    vmovdqu64 %zmm4, 1312(%rsp)
    vmovdqu64 %zmm5, 1376(%rsp)
    vmovdqu64 %zmm6, 1440(%rsp)
    vmovdqu64 %zmm7, 1504(%rsp)
    vmovdqu64 %zmm8, 1568(%rsp)
    vmovdqu64 %zmm9, 1632(%rsp)
    vmovdqu64 %zmm10, 1696(%rsp)
    vmovdqu64 %zmm11, 1760(%rsp)
    vmovdqu64 %zmm12, 1824(%rsp)
    vmovdqu64 %zmm13, 1888(%rsp)
    vmovdqu64 %zmm14, 1952(%rsp)
    vmovdqu64 %zmm15, 2016(%rsp)
    vmovdqu64 %zmm16, 2080(%rsp)
    vmovdqu64 %zmm17, 2144(%rsp)
    vmovdqu64 %zmm18, 2208(%rsp)
    vmovdqu64 %zmm19, 2272(%rsp)
    vmovdqu64 %zmm20, 2336(%rsp)
    vmovdqu64 %zmm21, 2400(%rsp)
    vmovdqu64 %zmm22, 2464(%rsp)
    vmovdqu64 %zmm23, 2528(%rsp)
    vmovdqu64 %zmm24, 2592(%rsp)
    vmovdqu64 %zmm25, 2656(%rsp)
    vmovdqu64 %zmm26, 2720(%rsp)
    vmovdqu64 %zmm27, 2784(%rsp)
    vmovdqu64 %zmm28, 2848(%rsp)
    vmovdqu64 %zmm29, 2912(%rsp)
    vmovdqu64 %zmm30, 2976(%rsp)
    vmovdqu64 %zmm31, 3040(%rsp)
    kmovw %k0, %eax
    cmpl $0x5a5a, %eax
    jne .Lbad_vector
    kmovw %k1, %eax
    cmpl $0x5a5a, %eax
    jne .Lbad_vector
    kmovw %k2, %eax
    cmpl $0x5a5a, %eax
    jne .Lbad_vector
    kmovw %k3, %eax
    cmpl $0x5a5a, %eax
    jne .Lbad_vector
    kmovw %k4, %eax
    cmpl $0x5a5a, %eax
    jne .Lbad_vector
    kmovw %k5, %eax
    cmpl $0x5a5a, %eax
    jne .Lbad_vector
    kmovw %k6, %eax
    cmpl $0x5a5a, %eax
    jne .Lbad_vector
    kmovw %k7, %eax
    cmpl $0x5a5a, %eax
    jne .Lbad_vector
    movl $2048, %ecx
.Lcheck_vectors:
    leaq 1056(%rsp), %rdi
    xorl %esi, %esi
.Lcheck_byte:
    cmpb $0x5a, (%rdi,%rsi)
    jne .Lbad_vector
    incl %esi
    cmpl %ecx, %esi
    jb .Lcheck_byte
    leaq 32(%rsp), %rsi
    leaq 544(%rsp), %rdi
    movl $160, %ecx
    repe cmpsb
    jne .Lbad_x87
    xorl %eax, %eax
    jmp .Ldone
.Lbad_address:
    movl $1, %eax
    jmp .Ldone
.Lbad_gpr:
    movl $2, %eax
    jmp .Ldone
.Lbad_vector:
    movl $3, %eax
    jmp .Ldone
.Lbad_x87:
    movl $4, %eax
.Ldone:
    fxrstor64 3136(%rsp)
    addq $3656, %rsp
    popq %r15
    popq %r14
    popq %r13
    popq %r12
    popq %rbx
    popq %rbp
    ret
.size probe_state,.-probe_state
.section .rodata
.p2align 6
.Lpattern:
    .fill 64,1,0x5a
.section .note.GNU-stack,"",@progbits
