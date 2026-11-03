.section .text.entry, "ax"
.balign 4
.global _start
.type _start, %function
_start:
    b start_impl
.size _start, .-_start
