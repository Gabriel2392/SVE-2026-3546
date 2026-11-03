ENTRY(_start)
SECTIONS
{
    . = 0x896010100;
    __code_start = .;
    .code : { KEEP(*(.text.entry)) KEEP(*(.text.keep)) *(.text*) *(.rodata*) *(.data*) }
    __code_end = .;
    ASSERT(__code_end - __code_start <= 0xee0, "code exceeds 3808 bytes")
    .bss (NOLOAD) : { *(.bss*) *(COMMON) }
    ASSERT(SIZEOF(.bss) == 0, "payload must not use BSS")
    /DISCARD/ : { *(.comment*) *(.note*) *(.eh_frame*) }
}
