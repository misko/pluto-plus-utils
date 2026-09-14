ENTRY(entry)
SECTIONS {
 . = 0x06000000;
 .text : { *(.text.entry) *(.text*) }
 .rodata : { *(.rodata*) }
 /DISCARD/ : { *(.comment) *(.note*) *(.ARM.exidx*) *(.ARM.extab*) }
}
