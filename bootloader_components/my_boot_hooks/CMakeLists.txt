idf_component_register(
    SRCS    "hooks.c"
    PRIV_REQUIRES bootloader_support spi_flash
)

# We need to force GCC to integrate this static library into the
# bootloader link. Indeed, by default, as the hooks in the bootloader are weak,
# the linker would just ignore the symbols in the extra. (i.e. not strictly
# required)
# To do so, we need to define the symbol (function) `bootloader_hooks_include`
# within hooks.c source file.
