/* Unicorn Emulator Engine */
/* By Nguyen Anh Quynh, 2015 */

/* Sample code to demonstrate how to emulate RISC-V code */

#include <unicorn/unicorn.h>
#include <string.h>

// code to be emulated
#define RISCV_CODE "\x93\xE0\xF0\x7F" // ori $x1, $x1, 0xFF;

// memory address where emulation starts
#define START_ADDRESS 0x10000

static void hook_block(uc_engine *uc, uint64_t address, uint32_t size, void *user_data)
{
    printf(">>> Tracing basic block at 0x%" PRIx64 ", block size = 0x%x\n", address, size);
}

static void hook_code(uc_engine *uc, uint64_t address, uint32_t size, void *user_data)
{
    printf(">>> Tracing instruction at 0x%" PRIx64 ", instruction size = 0x%x\n", address, size);
}

static void test_riscv32(void)
{
    uc_engine *uc;
    uc_err err;
    uc_hook trace1, trace2;

    int x1 = 0x6789;     // X1 register

    printf("Emulate 32-bit RISC-V code\n");

    // Initialize emulator in RISC-V 32-bit mode
    err = uc_open(UC_ARCH_RISCV, UC_MODE_RISCV32, &uc);
    if (err) {
        printf("Failed on uc_open() with error returned: %u (%s)\n",
                err, uc_strerror(err));
        return;
    }

    // map 2MB memory for this emulation
    uc_mem_map(uc, START_ADDRESS, 2 * 1024 * 1024, UC_PROT_ALL);

    // write machine code to be emulated to memory
    uc_mem_write(uc, START_ADDRESS, RISCV_CODE, sizeof(RISCV_CODE) - 1);

    // initialize machine registers
    uc_reg_write(uc, UC_RISCV_REG_X1, &x1);

    // tracing all basic blocks with customized callback
    uc_hook_add(uc, &trace1, UC_HOOK_BLOCK, hook_block, NULL, 1, 0);

    // tracing one instruction at START_ADDRESS with customized callback
    uc_hook_add(uc, &trace2, UC_HOOK_CODE, hook_code, NULL, START_ADDRESS, START_ADDRESS);

    // emulate machine code in infinite time (last param = 0), or when
    // finishing all the code.
    err = uc_emu_start(uc, START_ADDRESS, START_ADDRESS + sizeof(RISCV_CODE) - 1, 0, 0);
    if (err) {
        printf("Failed on uc_emu_start() with error returned: %u (%s)\n", err, uc_strerror(err));
    }

    // now print out some registers
    printf(">>> Emulation done. Below is the CPU context\n");

    uc_reg_read(uc, UC_RISCV_REG_X1, &x1);
    printf(">>> X1 = 0x%08X\n", x1);

    uc_close(uc);
}

static void test_riscv64(void)
{
    uc_engine *uc;
    uc_err err;
    uc_hook trace1, trace2;

    int x1 = 0x6789;     // X1 register

    printf("===========================\n");
    printf("Emulate 64-bit RISC-V code\n");

    // Initialize emulator in RISC-V 64-bit mode
    err = uc_open(UC_ARCH_RISCV, UC_MODE_RISCV64, &uc);
    if (err) {
        printf("Failed on uc_open() with error returned: %u (%s)\n",
                err, uc_strerror(err));
        return;
    }

    // map 2MB memory for this emulation
    uc_mem_map(uc, START_ADDRESS, 2 * 1024 * 1024, UC_PROT_ALL);

    // write machine code to be emulated to memory
    uc_mem_write(uc, START_ADDRESS, RISCV_CODE, sizeof(RISCV_CODE) - 1);

    // initialize machine registers
    uc_reg_write(uc, UC_RISCV_REG_X1, &x1);

    // tracing all basic blocks with customized callback
    uc_hook_add(uc, &trace1, UC_HOOK_BLOCK, hook_block, NULL, 1, 0);

    // tracing one instruction at START_ADDRESS with customized callback
    uc_hook_add(uc, &trace2, UC_HOOK_CODE, hook_code, NULL, START_ADDRESS, START_ADDRESS);

    // emulate machine code in infinite time (last param = 0), or when
    // finishing all the code.
    err = uc_emu_start(uc, START_ADDRESS, START_ADDRESS + sizeof(RISCV_CODE) - 1, 0, 0);
    if (err) {
        printf("Failed on uc_emu_start() with error returned: %u (%s)\n", err, uc_strerror(err));
    }

    // now print out some registers
    printf(">>> Emulation done. Below is the CPU context\n");

    uc_reg_read(uc, UC_RISCV_REG_X1, &x1);
    printf(">>> X1 = 0x%08X\n", x1);

    uc_close(uc);
}

int main(int argc, char **argv, char **envp)
{
    // dynamically load shared library
#ifdef DYNLOAD
    if (!uc_dyn_load(NULL, 0)) {
        printf("Error dynamically loading shared library.\n");
        printf("Please check that unicorn.dll/unicorn.so is available as well as\n");
        printf("any other dependent dll/so files.\n");
        printf("The easiest way is to place them in the same directory as this app.\n");
        return 1;
    }
#endif

    test_riscv32();
    test_riscv64();

    // dynamically free shared library
#ifdef DYNLOAD
    uc_dyn_free();
#endif

    return 0;
}
