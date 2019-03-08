/* Unicorn Emulator Engine */
/* By Nguyen Anh Quynh <aquynh@gmail.com> */

#ifndef UC_QEMU_TARGET_RISCV_H
#define UC_QEMU_TARGET_RISCV_H

void riscv32_uc_init(struct uc_struct *uc);
void riscv64_uc_init(struct uc_struct *uc);

extern const int RISCV32_REGS_STORAGE_SIZE_riscv32;
extern const int RISCV64_REGS_STORAGE_SIZE_riscv64;

#endif
