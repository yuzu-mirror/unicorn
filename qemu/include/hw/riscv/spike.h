#ifndef HW_RISCV_SPIKE_H
#define HW_RISCV_SPIKE_H

#if defined(TARGET_RISCV32)
#define SPIKE_V1_09_1_CPU TYPE_RISCV_CPU_RV32GCSU_V1_09_1
#define SPIKE_V1_10_0_CPU TYPE_RISCV_CPU_RV32GCSU_V1_10_0
#elif defined(TARGET_RISCV64)
#define SPIKE_V1_09_1_CPU TYPE_RISCV_CPU_RV64GCSU_V1_09_1
#define SPIKE_V1_10_0_CPU TYPE_RISCV_CPU_RV64GCSU_V1_10_0
#endif

void spike_v1_10_0_machine_init_register_types(struct uc_struct *uc);

#endif /* HW_RISCV_SPIKE_H */
