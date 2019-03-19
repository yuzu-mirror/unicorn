/*
 * RISC-V translation routines for the RVXI Base Integer Instruction Set.
 *
 * Copyright (c) 2016-2017 Sagar Karandikar, sagark@eecs.berkeley.edu
 * Copyright (c) 2018 Peer Adelt, peer.adelt@hni.uni-paderborn.de
 *                    Bastian Koppelmann, kbastian@mail.uni-paderborn.de
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms and conditions of the GNU General Public License,
 * version 2 or later, as published by the Free Software Foundation.
 *
 * This program is distributed in the hope it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License for
 * more details.
 *
 * You should have received a copy of the GNU General Public License along with
 * this program.  If not, see <http://www.gnu.org/licenses/>.
 */

static bool trans_lui(DisasContext *ctx, arg_lui *a)
{
    if (a->rd != 0) {
        TCGContext *tcg_ctx = ctx->uc->tcg_ctx;
        tcg_gen_movi_tl(tcg_ctx, tcg_ctx->cpu_gpr_risc[a->rd], a->imm);
    }
    return true;
}

static bool trans_auipc(DisasContext *ctx, arg_auipc *a)
{
    if (a->rd != 0) {
        TCGContext *tcg_ctx = ctx->uc->tcg_ctx;
        tcg_gen_movi_tl(tcg_ctx, tcg_ctx->cpu_gpr_risc[a->rd], a->imm + ctx->base.pc_next);
    }
    return true;
}

static bool trans_jal(DisasContext *ctx, arg_jal *a)
{
    gen_jal(ctx, a->rd, a->imm);
    return true;
}

static bool trans_jalr(DisasContext *ctx, arg_jalr *a)
{
    TCGContext *tcg_ctx = ctx->uc->tcg_ctx;

    /* no chaining with JALR */
    TCGLabel *misaligned = NULL;
    TCGv t0 = tcg_temp_new(tcg_ctx);

    gen_get_gpr(ctx, tcg_ctx->cpu_pc_risc, a->rs1);
    tcg_gen_addi_tl(tcg_ctx, tcg_ctx->cpu_pc_risc, tcg_ctx->cpu_pc_risc, a->imm);
    tcg_gen_andi_tl(tcg_ctx, tcg_ctx->cpu_pc_risc, tcg_ctx->cpu_pc_risc, (target_ulong)-2);

    if (!has_ext(ctx, RVC)) {
        misaligned = gen_new_label(tcg_ctx);
        tcg_gen_andi_tl(tcg_ctx, t0, tcg_ctx->cpu_pc_risc, 0x2);
        tcg_gen_brcondi_tl(tcg_ctx, TCG_COND_NE, t0, 0x0, misaligned);
    }

    if (a->rd != 0) {
        tcg_gen_movi_tl(tcg_ctx, tcg_ctx->cpu_gpr_risc[a->rd], ctx->pc_succ_insn);
    }
    tcg_gen_lookup_and_goto_ptr(tcg_ctx);

    if (misaligned) {
        gen_set_label(tcg_ctx, misaligned);
        gen_exception_inst_addr_mis(ctx);
    }
    ctx->base.is_jmp = DISAS_NORETURN;

    tcg_temp_free(tcg_ctx, t0);
    return true;
}

static bool gen_branch(DisasContext *ctx, arg_b *a, TCGCond cond)
{
    TCGContext *tcg_ctx = ctx->uc->tcg_ctx;

    TCGLabel *l = gen_new_label(tcg_ctx);
    TCGv source1, source2;
    source1 = tcg_temp_new(tcg_ctx);
    source2 = tcg_temp_new(tcg_ctx);
    gen_get_gpr(ctx, source1, a->rs1);
    gen_get_gpr(ctx, source2, a->rs2);

    tcg_gen_brcond_tl(tcg_ctx, cond, source1, source2, l);
    gen_goto_tb(ctx, 1, ctx->pc_succ_insn);
    gen_set_label(tcg_ctx, l); /* branch taken */

    if (!has_ext(ctx, RVC) && ((ctx->base.pc_next + a->imm) & 0x3)) {
        /* misaligned */
        gen_exception_inst_addr_mis(ctx);
    } else {
        gen_goto_tb(ctx, 0, ctx->base.pc_next + a->imm);
    }
    ctx->base.is_jmp = DISAS_NORETURN;

    tcg_temp_free(tcg_ctx, source1);
    tcg_temp_free(tcg_ctx, source2);

    return true;
}

static bool trans_beq(DisasContext *ctx, arg_beq *a)
{
    return gen_branch(ctx, a, TCG_COND_EQ);
}

static bool trans_bne(DisasContext *ctx, arg_bne *a)
{
    return gen_branch(ctx, a, TCG_COND_NE);
}

static bool trans_blt(DisasContext *ctx, arg_blt *a)
{
    return gen_branch(ctx, a, TCG_COND_LT);
}

static bool trans_bge(DisasContext *ctx, arg_bge *a)
{
    return gen_branch(ctx, a, TCG_COND_GE);
}

static bool trans_bltu(DisasContext *ctx, arg_bltu *a)
{
    return gen_branch(ctx, a, TCG_COND_LTU);
}

static bool trans_bgeu(DisasContext *ctx, arg_bgeu *a)
{
    return gen_branch(ctx, a, TCG_COND_GEU);
}

static bool gen_load(DisasContext *ctx, arg_lb *a, TCGMemOp memop)
{
    TCGContext *tcg_ctx = ctx->uc->tcg_ctx;

    TCGv t0 = tcg_temp_new(tcg_ctx);
    TCGv t1 = tcg_temp_new(tcg_ctx);
    gen_get_gpr(ctx, t0, a->rs1);
    tcg_gen_addi_tl(tcg_ctx, t0, t0, a->imm);

    tcg_gen_qemu_ld_tl(ctx->uc, t1, t0, ctx->mem_idx, memop);
    gen_set_gpr(ctx, a->rd, t1);
    tcg_temp_free(tcg_ctx, t0);
    tcg_temp_free(tcg_ctx, t1);
    return true;
}

static bool trans_lb(DisasContext *ctx, arg_lb *a)
{
    return gen_load(ctx, a, MO_SB);
}

static bool trans_lh(DisasContext *ctx, arg_lh *a)
{
    return gen_load(ctx, a, MO_TESW);
}

static bool trans_lw(DisasContext *ctx, arg_lw *a)
{
    return gen_load(ctx, a, MO_TESL);
}

static bool trans_lbu(DisasContext *ctx, arg_lbu *a)
{
    return gen_load(ctx, a, MO_UB);
}

static bool trans_lhu(DisasContext *ctx, arg_lhu *a)
{
    return gen_load(ctx, a, MO_TEUW);
}

static bool gen_store(DisasContext *ctx, arg_sb *a, TCGMemOp memop)
{
    TCGContext *tcg_ctx = ctx->uc->tcg_ctx;

    TCGv t0 = tcg_temp_new(tcg_ctx);
    TCGv dat = tcg_temp_new(tcg_ctx);
    gen_get_gpr(ctx, t0, a->rs1);
    tcg_gen_addi_tl(tcg_ctx, t0, t0, a->imm);
    gen_get_gpr(ctx, dat, a->rs2);

    tcg_gen_qemu_st_tl(ctx->uc, dat, t0, ctx->mem_idx, memop);
    tcg_temp_free(tcg_ctx, t0);
    tcg_temp_free(tcg_ctx, dat);
    return true;
}

static bool trans_sb(DisasContext *ctx, arg_sb *a)
{
    return gen_store(ctx, a, MO_SB);
}

static bool trans_sh(DisasContext *ctx, arg_sh *a)
{
    return gen_store(ctx, a, MO_TESW);
}

static bool trans_sw(DisasContext *ctx, arg_sw *a)
{
    return gen_store(ctx, a, MO_TESL);
}

#ifdef TARGET_RISCV64
static bool trans_lwu(DisasContext *ctx, arg_lwu *a)
{
    return gen_load(ctx, a, MO_TEUL);
}

static bool trans_ld(DisasContext *ctx, arg_ld *a)
{
    return gen_load(ctx, a, MO_TEQ);
}

static bool trans_sd(DisasContext *ctx, arg_sd *a)
{
    return gen_store(ctx, a, MO_TEQ);
}
#endif

static bool trans_addi(DisasContext *ctx, arg_addi *a)
{
    gen_arith_imm(ctx, OPC_RISC_ADDI, a->rd, a->rs1, a->imm);
    return true;
}

static bool trans_slti(DisasContext *ctx, arg_slti *a)
{
    gen_arith_imm(ctx, OPC_RISC_SLTI, a->rd, a->rs1, a->imm);
    return true;
}

static bool trans_sltiu(DisasContext *ctx, arg_sltiu *a)
{
    gen_arith_imm(ctx, OPC_RISC_SLTIU, a->rd, a->rs1, a->imm);
    return true;
}

static bool trans_xori(DisasContext *ctx, arg_xori *a)
{
    gen_arith_imm(ctx, OPC_RISC_XORI, a->rd, a->rs1, a->imm);
    return true;
}
static bool trans_ori(DisasContext *ctx, arg_ori *a)
{
    gen_arith_imm(ctx, OPC_RISC_ORI, a->rd, a->rs1, a->imm);
    return true;
}
static bool trans_andi(DisasContext *ctx, arg_andi *a)
{
    gen_arith_imm(ctx, OPC_RISC_ANDI, a->rd, a->rs1, a->imm);
    return true;
}
static bool trans_slli(DisasContext *ctx, arg_slli *a)
{
    gen_arith_imm(ctx, OPC_RISC_SLLI, a->rd, a->rs1, a->shamt);
    return true;
}

static bool trans_srli(DisasContext *ctx, arg_srli *a)
{
    gen_arith_imm(ctx, OPC_RISC_SHIFT_RIGHT_I, a->rd, a->rs1, a->shamt);
    return true;
}

static bool trans_srai(DisasContext *ctx, arg_srai *a)
{
    gen_arith_imm(ctx, OPC_RISC_SHIFT_RIGHT_I, a->rd, a->rs1, a->shamt | 0x400);
    return true;
}

static bool trans_add(DisasContext *ctx, arg_add *a)
{
    gen_arith(ctx, OPC_RISC_ADD, a->rd, a->rs1, a->rs2);
    return true;
}

static bool trans_sub(DisasContext *ctx, arg_sub *a)
{
    gen_arith(ctx, OPC_RISC_SUB, a->rd, a->rs1, a->rs2);
    return true;
}

static bool trans_sll(DisasContext *ctx, arg_sll *a)
{
    gen_arith(ctx, OPC_RISC_SLL, a->rd, a->rs1, a->rs2);
    return true;
}

static bool trans_slt(DisasContext *ctx, arg_slt *a)
{
    gen_arith(ctx, OPC_RISC_SLT, a->rd, a->rs1, a->rs2);
    return true;
}

static bool trans_sltu(DisasContext *ctx, arg_sltu *a)
{
    gen_arith(ctx, OPC_RISC_SLTU, a->rd, a->rs1, a->rs2);
    return true;
}

static bool trans_xor(DisasContext *ctx, arg_xor *a)
{
    gen_arith(ctx, OPC_RISC_XOR, a->rd, a->rs1, a->rs2);
    return true;
}

static bool trans_srl(DisasContext *ctx, arg_srl *a)
{
    gen_arith(ctx, OPC_RISC_SRL, a->rd, a->rs1, a->rs2);
    return true;
}

static bool trans_sra(DisasContext *ctx, arg_sra *a)
{
    gen_arith(ctx, OPC_RISC_SRA, a->rd, a->rs1, a->rs2);
    return true;
}

static bool trans_or(DisasContext *ctx, arg_or *a)
{
    gen_arith(ctx, OPC_RISC_OR, a->rd, a->rs1, a->rs2);
    return true;
}

static bool trans_and(DisasContext *ctx, arg_and *a)
{
    gen_arith(ctx, OPC_RISC_AND, a->rd, a->rs1, a->rs2);
    return true;
}

#ifdef TARGET_RISCV64
static bool trans_addiw(DisasContext *ctx, arg_addiw *a)
{
    gen_arith_imm(ctx, OPC_RISC_ADDIW, a->rd, a->rs1, a->imm);
    return true;
}

static bool trans_slliw(DisasContext *ctx, arg_slliw *a)
{
    gen_arith_imm(ctx, OPC_RISC_SLLIW, a->rd, a->rs1, a->shamt);
    return true;
}

static bool trans_srliw(DisasContext *ctx, arg_srliw *a)
{
    gen_arith_imm(ctx, OPC_RISC_SHIFT_RIGHT_IW, a->rd, a->rs1, a->shamt);
    return true;
}

static bool trans_sraiw(DisasContext *ctx, arg_sraiw *a)
{
    gen_arith_imm(ctx, OPC_RISC_SHIFT_RIGHT_IW , a->rd, a->rs1,
                  a->shamt | 0x400);
    return true;
}

static bool trans_addw(DisasContext *ctx, arg_addw *a)
{
    gen_arith(ctx, OPC_RISC_ADDW, a->rd, a->rs1, a->rs2);
    return true;
}

static bool trans_subw(DisasContext *ctx, arg_subw *a)
{
    gen_arith(ctx, OPC_RISC_SUBW, a->rd, a->rs1, a->rs2);
    return true;
}

static bool trans_sllw(DisasContext *ctx, arg_sllw *a)
{
    gen_arith(ctx, OPC_RISC_SLLW, a->rd, a->rs1, a->rs2);
    return true;
}

static bool trans_srlw(DisasContext *ctx, arg_srlw *a)
{
    gen_arith(ctx, OPC_RISC_SRLW, a->rd, a->rs1, a->rs2);
    return true;
}

static bool trans_sraw(DisasContext *ctx, arg_sraw *a)
{
    gen_arith(ctx, OPC_RISC_SRAW, a->rd, a->rs1, a->rs2);
    return true;
}
#endif

static bool trans_fence(DisasContext *ctx, arg_fence *a)
{
    TCGContext *tcg_ctx = ctx->uc->tcg_ctx;

    /* FENCE is a full memory barrier. */
    tcg_gen_mb(tcg_ctx, TCG_MO_ALL | TCG_BAR_SC);
    return true;
}

static bool trans_fence_i(DisasContext *ctx, arg_fence_i *a)
{
    TCGContext *tcg_ctx = ctx->uc->tcg_ctx;

    /*
     * FENCE_I is a no-op in QEMU,
     * however we need to end the translation block
     */
    tcg_gen_movi_tl(tcg_ctx, tcg_ctx->cpu_pc_risc, ctx->pc_succ_insn);
    tcg_gen_exit_tb(tcg_ctx, NULL, 0);
    ctx->base.is_jmp = DISAS_NORETURN;
    return true;
}

#define RISCV_OP_CSR_PRE do {\
    source1 = tcg_temp_new(tcg_ctx); \
    csr_store = tcg_temp_new(tcg_ctx); \
    dest = tcg_temp_new(tcg_ctx); \
    rs1_pass = tcg_temp_new(tcg_ctx); \
    gen_get_gpr(ctx, source1, a->rs1); \
    tcg_gen_movi_tl(tcg_ctx, tcg_ctx->cpu_pc_risc, ctx->base.pc_next); \
    tcg_gen_movi_tl(tcg_ctx, rs1_pass, a->rs1); \
    tcg_gen_movi_tl(tcg_ctx, csr_store, a->csr); \
} while (0)

#define RISCV_OP_CSR_POST do {\
    gen_set_gpr(ctx, a->rd, dest); \
    tcg_gen_movi_tl(tcg_ctx, tcg_ctx->cpu_pc_risc, ctx->pc_succ_insn); \
    tcg_gen_exit_tb(tcg_ctx, NULL, 0); \
    ctx->base.is_jmp = DISAS_NORETURN; \
    tcg_temp_free(tcg_ctx, source1); \
    tcg_temp_free(tcg_ctx, csr_store); \
    tcg_temp_free(tcg_ctx, dest); \
    tcg_temp_free(tcg_ctx, rs1_pass); \
} while (0)


static bool trans_csrrw(DisasContext *ctx, arg_csrrw *a)
{
    TCGContext *tcg_ctx = ctx->uc->tcg_ctx;
    TCGv source1, csr_store, dest, rs1_pass;
    RISCV_OP_CSR_PRE;
    gen_helper_csrrw(tcg_ctx, dest, tcg_ctx->cpu_env, source1, csr_store);
    RISCV_OP_CSR_POST;
    return true;
}

static bool trans_csrrs(DisasContext *ctx, arg_csrrs *a)
{
    TCGContext *tcg_ctx = ctx->uc->tcg_ctx;
    TCGv source1, csr_store, dest, rs1_pass;
    RISCV_OP_CSR_PRE;
    gen_helper_csrrs(tcg_ctx, dest, tcg_ctx->cpu_env, source1, csr_store, rs1_pass);
    RISCV_OP_CSR_POST;
    return true;
}

static bool trans_csrrc(DisasContext *ctx, arg_csrrc *a)
{
    TCGContext *tcg_ctx = ctx->uc->tcg_ctx;
    TCGv source1, csr_store, dest, rs1_pass;
    RISCV_OP_CSR_PRE;
    gen_helper_csrrc(tcg_ctx, dest, tcg_ctx->cpu_env, source1, csr_store, rs1_pass);
    RISCV_OP_CSR_POST;
    return true;
}

static bool trans_csrrwi(DisasContext *ctx, arg_csrrwi *a)
{
    TCGContext *tcg_ctx = ctx->uc->tcg_ctx;
    TCGv source1, csr_store, dest, rs1_pass;
    RISCV_OP_CSR_PRE;
    gen_helper_csrrw(tcg_ctx, dest, tcg_ctx->cpu_env, rs1_pass, csr_store);
    RISCV_OP_CSR_POST;
    return true;
}

static bool trans_csrrsi(DisasContext *ctx, arg_csrrsi *a)
{
    TCGContext *tcg_ctx = ctx->uc->tcg_ctx;
    TCGv source1, csr_store, dest, rs1_pass;
    RISCV_OP_CSR_PRE;
    gen_helper_csrrs(tcg_ctx, dest, tcg_ctx->cpu_env, rs1_pass, csr_store, rs1_pass);
    RISCV_OP_CSR_POST;
    return true;
}

static bool trans_csrrci(DisasContext *ctx, arg_csrrci *a)
{
    TCGContext *tcg_ctx = ctx->uc->tcg_ctx;
    TCGv source1, csr_store, dest, rs1_pass;
    RISCV_OP_CSR_PRE;
    gen_helper_csrrc(tcg_ctx, dest, tcg_ctx->cpu_env, rs1_pass, csr_store, rs1_pass);
    RISCV_OP_CSR_POST;
    return true;
}
