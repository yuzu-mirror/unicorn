/*
 * RISC-V translation routines for the RVV Standard Extension.
 *
 * Copyright (c) 2020 T-Head Semiconductor Co., Ltd. All rights reserved.
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

static bool trans_vsetvl(DisasContext *ctx, arg_vsetvl *a)
{
    TCGContext *tcg_ctx = ctx->uc->tcg_ctx;
    TCGv s1, s2, dst;

    if (!has_ext(ctx, RVV)) {
        return false;
    }

    s2 = tcg_temp_new(tcg_ctx);
    dst = tcg_temp_new(tcg_ctx);

    /* Using x0 as the rs1 register specifier, encodes an infinite AVL */
    if (a->rs1 == 0) {
        /* As the mask is at least one bit, RV_VLEN_MAX is >= VLMAX */
        s1 = tcg_const_tl(tcg_ctx, RV_VLEN_MAX);
    } else {
        s1 = tcg_temp_new(tcg_ctx);
        gen_get_gpr(ctx, s1, a->rs1);
    }
    gen_get_gpr(ctx, s2, a->rs2);
    gen_helper_vsetvl(tcg_ctx, dst, tcg_ctx->cpu_env, s1, s2);
    gen_set_gpr(ctx, a->rd, dst);
    tcg_gen_movi_tl(tcg_ctx, tcg_ctx->cpu_pc_risc, ctx->pc_succ_insn);
    lookup_and_goto_ptr(ctx);
    ctx->base.is_jmp = DISAS_NORETURN;

    tcg_temp_free(tcg_ctx, s1);
    tcg_temp_free(tcg_ctx, s2);
    tcg_temp_free(tcg_ctx, dst);
    return true;
}

static bool trans_vsetvli(DisasContext *ctx, arg_vsetvli *a)
{
    TCGContext *tcg_ctx = ctx->uc->tcg_ctx;
    TCGv s1, s2, dst;

    if (!has_ext(ctx, RVV)) {
        return false;
    }

    s2 = tcg_const_tl(tcg_ctx, a->zimm);
    dst = tcg_temp_new(tcg_ctx);

    /* Using x0 as the rs1 register specifier, encodes an infinite AVL */
    if (a->rs1 == 0) {
        /* As the mask is at least one bit, RV_VLEN_MAX is >= VLMAX */
        s1 = tcg_const_tl(tcg_ctx, RV_VLEN_MAX);
    } else {
        s1 = tcg_temp_new(tcg_ctx);
        gen_get_gpr(ctx, s1, a->rs1);
    }
    gen_helper_vsetvl(tcg_ctx, dst, tcg_ctx->cpu_env, s1, s2);
    gen_set_gpr(ctx, a->rd, dst);
    gen_goto_tb(ctx, 0, ctx->pc_succ_insn);
    ctx->base.is_jmp = DISAS_NORETURN;

    tcg_temp_free(tcg_ctx, s1);
    tcg_temp_free(tcg_ctx, s2);
    tcg_temp_free(tcg_ctx, dst);
    return true;
}
