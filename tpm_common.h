/* 
 * tpm_common.h
 * Common interface to operate TPM (1 or 2).
 * 
 *
 * The program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public
 * License as published by the Free Software Foundation; either
 * version 3 of the License, or (at your option) any later version.
 *
 * The program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public
 * License along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301  USA 
 *
 * In addition, as a special exception, the copyright holders give
 * permission to link the code of portions of this program with the
 * OpenSSL library under certain conditions as described in each
 * individual source file, and distribute linked combinations
 * including the two.
 *
 * You must obey the GNU General Public License in all respects
 * for all of the code used other than OpenSSL.  If you modify
 * file(s) with this exception, you may extend this exception to your
 * version of the file(s), but you are not obligated to do so.  If you
 * do not wish to do so, delete this exception statement from your
 * version.  If you delete this exception statement from all source
 * files in the program, then also delete it here.
 */

#ifndef _TPM_COMMON_H_
#define _TPM_COMMON_H_

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <assert.h>
#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#if 0
}
#endif
#endif

#define PCRSIZE 64

typedef struct pcr {
  char s;
  char a[PCRSIZE];
} pcr;

int fprintpcr(FILE* fp, uint32_t pcr_index, const pcr* pcr_content);

typedef struct pcr_vtbl pcr_vtbl;
typedef struct tpm2_spec_vtbl tpm2_spec_vtbl;

#define FP_tpm_errout(x) uint32_t (x)(const char* message, uint32_t ret)
typedef FP_tpm_errout(fp_tpm_errout);

typedef struct pcr_context_base {
  const pcr_vtbl* vtbl;
  union {
    uintptr_t privdata[2];
  };
} pcr_context_base;

// functions to implement for both tpm1 and tpm2

#define FP_ctx_init(x) uint32_t (x)(pcr_context_base* ctx, const pcr_vtbl* vtbl)
typedef FP_ctx_init(fp_ctx_init);

#define FP_ctx_uninit(x) uint32_t (x)(pcr_context_base* ctx)
typedef FP_ctx_uninit(fp_ctx_uninit);

#define FP_ctx_freemem(x) void (x)(pcr_context_base* ctx, void* ptr)
typedef FP_ctx_freemem(fp_ctx_freemem);

#define FP_pcr_read(x) uint32_t (x)(pcr_context_base* ctx, \
				    uint32_t pcr_index,	   \
				    pcr* pcrvalue)
typedef FP_pcr_read(fp_pcr_read);

#define FP_pcr_extend(x) uint32_t (x)(pcr_context_base* ctx, \
				      uint32_t pcr_index,    \
				      const char* data,	     \
				      uint32_t datalen,	     \
				      pcr* newvalue)
typedef FP_pcr_extend(fp_pcr_extend);

#define FP_pcr_reset(x) uint32_t (x)(pcr_context_base* ctx, \
				     uint32_t pcr_index)
typedef FP_pcr_reset(fp_pcr_reset);

// functions to implement only for tpm2

#define FP_ctx_setalg(x)				\
  void (x)(pcr_context_base* ctx,			\
	       uint32_t alg)
typedef FP_ctx_setalg(fp_ctx_setalg);

#define FP_pcr_setalg(x)				\
  uint32_t (x)(pcr_context_base* ctx,			\
	       const void* selection)
typedef FP_pcr_setalg(fp_pcr_setalg);

typedef struct tpm2_spec_vtbl tpm2_spec_vtbl;

struct pcr_vtbl {
  const char* tpm_version;
  const tpm2_spec_vtbl* vt2;

  fp_tpm_errout* errout;
  fp_ctx_init* ctx_init;
  fp_ctx_uninit* ctx_uninit;
  fp_ctx_freemem* ctx_freemem;
  fp_pcr_read* pcr_read;
  fp_pcr_extend* pcr_extend;
  fp_pcr_reset* pcr_reset;
};

struct tpm2_spec_vtbl {
  fp_ctx_setalg* ctx_setalg;
  fp_pcr_setalg* pcr_setalg;
};

static inline bool vtbl_isvalid(const pcr_vtbl* t)
{
  return (t->tpm_version
	  && t->errout
	  && t->ctx_init
	  && t->ctx_uninit
	  && t->ctx_freemem
	  && t->pcr_read
	  && t->pcr_extend
	  && t->pcr_reset);
}

static inline int tpm_errout(const pcr_context_base* ctx,
			 const char* message,
			 uint32_t ret)
{
  return ctx->vtbl->errout(message, ret);
}

static inline FP_ctx_init(tpm_ctx_init)
{
  assert(vtbl != NULL);
  assert(vtbl_isvalid(vtbl));
  ctx->vtbl = vtbl;
  return ctx->vtbl->ctx_init(ctx, vtbl);
}

static inline FP_ctx_uninit(tpm_ctx_uninit)
{
  return ctx->vtbl->ctx_uninit(ctx);
}

static inline FP_ctx_freemem(tpm_ctx_freemem)
{
  return ctx->vtbl->ctx_freemem(ctx, ptr);
}

static inline FP_pcr_read(tpm_pcr_read)
{
  return ctx->vtbl->pcr_read(ctx, 
			     pcr_index,
			     pcrvalue);
}

static inline FP_pcr_extend(tpm_pcr_extend)
{
  return ctx->vtbl->pcr_extend(ctx,
			       pcr_index,
			       data,
			       datalen,
			       newvalue);
}

static inline FP_pcr_reset(tpm_pcr_reset)
{
  return ctx->vtbl->pcr_reset(ctx, pcr_index);
}

static inline FP_pcr_setalg(tpm_pcr_setalg)
{
  return ((ctx->vtbl->vt2)?
	  ctx->vtbl->vt2->pcr_setalg(ctx, selection):
	  0);
}

static inline FP_ctx_setalg(tpm_ctx_setalg)
{
  if(ctx->vtbl->vt2) {
    ctx->vtbl->vt2->ctx_setalg(ctx, alg);
  }
}

#ifdef __cplusplus
#if 0
{
#endif
}
#endif

#endif
