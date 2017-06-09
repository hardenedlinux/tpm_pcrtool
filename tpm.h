/* 
 * tpm.h
 * Functions to operate TPM.
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

#ifndef _TPM_H_
#define _TPM_H_

#ifdef __cplusplus
extern "C" {
#if 0
}
#endif
#endif

#include <stdio.h>
#include <stdlib.h>
#include <tss/tss_error.h>
#include <tss/platform.h>
#include <tss/tss_defines.h>
#include <tss/tss_typedef.h>
#include <tss/tss_structs.h>
#include <tss/tspi.h>
#include <trousers/trousers.h>
#include <trousers/tss.h>

#define PCRSIZE 20

typedef char PCR[PCRSIZE];

static inline TSS_RESULT errout(const char* message, TSS_RESULT res)
{
#ifdef TSS_DEBUG
  fprintf(stderr, "Line%d, %s: %s returned 0x%08x. %s.\n",
	  __LINE__, __func__, message, res,
	  (const char *)Trspi_Error_String(res));
#endif
  return res;
}



typedef struct TSS_BASIC_HANDLES {
  TSS_HOBJECT ctx;
  TSS_HOBJECT tpm;
}TSS_BASIC_HANDLES;

TSS_RESULT tss_basic_handle_init(TSS_BASIC_HANDLES* hdls);
TSS_RESULT tss_basic_handle_uninit(TSS_BASIC_HANDLES* hdls);
int fprintpcr(FILE* fp, uint32_t pcr_index, const PCR* pcr_content);

static inline void tss_basic_handle_freemem(TSS_BASIC_HANDLES hdls, void* ptr)
{
  Tspi_Context_FreeMemory(hdls.ctx, ptr);
}

static inline TSS_RESULT readpcr(TSS_BASIC_HANDLES hdls, uint32_t pcr_index, uint32_t* pcrvlen, char** pcrvalue)
{
  return Tspi_TPM_PcrRead(hdls.tpm, pcr_index, pcrvlen, (BYTE**)pcrvalue);
  //free *pcrvalue with tss_basic_handle_freemem
}

TSS_RESULT extendpcr(TSS_BASIC_HANDLES hdls,
		     uint32_t pcr_index,
		     const char* data,
		     uint32_t datalen,
		     uint32_t* newvlen,
		     char** newvalue);


TSS_RESULT resetpcr(TSS_BASIC_HANDLES hdls, uint32_t pcr_index);

#ifdef __cplusplus
#if 0
{
#endif
}
#endif

#endif
