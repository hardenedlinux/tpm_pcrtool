/* 
 * tpm12.c
 * Functions to operate TPM 1.2.
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

#include <string.h>
#include "tpm12.h"

static FP_tpm_errout(tpm12_errout)
{
  fprintf(stderr, "%s returned 0x%08x. %s.\n",
	  message, ret, (const char *)Trspi_Error_String(ret));
  return ret;
}

//TSS_RESULT tss_basic_handle_init(TSS_BASIC_HANDLES* hdls)

static FP_ctx_init(tpm12_ctx_init)
{
  tpm12_pcr_context* ctx1 = (tpm12_pcr_context*)ctx;
  TSS_RESULT r = TSS_SUCCESS;
  r = tpm12_errout("Create Context",
		   Tspi_Context_Create(&ctx1->ctx));
  if (r != TSS_SUCCESS)
    return r;
  
  r = tpm12_errout("Context Connect",
		   Tspi_Context_Connect(ctx1->ctx, NULL));
  if (r != TSS_SUCCESS)
    return r;
  
  return tpm12_errout("Get TPM Handle",
		Tspi_Context_GetTpmObject(ctx1->ctx, &ctx1->tpm));
}

//TSS_RESULT tss_basic_handle_uninit(TSS_BASIC_HANDLES* hdls)
static FP_ctx_uninit(tpm12_ctx_uninit)
{
  tpm12_pcr_context* ctx1 = (tpm12_pcr_context*)ctx;
  TSS_RESULT r = TSS_SUCCESS;
  
  r = tpm12_errout("Free CTX-binded memories", Tspi_Context_FreeMemory(ctx1->ctx, NULL));
  if (r != TSS_SUCCESS)
    return r;
  
  r = tpm12_errout("Close CTX", Tspi_Context_Close(ctx1->ctx));
  
  ctx1->tpm = 0;
  ctx1->ctx = 0;

  return r;
}

static FP_ctx_freemem(tpm12_ctx_freemem)
{
  tpm12_pcr_context* ctx1 = (tpm12_pcr_context*)ctx;
  Tspi_Context_FreeMemory(ctx1->ctx, ptr);
}

static FP_pcr_read(tpm12_pcr_read)
{
  tpm12_pcr_context* ctx1 = (tpm12_pcr_context*)ctx;
  uint32_t l = 0;
  char* v = NULL;
  uint32_t ret = Tspi_TPM_PcrRead(ctx1->tpm,
				  pcr_index,
				  &l,
				  (BYTE**)&v);
  if((TSS_SUCCESS == ret)
     && (l == PCRSIZE)) {
    memcpy(pcrvalue->a, v, PCRSIZE);
  }

  if(v != NULL) {
    tpm12_ctx_freemem(ctx, v);
  }
  
  return ret;
}

/*TSS_RESULT extendpcr(TSS_BASIC_HANDLES hdls,
		     uint32_t pcr_index,
		     const char* data,
		     uint32_t datalen,
		     uint32_t* newvlen,
		     char** newvalue)*/
static FP_pcr_extend(tpm12_pcr_extend)
{
  tpm12_pcr_context* ctx1 = (tpm12_pcr_context*)ctx;  
  TSS_PCR_EVENT event;
  memset(&event, 0, sizeof(TSS_PCR_EVENT));
  event.ulPcrIndex = pcr_index;

  uint32_t l = 0;
  char* v = NULL;
  uint32_t ret = Tspi_TPM_PcrExtend(ctx1->tpm,
				    pcr_index,
				    datalen,
				    (BYTE*)data,
				    &event,
				    &l,
				    (BYTE**)&v);
  if((TSS_SUCCESS == ret)
     && (l == PCRSIZE)) {
    memcpy(newvalue->a, v, PCRSIZE);
  }

  if(v != NULL) {
    tpm12_ctx_freemem(ctx, v);
  }
  
  return ret;
}

//TSS_RESULT resetpcr(TSS_BASIC_HANDLES hdls, uint32_t pcr_index)
static FP_pcr_reset(tpm12_pcr_reset)
{
  tpm12_pcr_context* ctx1 = (tpm12_pcr_context*)ctx;
  TSS_HANDLE pcr_composite = 0;
  TSS_RESULT r = TSS_SUCCESS;
  r = Tspi_Context_CreateObject(ctx1->ctx, TSS_OBJECT_TYPE_PCRS,
			       0, &pcr_composite);
  if(r != TSS_SUCCESS)
    return r;
  do {
    r = Tspi_PcrComposite_SelectPcrIndex(pcr_composite, pcr_index);
    if(r != TSS_SUCCESS)
      break;
    
    r = Tspi_TPM_PcrReset(ctx1->tpm, pcr_composite);
  } while(0);

  TSS_RESULT rclose = Tspi_Context_CloseObject(ctx1->ctx, pcr_composite);
  
  return (rclose == TSS_SUCCESS)?r:rclose;
}

const pcr_vtbl tpm12_pcr_vtbl
= (pcr_vtbl) {
  "1.2",
  NULL,

  tpm12_errout,
  tpm12_ctx_init,
  tpm12_ctx_uninit,
  tpm12_ctx_freemem,
  tpm12_pcr_read,
  tpm12_pcr_extend,
  tpm12_pcr_reset
};
