/* 
 * tpm.c
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

#include <string.h>
#include "tpm.h"

TSS_RESULT tss_basic_handle_init(TSS_BASIC_HANDLES* hdls)
{
  TSS_RESULT r = TSS_SUCCESS;
  r = errout("Create Context",
	     Tspi_Context_Create(&hdls->ctx));
  if (r != TSS_SUCCESS)
    return r;
  
  r = errout("Context Connect",
	     Tspi_Context_Connect(hdls->ctx, NULL));
  if (r != TSS_SUCCESS)
    return r;
  
  return errout("Get TPM Handle",
		Tspi_Context_GetTpmObject(hdls->ctx, &hdls->tpm));
}

TSS_RESULT tss_basic_handle_uninit(TSS_BASIC_HANDLES* hdls)
{
  TSS_RESULT r = TSS_SUCCESS;
  
  r = errout("Free CTX-binded memories", Tspi_Context_FreeMemory(hdls->ctx, NULL));
  if (r != TSS_SUCCESS)
    return r;
  
  r = errout("Close CTX", Tspi_Context_Close(hdls->ctx));
  
  hdls->tpm = 0;
  hdls->ctx = 0;

  return r;
}



int fprintpcr(FILE* fp, uint32_t pcr_index, const PCR* pcr_content)
{
  int res = 0;
  res += fprintf(fp, "PCR %u:", pcr_index);
  {
    int i;
    for(i = 0; i < sizeof(*pcr_content); i++){
      res += fprintf(fp, ":%02hhx", (*pcr_content)[i]);
    }
  }
  res += fprintf(fp, "\n");
  return res;
}

TSS_RESULT extendpcr(TSS_BASIC_HANDLES hdls,
		     uint32_t pcr_index,
		     const char* data,
		     uint32_t datalen,
		     uint32_t* newvlen,
		     char** newvalue)
{
  TSS_PCR_EVENT event;
  memset(&event, 0, sizeof(TSS_PCR_EVENT));
  event.ulPcrIndex = pcr_index;
  
  return Tspi_TPM_PcrExtend(hdls.tpm, pcr_index, datalen, (BYTE*)data,
			    &event, newvlen, (BYTE**)newvalue);
}

TSS_RESULT resetpcr(TSS_BASIC_HANDLES hdls, uint32_t pcr_index)
{
  TSS_HANDLE pcr_composite = 0;
  TSS_RESULT r = TSS_SUCCESS;
  r = Tspi_Context_CreateObject(hdls.ctx, TSS_OBJECT_TYPE_PCRS,
			       0, &pcr_composite);
  if(r != TSS_SUCCESS)
    return r;
  do {
    r = Tspi_PcrComposite_SelectPcrIndex(pcr_composite, pcr_index);
    if(r != TSS_SUCCESS)
      break;
    
    r = Tspi_TPM_PcrReset(hdls.tpm, pcr_composite);
  } while(0);

  TSS_RESULT rclose = Tspi_Context_CloseObject(hdls.ctx, pcr_composite);
  
  return (rclose == TSS_SUCCESS)?r:rclose;
}
