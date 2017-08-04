/* 
 * tpm2.c
 * Functions to operate TPM 2.
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

#include "tpm2.h"
#include "tpm2_md_alg.h"
#include <stdarg.h>
#include <stdio.h>

/*
 * Contrast to tpm1.2, in which fed data to extend pcr's content can have 
 * arbitrary length (with a maximum, indeed), in tpm2, such data must have
 * a length identical to the digest size of the algorithm to be used in the
 * extention process, so we must implement a list of supported algorithm,
 * to meet such limitation.
 */

static const tpm2_hashalg_list_item tpm2_hashalg_supported[] = {
#ifdef TPM_ALG_SHA
  {"sha", TPM_ALG_SHA},
#endif
#ifdef TPM_ALG_SHA1
  {"sha1", TPM_ALG_SHA1},
#endif
#ifdef TPM_ALG_SHA256
  {"sha256", TPM_ALG_SHA256},
#endif
#ifdef TPM_ALG_SHA384
  {"sha384", TPM_ALG_SHA384},
#endif
#ifdef TPM_ALG_SHA512
  {"sha512", TPM_ALG_SHA512},
#endif
  {NULL, 0}
};

//This function below is exported via tpm2_me_alg.h.

const tpm2_hashalg_list_item* MD_tpm2_checksupport(const char* mdname)
{
  const tpm2_hashalg_list_item* candidate = tpm2_hashalg_supported;
  for(;candidate->name != NULL; candidate ++) {
    if(0 == strcmp(mdname, candidate->name)) {
      return candidate;
    }
  }
  return NULL;
}

const TCTI_DEVICE_CONF localdev
= (TCTI_DEVICE_CONF) {
  "/dev/tpm0",
  NULL,
  NULL
};

const TCTI_SOCKET_CONF localsrv
= (TCTI_SOCKET_CONF) {
  "127.0.0.1",
  2323,
  NULL,
  NULL,
  NULL
};

static const TSS2_ABI_VERSION abiver
= (TSS2_ABI_VERSION){
  TSSWG_INTEROP,
  TSS_SAPI_FIRST_FAMILY,
  TSS_SAPI_FIRST_LEVEL,
  TSS_SAPI_FIRST_LEVEL
};

/*
 * In tpm2, there are multiple "banks" of digest algorithm, each of which
 * has 24 pcrs, which operabilities could be configured independently, but
 * the latter command to configure EVERY pcrs on EVERY banks would override
 * the former, which means it is unable to set pcr one by one, instead, all
 * pcrs should be configured with one single command. To do so, we need a
 * string representation of TPML_PCR_SELECTION for HUMAN invokers to use,
 * and a function to parse it to the binary representation.
 *
 * The string representation is described in pcrtool.c, and the parser 
 * function is implemented below.
 *
 * This function below is exported via tpm2_me_alg.h.
 */

bool parse_selection(const char* s, size_t* count, void** selection)
{
  char alg[13];
  const char* finger = s;
  TPML_PCR_SELECTION* sel = (TPML_PCR_SELECTION*)calloc(1, sizeof(TPML_PCR_SELECTION));
  if(sel == NULL) {
    *count = 0;
    *selection = NULL;
    return false;
  }

  do {
    int ret = sscanf(finger, "%12[^:]", alg);
    finger = strchr(finger, ':');
    if(finger == NULL || ret != 1) break;
     
    ret = sscanf(finger,
		 ":%2hhx%2hhx%2hhx",
		 &sel->pcrSelections[sel->count].pcrSelect[2],
		 &sel->pcrSelections[sel->count].pcrSelect[1],
		 &sel->pcrSelections[sel->count].pcrSelect[0]);
    if(ret != 3) break;

    {
      //fill necessary items.
      const tpm2_hashalg_list_item* ialg = MD_tpm2_checksupport(alg);
      if(ialg == NULL) break;
      sel->pcrSelections[sel->count].hash = ialg->id;
      sel->pcrSelections[sel->count].sizeofSelect =
	sizeof(sel->pcrSelections[sel->count].pcrSelect);
      ++ sel->count;
      if(sel->count >= HASH_COUNT) break;
    }
    
    finger = strchr(finger, '+');
    if(finger == NULL) break;
    finger ++;
  } while (*finger != '\0');

  if(sel->count == 0) {
    free(sel);
    *count = 0;
    *selection = NULL;
    return false;
  }
  (*selection) = (void*)sel;
  (*count) = sel->count;
  return true;
}

/*
 * since tpm2 use callback to generate log,
 * we only provide a trivial 'errout'.
 */
static FP_tpm_errout(tpm2_errout)
{
  fprintf(stderr, "%s0x%x\n", message, ret);
  return ret;
}

static FP_ctx_init(tpm2_ctx_init)
{
  tpm2_pcr_context* ctx2 = (tpm2_pcr_context*)ctx;

  TSS2_TCTI_CONTEXT* tcti_vtbl = NULL;
  size_t tcti_vtbl_size = 0;
  TSS2_SYS_CONTEXT *sysctx = NULL;
  size_t sysctx_size = 0;
  TSS2_RC ret = TSS2_RC_SUCCESS;

  do {
    //init tcti_vtbl
    //get vtbl's size
    //ret = InitDeviceTcti(NULL, &tcti_vtbl_size, NULL);
    ret = InitSocketTcti(NULL, &tcti_vtbl_size, NULL, 0);
    if(ret != TSS2_RC_SUCCESS)
      break;
    
    tcti_vtbl = (TSS2_TCTI_CONTEXT*)calloc(1, tcti_vtbl_size);
    if(tcti_vtbl == NULL) {
      ret = TSS2_BASE_RC_GENERAL_FAILURE;
      break;
    }

    //ret = InitDeviceTcti(tcti_vtbl, &tcti_vtbl_size, &localdev);
    ret = InitSocketTcti(tcti_vtbl, &tcti_vtbl_size, &localsrv, 0);
    if(ret != TSS2_RC_SUCCESS) {
      free(tcti_vtbl);
      break;
    }

    sysctx_size = Tss2_Sys_GetContextSize(0);
    sysctx = (TSS2_SYS_CONTEXT*)calloc(1, sysctx_size);
    if(sysctx == NULL) {
      free(tcti_vtbl);
      ret = TSS2_BASE_RC_GENERAL_FAILURE;
      break;
    }

    ret = Tss2_Sys_Initialize(sysctx, sysctx_size, tcti_vtbl, (TSS2_ABI_VERSION*)&abiver);
    if(ret != TSS2_RC_SUCCESS) {
      free(sysctx);
      free(tcti_vtbl);
      break;
    }

    ctx2->ctx = sysctx;
    
  } while(0);

  return ret;  
}

static FP_ctx_uninit(tpm2_ctx_uninit)
{
  tpm2_pcr_context* ctx2 = (tpm2_pcr_context*)ctx;
  
  TSS2_RC ret = TSS2_RC_SUCCESS;
  TSS2_TCTI_CONTEXT* vtbl = NULL;

  Tss2_Sys_GetTctiContext(ctx2->ctx, &vtbl);
  Tss2_Sys_Finalize(ctx2->ctx);
  free(ctx2->ctx);
  free(vtbl);
  ctx2->ctx = NULL;
  return ret;
}

static FP_ctx_freemem(tpm2_ctx_freemem)
{
  free(ptr);
}

#define SETB_PCR_SELECT( pcrSelection, index )	\
  do {(pcrSelection).pcrSelect[( (index)/8 )] |= ( 1 << ( (index) % 8) );} while(0)

#define CLRB_PCR_SELECT( pcrSelection )		\
  do {						\
    (pcrSelection).pcrSelect[0] = 0;		\
    (pcrSelection).pcrSelect[1] = 0;		\
    (pcrSelection).pcrSelect[2] = 0;		\
  } while(0)

#define SETALL_PCR_SELECT( pcrSelection )		\
  do {						\
    (pcrSelection).pcrSelect[0] = 0xff;		\
    (pcrSelection).pcrSelect[1] = 0xff;		\
    (pcrSelection).pcrSelect[2] = 0xff;		\
  } while(0)

#define SETSZ_PCR_SELECT( pcrSelection, size )		\
  do{(pcrSelection).sizeofSelect = size;}while(0)

static FP_pcr_read(tpm2_pcr_read)
{
  tpm2_pcr_context* ctx2 = (tpm2_pcr_context*)ctx;
  TSS2_RC ret = TSS2_RC_SUCCESS;

  TPML_DIGEST pcrValues;
  TPML_PCR_SELECTION pcrSelection, pcrSelectionOut;
  UINT32 pcrUpdateCounter = 0;

  pcrSelection.count = 1;
  pcrSelection.pcrSelections[0].hash = ctx2->alg;
  pcrSelection.pcrSelections[0].sizeofSelect = sizeof(pcrSelection.pcrSelections[0].pcrSelect);
  CLRB_PCR_SELECT(pcrSelection.pcrSelections[0]);
  SETB_PCR_SELECT(pcrSelection.pcrSelections[0], pcr_index);

  ret = Tss2_Sys_PCR_Read(ctx2->ctx,
			  0,
			  &pcrSelection,
			  &pcrUpdateCounter,
			  &pcrSelectionOut,
			  &pcrValues,
			  0);

  if(ret == TSS2_RC_SUCCESS) {
    if (sizeof(pcrvalue->a) < pcrValues.digests[0].t.size) {
      pcrvalue->s = 0;
    } else {
      memcpy(pcrvalue->a, pcrValues.digests[0].t.buffer, pcrValues.digests[0].t.size);
      pcrvalue->s = pcrValues.digests[0].t.size;
    }
  }
  
  return ret;
  
}

static FP_pcr_extend(tpm2_pcr_extend)
{
  tpm2_pcr_context* ctx2 = (tpm2_pcr_context*)ctx;
  TSS2_RC ret = TSS2_RC_SUCCESS;

  TPMS_AUTH_COMMAND sessionData, *sessionDataptr = &sessionData;
  TSS2_SYS_CMD_AUTHS sessionsData;
  TPML_DIGEST_VALUES digests;

  sessionsData.cmdAuths = &sessionDataptr;
  sessionData.sessionHandle = TPM_RS_PW;
  sessionData.nonce.t.size = 0;
  sessionData.hmac.t.size = 0;
  *( (UINT8 *)((void *)&sessionData.sessionAttributes ) ) = 0;
  sessionsData.cmdAuthsCount = 1;
  sessionsData.cmdAuths[0] = &sessionData;

  digests.count = 1;
  digests.digests[0].hashAlg = ctx2->alg;

  
  do {
    memcpy(&(digests.digests[0].digest), data, datalen);

    ret = Tss2_Sys_PCR_Extend(ctx2->ctx, pcr_index, &sessionsData, &digests, 0);
    if(ret != TSS2_RC_SUCCESS) {
      break;
    }

    ret = tpm2_pcr_read(ctx, pcr_index, newvalue);
  } while(0);

  return ret;
}

static FP_pcr_reset(tpm2_pcr_reset)
{
  tpm2_pcr_context* ctx2 = (tpm2_pcr_context*)ctx;
  TPMS_AUTH_COMMAND sessionData, *sessionDataPtr = &sessionData;
  TPMS_AUTH_RESPONSE sessionDataOut, *sessionDataOutPtr = &sessionDataOut;
  TSS2_SYS_CMD_AUTHS sessionsData;
  TSS2_SYS_RSP_AUTHS sessionsDataOut;

  sessionsDataOut.rspAuths = &sessionDataOutPtr;
  sessionsData.cmdAuths = &sessionDataPtr;

  sessionsDataOut.rspAuthsCount = 1;
  
  // Init authHandle
  sessionData.sessionHandle = TPM_RS_PW;

  // Init nonce.
  sessionData.nonce.t.size = 0;

  // init hmac
  sessionData.hmac.t.size = 0;
  
  // Init session attributes
  *( (UINT8 *)((void *)&sessionData.sessionAttributes ) ) = 0;

  sessionsData.cmdAuthsCount = 1;
  sessionsData.cmdAuths[0] = &sessionData;

  return Tss2_Sys_PCR_Reset(ctx2->ctx,
			    pcr_index,
			    &sessionsData,
			    &sessionsDataOut);
}

static FP_pcr_setalg(tpm2_pcr_setalg)
{
  tpm2_pcr_context* ctx2 = (tpm2_pcr_context*)ctx;
  TSS2_RC ret = TSS2_RC_SUCCESS;
  
  TPML_PCR_SELECTION* sel = (TPML_PCR_SELECTION*)selection;
  TPMS_AUTH_COMMAND sessionData, *sessionDataPtr = &sessionData;
  TPMS_AUTH_RESPONSE sessionDataOut, *sessionDataOutPtr = &sessionDataOut;
  TSS2_SYS_CMD_AUTHS sessionsData;
  TSS2_SYS_RSP_AUTHS sessionsDataOut;
  TPMI_YES_NO allocationSuccess;
  UINT32 maxPcr = 0;
  UINT32 sizeNeeded = 0;
  UINT32 sizeAvailable = 0;

  sessionsDataOut.rspAuths = &sessionDataOutPtr;
  sessionsData.cmdAuths = &sessionDataPtr;

  sessionsDataOut.rspAuthsCount = 1;
  
  // Init authHandle
  sessionData.sessionHandle = TPM_RS_PW;

  // Init nonce.
  sessionData.nonce.t.size = 0;

  // init hmac
  sessionData.hmac.t.size = 0;
  
  // Init session attributes
  *( (UINT8 *)((void *)&sessionData.sessionAttributes ) ) = 0;

  sessionsData.cmdAuthsCount = 1;
  sessionsData.cmdAuths[0] = &sessionData;

 
  
    
      
  ret = Tss2_Sys_PCR_Allocate(ctx2->ctx,
			      TPM_RH_PLATFORM,
			      &sessionsData,
			      sel,
			      &allocationSuccess,
			      &maxPcr,
			      &sizeNeeded,
			      &sizeAvailable,
			      &sessionsDataOut);
    
 
  
  return ret;
}

static FP_ctx_setalg(tpm2_ctx_setalg)
{
  tpm2_pcr_context* ctx2 = (tpm2_pcr_context*)ctx;
  ctx2->alg = alg;
}

static const tpm2_spec_vtbl vt2 = (tpm2_spec_vtbl){
  tpm2_ctx_setalg,
  tpm2_pcr_setalg
};

const pcr_vtbl tpm2_pcr_vtbl
= (pcr_vtbl) {
  "2",
  &vt2,

  tpm2_errout,
  tpm2_ctx_init,
  tpm2_ctx_uninit,
  tpm2_ctx_freemem,
  tpm2_pcr_read,
  tpm2_pcr_extend,
  tpm2_pcr_reset
};
