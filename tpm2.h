/* 
 * tpm2.h
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

#ifndef _TPM2_H_
#define _TPM2_H_

#ifdef __cplusplus
extern "C" {
#if 0
}
#endif
#endif

#include "tpm_common.h"
#include <sapi/tpm20.h>
#include <tcti/tcti_device.h>
#include <tcti/tcti_socket.h>

typedef struct tpm2_pcr_context {
  const pcr_vtbl* vtbl;
  union {
    struct {
      TSS2_SYS_CONTEXT* ctx;
      TPMI_ALG_HASH alg;
    };
  };
} tpm2_pcr_context;

extern const pcr_vtbl tpm2_pcr_vtbl;

#ifdef __cplusplus
#if 0
{
#endif
}
#endif

#endif
