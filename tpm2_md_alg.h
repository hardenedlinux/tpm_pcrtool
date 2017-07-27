/* 
 * tpm2_md_alg.h
 * Functions to query hash algorithm compatibility against TPM 2.
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

#ifndef _TPM2_MD_ALG_H_
#define _TPM2_MD_ALG_H_

#ifdef __cplusplus
extern "C" {
#if 0
}
#endif
#endif

#include <stdbool.h>
#include <stdlib.h>

typedef struct tpm2_hashalg_list_item {
  const char* name;
  uint32_t id;
} tpm2_hashalg_list_item;

const tpm2_hashalg_list_item* MD_tpm2_checksupport(const char* mdname);

bool parse_selection(const char* s, size_t* count, void** selection);

#ifdef __cplusplus
#if 0
{
#endif
}
#endif

#endif
