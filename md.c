/* 
 * md.c
 * glue layer wrapped around hash operations for files.
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

#include "md.h"



MDBIO* MDBIO_new(const char* mdname)
{
  BIO* ret = BIO_new(BIO_f_md());
  if(!ret)
    return NULL;
  if(!BIO_set_md(ret, EVP_get_digestbyname(mdname))){
    BIO_free(ret);
    return NULL;
  }
  return ret;
}

size_t MDBIO_md_size(MDBIO* b)
{
  const EVP_MD* mdvt = NULL;
  if(false == BIO_get_md(b, &mdvt))
    return 0;
  return EVP_MD_meth_get_result_size(mdvt);
}

size_t MDBIO_feed_file(MDBIO* b, FILE* f, size_t buff_size)
{
  char* buff = (char*)malloc(buff_size);

  if(buff == NULL) // malloc failed
    return 0;// please check errno.

  BIO* bf = BIO_new_fp(f, false);//do not close f when closing bf
  if(bf == NULL)
    return 0;// please chech ERR.

  BIO_push(b, bf);

  int rdlen = 0;
  size_t total = 0;
  do {
    rdlen = BIO_read(b, buff, buff_size);
    total += rdlen;
  } while(rdlen > 0);

  //do cleaning here.
  {
    BIO_pop(bf);
    BIO_free(bf);
    free(buff);
  }
  
  return total;
}
