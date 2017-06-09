/* 
 * pcrtool.c
 * command line tool to operate PCRs of a TPM.
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

#include "tpm.h"
#include "md.h"
#include <stdbool.h>
#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <unistd.h>

const char usagefmt[]
= "Usage: %s [option] command index-of-a-pcr [files]\n"
  "Commands:\n"
  "\n"
  "read - read the value of the pcr whose index is given.\n"
  "extend - extend the value of the pcr with the hashsums\n"
  "\tof given files, and output the new value.\n"
  "clear - reset the value of the pcr to its initial state.\n"
  "\n"
  "Options:\n"
  "-a - select hash algorithm - default to sha256.\n"
  "-b - output pcr value as raw binary, rather than hex string.\n"
  "-o - write to a file instead of stdout.\n";

const char optstr[] = "a:bo:";

int outputpcr(bool binary_out,
	      FILE* fp,
	      uint32_t pcr_index,
	      const PCR* pcr_content)
{
  if(binary_out)
    return fwrite((*pcr_content), sizeof(*pcr_content), 1, fp);
  else
    return fprintpcr(fp, pcr_index, pcr_content);
}

typedef struct farr {
  size_t num;
  FILE* arr[];
} farr;

void freefarr(farr* a)
{
  if(a == NULL)
    return;
  {
    size_t i = 0;
    for(;i < a->num; i++) {
      if(a->arr[i] != NULL)
	fclose(a->arr[i]);
    }
  }
  free(a);
}

farr* openfarr(int filec, const char** filev)
{
  farr* a = (farr*)calloc(sizeof(farr), sizeof(farr)/sizeof(void*) + filec);
  if(a == NULL)
    return NULL;
  a->num = filec;
  {
    size_t i = 0;
    for(; i < filec; i++) {
      FILE* fp = fopen(filev[i], "rb");
      if(fp == NULL) {
	fprintf(stderr, "Fail to open the %zuth file %s:\n"
		"%d: %s\n", i, filev[i], errno, strerror(errno));
	freefarr(a);
	return NULL;
      }else{
	a->arr[i] = fp;
      }
    }
  }
  return a;
}

int main(int argc, char** argv)
{
  const char* alg = "sha256";
  bool binout = false;
  const char* outfile = NULL;
  const char* command = NULL;
  int index = 0;

  if (argc == 1) {
    fprintf(stderr, usagefmt,
		argv[0]);
    return 0;
  }

  // parse options.
  {
    int opt = 0;
    for(opt = getopt(argc, argv, optstr);
	opt != -1;
	opt = getopt(argc, argv, optstr)) {
      switch(opt) {
      case 'a':
	alg = optarg;
	break;
      case 'b':
	binout = true;
	break;
      case 'o':
	outfile = optarg;
	break;
      default: // '?' 
	fprintf(stderr, usagefmt,
		argv[0]);
	return -(EXIT_FAILURE);
      }
    }
  }

  FILE* fpout = NULL;
  if(outfile)
    fpout = fopen(outfile, "wb");
  else
    fpout = stdout;

  if(fpout == NULL) {
    fprintf(stderr,
	    "unable to open file %s to write!\n",
	    outfile);
    return -(EXIT_FAILURE);
  }
    

  command = argv[optind];
  index = atoi(argv[optind + 1]);
  if((index < 0)||(index > 23)) {
    fprintf(stderr, "PCR index %d is invalid!\n", index);
    return -(EXIT_FAILURE);
  }

  TSS_BASIC_HANDLES bh = {0, 0};
  int ret = TSS_SUCCESS;

  {
    ret = tss_basic_handle_init(&bh);
    if (TSS_SUCCESS != ret)
      return ret;
  }

  
  
  do {
    if(0 == strcmp("read", command)) {
      char* value = NULL;
      uint32_t vlen = 0;
      ret = errout("read pcr value...\n",
		   readpcr(bh, index, &vlen, &value));
      if((TSS_SUCCESS == ret)
	 && (vlen == sizeof(PCR))) {
	outputpcr(binout, fpout, index, (const PCR*)value);
      }else{
	//something wrong.
      }
      tss_basic_handle_freemem(bh, value);
    } else if (0 == strcmp("extend", command)) {
      if(!OSSL_init()) {
	fputs("Error: Unable to init OpenSSL Library!\n",stderr);
	ret = EXIT_FAILURE;
	break;
      }
      
      MDBIO* b = MDBIO_new(alg);
      if(b == NULL) {
	fprintf(stderr, "Error: Unable to create MDBIO: %s\n",
		ERR_error_string(ERR_get_error(), NULL));
	ret = -(EXIT_FAILURE);
	break;
      }

      do {
	int fileind = optind + 2;
	farr* fa = openfarr(argc - fileind, (const char**)(argv + fileind));

	if(fa == NULL) {
	  fputs("unable to open all given files!\n", stderr);
	  break;
	}

	

	uint32_t vlen = 0;
	char* value = NULL;
	char buf[MDBIO_md_size(b)];
	{
	  size_t i = 0;
	  for(; i < fa->num; i++){
	    MDBIO_feed_file(b, fa->arr[i], 1024);
	    MDBIO_getmd(b, buf, sizeof(buf));
	    ret = errout("extend pcr value...\n",
				     extendpcr(bh, index,
					       buf, sizeof(buf),
					       &vlen, &value));
	    if(TSS_SUCCESS != ret){
	      vlen = 0;
	      value = NULL;
	      break;
	    }

	    if(i < (fa->num - 1)) {
	      tss_basic_handle_freemem(bh, value);
	      value = NULL;
	    }
	  }
	}

	if((value != NULL) && (vlen == sizeof(PCR))) {
	  outputpcr(binout, fpout, index, (const PCR*)value);
	  tss_basic_handle_freemem(bh, value);
	} 	
      } while (0);
      
      BIO_free(b);
      OSSL_uninit();
    } else if (0 == strcmp("clear", command)) {
      ret = errout("clear pcr value...\n", resetpcr(bh, index));
    } else {
      fprintf(stderr, "command \"%s\" is not supported!\n", command);
      ret = -(EXIT_FAILURE);
    }
  } while (0);

  tss_basic_handle_uninit(&bh);
  if (fpout != stdout)
    fclose(fpout);
  
  return ret;
}
