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

#include "tpm_common.h"
#include "tpm2_md_alg.h"
#include "md.h"
#include <stdbool.h>
#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <unistd.h>

const char usagefmt[]
= "Usage: %s [option] command <index-of-a-pcr or cfgstr> [files]\n"
  "Commands:\n"
  "\n"
  "read - read the value of the pcr whose index is given.\n"
  "extend - extend the value of the pcr with the hashsums\n"
  "\tof given files, and output the new value.\n"
  "clear - reset the value of the pcr to its initial state.\n"
  "setalg - (for TPM2 only) enable a bitmap of pcr on the bank of an algorithm,\n"
  "\tneeds a configure string in \"alg1:map1+alg2:map2...n\" format.\n"
  "Options:\n"
  "-a - select hash algorithm - default to sha1.\n"
  "\tnote: on TPM2, algorithm for file must match with pcr's bank algorithm.\n"
  "-b - output pcr value as raw binary, rather than hex string.\n"
  "-o - write to a file instead of stdout.\n"
  "Examples:\n"
  "read the value of pcr 12:\n"
  "\t%s read 12\n"
  "read the value of pcr 12 on sha256 bank (for TPM2 only):\n"
  "\t%s -a sha256 read 12\n"
  "extend the value of pcr 16 with files:\n"
  "\t%s extend 12 file1 <file2> ...\n"
  "clear the value of pcr 17:\n"
  "\t%s clear 17\n"
  "clear the value of pcr 17 on sha256 bank (for TPM2 only):\n"
  "\t%s -a sha256 clear 17\n"
  "enable pcr 3, 4 on sha256 bank, and pcr 17, 18 on sha384 bank (for TPM2 only):\n"
  "\t%s setalg sha256:000018+sha384:030000\n";

const char optstr[] = "a:bo:";

extern const pcr_vtbl tpm12_pcr_vtbl;
extern const pcr_vtbl tpm2_pcr_vtbl;

int outputpcr(bool binary_out,
	      FILE* fp,
	      uint32_t pcr_index,
	      const pcr* pcr_content)
{
  if(pcr_content->s == 0) {
    fprintf(stderr,
	    "Warning: pcr %u reports no value, which indicates "
	    "hash algorithm mismatch when accessing tpm2.\n", pcr_index);
    return 0;
  }
  if(binary_out)
    return fwrite(pcr_content->a, sizeof(pcr_content->a), 1, fp);
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
  const char* alg = "sha1";
  const tpm2_hashalg_list_item* ialg = NULL;
  bool binout = false;
  const char* outfile = NULL;
  const char* command = NULL;
  uint32_t pcr_index = 24;//for "all pcrs".
  const char* cfgmap = NULL;

  if (argc == 1) {
    fprintf(stderr,
	    usagefmt,
	    argv[0],
	    argv[0],
	    argv[0],
	    argv[0],
	    argv[0],
	    argv[0],
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
  if(argv[optind + 1] == NULL) {
    fputs("Missing operand!\n", stderr);
    return -(EXIT_FAILURE);
  }
  
  if(0 != strcmp(command, "setalg")){
    pcr_index = atoi(argv[optind + 1]);
    
    if((pcr_index < 0)||
       (pcr_index > 23)) {
      fprintf(stderr, "PCR index %d is invalid!\n", pcr_index);
      return -(EXIT_FAILURE);
    }
  } else {
    cfgmap = argv[optind + 1];
  }
  
  const pcr_vtbl* t = &tpm12_pcr_vtbl;
  pcr_context_base ctx = (pcr_context_base){NULL, {{0, 0}}};
  int ret = 0;

  {
    fputs("Trying to access TPM v1...\n", stderr);
    ret = tpm_ctx_init(&ctx, t);
    if (0 == ret) {
      fputs("Successful to get access to a tpm1, going ahead...\n", stderr);
    } else {
      tpm_ctx_uninit(&ctx);
      fprintf(stderr,
	      "0x%x: Unable to get access to a tpm1, try tpm2 instead...\n",
	      ret);
      t = &tpm2_pcr_vtbl;
      ret = tpm_ctx_init(&ctx, t);
      if (0 == ret) {
	fputs("Successful to get access to a tpm2, going ahead...\n", stderr);
	ialg = MD_tpm2_checksupport(alg);
	if(ialg != NULL) {
	  tpm_ctx_setalg(&ctx, ialg->id);
	} else {
	  alg = NULL;
	  
	}
      } else {
	fprintf(stderr,
		"0x%x: Unable to find any supported tpms, exiting.\n",
		ret);
	return ret;
      }
    }
  }
  
  do {
    if(0 == strcmp("read", command)) {
      pcr value;
      ret = tpm_errout(&ctx, "read pcr value...\n",
		   tpm_pcr_read(&ctx, pcr_index, &value));
      if(0 == ret) {
	outputpcr(binout, fpout, pcr_index, &value);
      }else{
	//something wrong.
      }
    } else if (0 == strcmp("extend", command)) {
      if(alg == NULL) {
	fprintf(stderr, "TPM2 cannot process the digest of %s!\n", alg);
	tpm_ctx_uninit(&ctx);
	ret = -(EXIT_FAILURE);
	break;
      }

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

	

	pcr value;
	char buf[MDBIO_md_size(b)];
	{
	  size_t i = 0;
	  for(; i < fa->num; i++){
	    MDBIO_feed_file(b, fa->arr[i], 1024);
	    MDBIO_getmd(b, buf, sizeof(buf));
	    ret = tpm_errout(&ctx, "extend pcr value...\n",
			 tpm_pcr_extend(&ctx, pcr_index,
				    buf, sizeof(buf),
				    &value));
	    if(0 != ret){
	      break;
	    }
	  }
	}
	if(ret == 0)
	  outputpcr(binout, fpout, pcr_index, &value);

      } while (0);
      
      BIO_free(b);
      OSSL_uninit();
    } else if (0 == strcmp("clear", command)) {
      ret = tpm_errout(&ctx, "clear pcr value...\n", tpm_pcr_reset(&ctx, pcr_index));
    } else if (0 == strcmp("setalg", command)) {
      if(t == &tpm12_pcr_vtbl) {
	fputs("TPM1 does not support to set pcr's algorithm!\n", stderr);
	ret = -(EXIT_FAILURE);
	break;
      }

      size_t count = 0;
      void* selection = NULL;
      if(parse_selection(cfgmap, &count, &selection) == false) {
	fputs("Failed to pass config bitmap!\n", stderr);
	ret = -(EXIT_FAILURE);
	break;
      } else {
	fprintf(stderr,
		"%zu bitmap(s) get parsed! settings will be applied.\n",
		count);
      }
      
      ret = tpm_errout(&ctx, "set pcr algorithm...\n", tpm_pcr_setalg(&ctx, selection));
      free(selection);
      if(ret == 0) {
    
	  fputs("Config bitmap applied,\n"
		"which will take effect since the next boot.\n",
		 stderr);
	
	
		
      } else if(ret == 0x1c3) {
	fputs("Config bitmap is not applied,\n"
	      "for some given algorithm is not supported by the tpm.\n",
	      stderr);
      }
    } else {
      fprintf(stderr, "command \"%s\" is not supported!\n", command);
      ret = -(EXIT_FAILURE);
    }
  } while (0);

  tpm_ctx_uninit(&ctx);
  if (fpout != stdout)
    fclose(fpout);
  
  return ret;
}
