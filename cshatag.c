/**
 * Copyright (C) 2012 Jakob Unterwurzacher
 * Author(s): Jakob Unterwurzacher <jakobunt@gmail.com>
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License as
 * published by the Free Software Foundation; either version 2 of the
 * License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA
 * 02111-1307, USA.
 */

#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <getopt.h>
#include <sys/xattr.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <openssl/sha.h>
#include <time.h>
#include <string.h>
#include <errno.h>

#define BUFSZ 8192
#define HASHLEN 256/8

/**
 * Holds a file's metadata
 */
typedef struct
{
	unsigned long long seconds;
	unsigned long nanoseconds;
	char sha256[HASHLEN*2+1];
	bool unset;
} xa_t;

/**
 * ASCII hex representation of char array
 */
char * bin2hex(unsigned char * bin, long len, char * out)
{
	char hexval[] = {'0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'a', 'b', 'c', 'd', 'e', 'f'};
	int j;
	for(j=0;j<len;j++)
	{
		out[2*j] = hexval[((bin[j] >> 4) & 0x0F)];
		out[2*j+1] = hexval[(bin[j]) & 0x0F];
	}
	out[2*len]=0;
	return out;
}

/**
 * sha256 of contents of f, ASCII hex representation
 */
char * fhash(FILE *f, char *hex)
{
	SHA256_CTX c;
	char buf[BUFSZ];
	size_t len;

	SHA256_Init(&c);

	while( (len=fread(buf, 1, BUFSZ,f) ) )
	{
		SHA256_Update(&c, buf, len);
	}

	unsigned char * hash;
	hash=calloc(1,HASHLEN);
	if(NULL == hash)
	{
		fprintf(stderr, "Insufficient memory for hashing file");
		exit(EXIT_FAILURE);
	}
	SHA256_Final(hash, &c);

	//printf("%s\n",bin2hex(hash,HASHLEN));

	return bin2hex(hash,HASHLEN,hex);
}

/**
 * Nanosecond precision mtime of a file
 */
xa_t getmtime(FILE *f)
{
	xa_t actual;

	int fd=fileno(f);
	struct stat buf;
	fstat(fd, &buf);
	if(!S_ISREG(buf.st_mode))
	{
		fprintf(stderr,"Error: this is not a regular file\n");
		exit(3);
	}
	actual.seconds=buf.st_mtim.tv_sec;
	actual.nanoseconds=buf.st_mtim.tv_nsec;

	return actual;
}

/**
 * File's actual metadata
 */
xa_t getactualxa(FILE *f)
{
	xa_t actual;
	/*
	 * Must read mtime *before* file hash,
	 * if the file is being modified, hash will be invalid
	 * but timestamp will be outdated anyway
	 */
	actual=getmtime(f);

	/*
	 * Compute hash
	 */
	fhash(f,actual.sha256);

	return actual;
}

/**
 * File's stored metadata
 */
xa_t getstoredxa(FILE *f)
{
	int fd=fileno(f);
	bool unset;
	xa_t xa = {0,0,{0}, true};
	/*
	 * Attempt to get the sha256sum stored by this tool
	 */
	unset = (fgetxattr(fd, "user.shatag.sha256", xa.sha256, sizeof(xa.sha256)) <= 0);

	/*
	 * Get the time stamp in terms of seconds and nanoseconds
	 */
	char ts[30] = {0};
	unset &= (fgetxattr(fd, "user.shatag.ts", ts, sizeof(ts)) <= 0);
	sscanf(ts,"%10llu.%9lu",&xa.seconds,&xa.nanoseconds);

	/*
	 * Flag if both fields are not set
	 */
	xa.unset = unset;

	return xa;
}

/**
 * Write out metadata to file's extended attributes
 */
bool writexa(FILE *f, xa_t xa)
{
	int fd=fileno(f);
	int flags=0;
	bool err;

	char buf [100];
	snprintf(buf,sizeof(buf),"%llu.%09lu",xa.seconds,xa.nanoseconds);
	err = fsetxattr(fd, "user.shatag.ts", buf, strlen(buf), flags);
	err |= fsetxattr(fd, "user.shatag.sha256", &xa.sha256, sizeof(xa.sha256), flags);

	return err;
}

/**
 * Pretty-print metadata
 */
char * formatxa(xa_t s)
{
	char * buf;
	char * prettysha;
	int buflen=HASHLEN*2+100;
	buf=calloc(1,buflen);

	if(NULL == buf)
	{
		fprintf(stderr, "Insufficient space to store hash stringed");
		exit(EXIT_FAILURE);
	}

	if(!s.unset)
		prettysha=s.sha256;
	else
		prettysha="0000000000000000000000000000000000000000000000000000000000000000";
	snprintf(buf,buflen,"%s %010llu.%09lu", prettysha, s.seconds, s.nanoseconds);
	return buf;
}

void checkFile(FILE* f, const char* fn, bool update)
{
	xa_t stored;
	stored=getstoredxa(f);
	xa_t actual;
	actual=getactualxa(f);
	bool needsupdate = false;
	bool havecorrupt = false;

	if(stored.seconds==actual.seconds && stored.nanoseconds==actual.nanoseconds)
	{
		/*
		 * Times are the same, go ahead and compare the hash
		 */
		if(strcmp(stored.sha256,actual.sha256)!=0)
		{
			/*
			 * Hashes are different, but this may be because
			 * the file has been modified while we were computing the hash.
			 * So check if the mtime ist still the same.
			 */
			xa_t a2;
			a2=getmtime(f);
			if(stored.seconds==a2.seconds && stored.nanoseconds==a2.nanoseconds)
			{
				/*
				 * Now, this is either data corruption or somebody modified the file
				 * and reset the mtime to the last value (to hide the modification?)
				 */
				fprintf(stderr,"Error: corrupt file \"%s\"\n",fn);
				printf("<corrupt> %s\n",fn);
				printf(" stored: %s\n actual: %s\n",formatxa(stored),formatxa(actual));
				needsupdate = true;
				havecorrupt = true;
			}
		}
		else
		{
			printf("<ok> %s\n",fn);
		}
	}
	else if (stored.unset)
	{
		fprintf(stdout, "<unset> %s\n actual: %s\n", fn,formatxa(actual));
		needsupdate = true;
	}
	else
	{
		printf("<outdated> %s\n",fn);
		printf(" stored: %s\n actual: %s\n",formatxa(stored),formatxa(actual));
		needsupdate = true;
	}

	if(update && needsupdate && writexa(f,actual))
	{
		fprintf(stderr,"Error: could not write extended attributes to file \"%s\": %s\n",fn,strerror(errno));
		exit(4);
	}

	if(havecorrupt)
		exit(5);
}

int main( int argc, char **argv )
{
	int c;
	bool update = false;
	const char* filename = NULL;

	static struct option long_options[] = {
		{"update", no_argument, 0, 'u'},
		{"file", required_argument, 0, 'f'},
		{"help", no_argument, 0, 'h'},
		{0, 0, 0, 0}
	};
	int option_index = 0;
	while ((c = getopt_long(argc, argv, "f:h:u", long_options, &option_index)) != -1)
	{
		switch (c)
		{
			case 0: break;
			case 'f':
			{
				filename = optarg;
				break;
			}
			case 'h':
			{
				fprintf(stdout, "Usage: %s --file $filename [--update]\n", argv[0]);
				exit(EXIT_SUCCESS);
			}
			case 'u':
			{
				update = true;
				break;
			}
			default:
			{
				exit(EXIT_FAILURE);
			}
		}
	}

	if(NULL == filename)
	{
		fprintf(stdout, "Failed to provide a filename\n");
		exit(EXIT_FAILURE);
	}

	FILE *f = fopen(filename,"r");
	if(!f)
	{
		fprintf(stderr,"Error: could not open file \"%s\": %s\n",filename,strerror(errno));
		exit(2);
	}

	checkFile(f, filename, update);

	exit(EXIT_SUCCESS);

}
