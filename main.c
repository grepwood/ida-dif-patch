#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>

#include "grepline.h"

#ifdef __WIN32
#	define OS_HEXLINE 16
#	define STRANGE_NEWLINE 1
#	define READ "rb"
#	define WRITE "wb"
#else
#	define OS_HEXLINE 17
#	define STRANGE_NEWLINE 2
#	define READ "r"
#	define WRITE "w"
#endif /*__WIN32*/

void help(char * exe)
{
	printf("IDA .dif patcher\nUsage: %s .dif output\n\t.dif - path to a .dif file to use\n\toutput - output file\n", exe);
}

int main(int argc, char *argv[])
{
	FILE * fp;
	FILE * newfile;
	FILE * binary;
	size_t read;
	size_t len = 0;
	char * line = NULL;
	if(argc != 3)
	{
		help(argv[0]);
		exit(1);
	}
	fp = fopen(argv[1], "r");
	if(fp == NULL)
	{
		puts("Error: empty file");
		exit(1);
	}
	else
	{
		puts("File opened");
	}
	read = grepline(&line, &len, fp);
	if(	strncmp(line, "This difference file has been created by IDA Pro", 48) == 0
	||	strncmp(line, "This difference file is created by The Interactive Disassembler", 63) == 0)
	{
		puts("IDA .dif file recognized");
	}
	else
	{
		puts("Unknown disassembler signature");
	}

	if(grepline(&line, &len, fp) == STRANGE_NEWLINE)
	{
		puts("Found expected newline");
		read = grepline(&line, &len, fp)-STRANGE_NEWLINE;
	}
	else
	{
		puts("There should be a newline here...");
	}

	uint32_t counter;
	char *binary_name = malloc(read);
	for(counter = 0; counter < read; ++counter)
	{
		binary_name[counter] = line[counter];
	}
	printf("Original file: %s\n", binary_name);
	if(strcmp(argv[2], binary_name) == 0)
	{
		puts("Can't write to the original file");
		free(binary_name);
		fclose(fp);
		exit(1);
	}
	binary = fopen(binary_name, READ);
	newfile = fopen(argv[2], WRITE);

	uint32_t address;
	uint32_t addr_counter = 0;
	uint8_t old;
	uint8_t new;
	char * hex_address = malloc(8);
	char * hex_byte = malloc(2);
	read = grepline(&line, &len, fp);
	while(!feof(fp) && read == OS_HEXLINE)
	{
		for(counter = 0; counter < 8; ++counter)
		{
			hex_address[counter] = line[counter];
		}
		address = strtoul(hex_address, NULL, 16);
		for(counter = 0; counter < 2; ++counter)
		{
			hex_byte[counter] = line[counter+10];
		}
		old = strtoul(hex_byte, NULL, 16);
		for(counter = 0; counter < 2; ++counter)
		{
			hex_byte[counter] = line[counter+13];
		}
		new = strtoul(hex_byte, NULL, 16);

		while(addr_counter < address)
		{
			fputc(fgetc(binary), newfile);
			++addr_counter;
		}
		printf("Modifying byte %x at offset %x to %x\n", old, address, new);
		fputc(new, newfile);
		++addr_counter;
		fgetc(binary);
		read = grepline(&line, &len, fp);
	}
	puts("All addresses modified");
	int c;
	while(!feof(binary))
	{
		c = fgetc(binary);
		if(c != EOF)
		{
			fputc(c, newfile);
		}
	}

	puts("Finished!");

	free(binary_name);
	free(hex_address);
	free(hex_byte);
	fclose(fp);
	fclose(binary);
	fclose(newfile);
	return 0;
}
