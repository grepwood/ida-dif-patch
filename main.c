#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <stdbool.h>

void help(char * exe)
{
	printf("IDA .dif patcher\nUsage: %s .dif output\n\t.dif - path to a .dif file to use\n\toutput - output file\n", exe);
}

int main(int argc, char *argv[])
{
	if(argc != 3)  
	{
		help(argv[0]);
		exit(1);
	}
	FILE * fp;
	FILE * newfile;
	char * line = NULL;
	size_t len = 0;
	ssize_t read;
	FILE * binary;
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
	read = getline(&line, &len, fp);
	if(	strncmp(line, "This difference file has been created by IDA Pro", 48) == 0
	||	strncmp(line, "This difference file is created by The Interactive Disassembler", 63) == 0)
	{
		puts("IDA .dif file recognized");
	}
	else
	{
		puts("Unknown disassembler signature");
	}

	if(getline(&line, &len, fp) == 2)
	{
		puts("Found expected newline");
		read = getline(&line, &len, fp)-2;
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

	binary = fopen(binary_name, "r");
	newfile = fopen(argv[2], "w");

//Here we get our address and values

	int c;
	uint32_t address, addr_counter = 0;
	uint8_t old, new;
	char * hex_address = malloc(8);
	char * hex_byte = malloc(2);
	do
	{
		read = getline(&line, &len, fp);
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

		for(addr_counter; addr_counter < address; ++addr_counter)
		{
			c = fgetc(binary);
			fputc(c, newfile);
		}
		printf("Modifying byte %x at offset %x to %x\n", old, address, new);
		fputc(new, newfile);
		++addr_counter;
		fgetc(binary);
	}
	while(fgetc(fp) != EOF);
	puts("All addresses modified");
	do
	{
		c = fgetc(binary);
		if(c != EOF)	{fputc(c, newfile);}
	}
	while(c != EOF);

	puts("Finished!");

	free(binary_name);
	free(hex_address);
	free(hex_byte);
	fclose(fp);
	fclose(binary);
	fclose(newfile);
	return 0;
}
