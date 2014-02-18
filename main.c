#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>

#include "grepline.h"

#ifdef _WIN32
#	define OS_HEXLINE 16
#	define OS_NEWLINE 1
#	define READ "rb"
#	define WRITE "wb"
#	ifndef _CRT_SECURE_NO_WARNINGS
#		define _CRT_SECURE_NO_WARNINGS
#	endif /*_CRT_SECURE_NO_WARNINGS*/
#	elif linux
#		define OS_HEXLINE 17
#		define OS_NEWLINE 2
#		define READ "r"
#		define WRITE "w"
#	else
#		error Unknown system.
#endif /*_WIN32*/

void help(char * exe)
{
	printf("IDA .dif patcher\nUsage: %s .dif output\n\t.dif - path to a .dif file to use\n\toutput - output file\n", exe);
}

int8_t CheckIDAVersion(FILE * DifFile)
{
	int8_t result = 0;
	size_t len = 0;
	char * line = NULL;
	grepline(&line, &len, DifFile);
	if(!strncmp(line,"This difference file has been created by IDA Pro",len-OS_HEXLINE) && 48 == len-OS_HEXLINE)
	{
		result = 6; /*IDA 6*/
	}
	else
	{
		if(!strncmp(line, "This difference file is created by The Interactive Disassembler",len-OS_HEXLINE) && 63 == len-OS_HEXLINE)
		{
			result = 5; /*IDA 5*/
		}
	}
	free(line);
	return result;
}

int8_t CheckNewline(FILE * DifFile)
{
	int8_t result = 1;
	size_t len = 0;
	char * line = NULL;
	grepline(&line, &len, DifFile);
	if(len != OS_NEWLINE)
	{
		result = 0; /*This is not an empty line*/
	}
	free(line);
	return result;
}

void ReadFileName(FILE * DifFile, char ** BinaryFileName)
{
	size_t len = 0;
	char * line = NULL;
	grepline(&line,&len,DifFile);
	len = len - OS_NEWLINE;
	*BinaryFileName = malloc(len+1);
	memset(*BinaryFileName,0,len+1);
	memcpy(*BinaryFileName,line,len);
	free(line);
}

void IDADifPatch(FILE * DifFile, FILE * Binary, FILE * NewFile)
{
	char OffsetString[9];
	uint32_t OffsetTarget = 0;
	uint32_t OffsetCurrent = 0;
	size_t len = 0;
	char * line = NULL;
	uint8_t New = 0;
	uint8_t Old = 0;
	int Buffer = 0;
	grepline(&line,&len,DifFile);
	while(!feof(DifFile) && len == OS_HEXLINE)
	{
/* Getting target offset */
		memset(OffsetString,0,9);
		memcpy(OffsetString,line,8);
		OffsetTarget = strtoul(OffsetString,NULL,16);
		printf("PATCH: @%s : ", OffsetString);
/* Preparing old and new byte */
		memset(OffsetString,0,3);
		memcpy(OffsetString,line+10,2);
		Old = (uint8_t)strtol(OffsetString,NULL,16);
		memset(OffsetString,0,3);
		memcpy(OffsetString,line+13,2);
		New = (uint8_t)strtol(OffsetString,NULL,16);
/* Filling space before target offset */
		while(OffsetCurrent < OffsetTarget)
		{
			fputc(fgetc(Binary),NewFile);
			++OffsetCurrent;
		}
/* Patching a byte */
		printf("%X->%X\n", Old, New);
		Buffer = fgetc(Binary);
/* Checking if we found an expected byte */
		if(Buffer != Old)
		{
			printf("WARNING: @%X : expected %X : got %X\n", OffsetTarget, Old, Buffer);
		}
		fputc(New,NewFile);
		++OffsetCurrent;
		grepline(&line, &len, DifFile);
	}
	free(line);
/* Done reading difference file. Filling the rest of the binary */
	while(!feof(Binary))
	{
		Buffer = fgetc(Binary);
		if(Buffer != EOF)
		{
			fputc(Buffer,NewFile);
		}
	}
	puts("PATCH: Finished!");
}

int main(int argc, char *argv[])
{
	FILE * DifFile;
	FILE * NewFile;
	FILE * Binary;
	char * BinaryFileName = NULL;
	int8_t IDAVersion = 0;
	int8_t IDAnewline = 0;
/* Did we forget arguments? */
	if(argc != 3)
	{
		help(argv[0]);
		exit(1);
	}
/* We can't work on empty files */
	DifFile = fopen(argv[1], "r");
	if(DifFile == NULL)
	{
		puts("ERROR: empty file");
		fclose(DifFile);
		exit(1);
	}
	else
	{
		puts("OK: File opened");
	}
/* Let's check if this is an actual IDA difference file */
	IDAVersion = CheckIDAVersion(DifFile);
	if(IDAVersion != 5 && IDAVersion != 6)
	{
		puts("WARNING: Unsupported disassembler detected. Proceed with caution.");
	}
	else
	{
		printf("OK: IDA %i recognized and hopefully not a spoof. Cross your fingers.\n",IDAVersion);
	}
/* IDA difference files have 2nd line empty */
	IDAnewline = CheckNewline(DifFile);
	if(!IDAnewline)
	{
		puts("ERROR: Failed newline check. Aborting patch.");
		fclose(DifFile);
		exit(1);
	}
/* If we haven't failed this far, we have to extract the binary name and open it */
	ReadFileName(DifFile,&BinaryFileName);
	Binary = fopen(BinaryFileName,READ);
/* Let's check if this isn't a dummy */
	if(Binary == NULL)
	{
		printf("ERROR: Original file doesn't exist.\nINFO: ORIG %s\n",BinaryFileName);
		free(BinaryFileName);
		fclose(Binary);
		fclose(DifFile);
		exit(1);
	}
/* Finally, let's create a new file to write to.
 * NOTE: file with the same name will be overwritten without patcher giving prior notice! */
	NewFile = fopen(argv[2],WRITE);
/* Declare some stuff */
	printf("DIF\tORIG\tOUT\n%s\t%s\t%s\n",argv[1],BinaryFileName,argv[2]);
	free(BinaryFileName);
/* Ready, set, patch! */
	IDADifPatch(DifFile,Binary,NewFile);
/* Cleaning up */
	fclose(DifFile);
	fclose(Binary);
	fclose(NewFile);
	return 0;
}
