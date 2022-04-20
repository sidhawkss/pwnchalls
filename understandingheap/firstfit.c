/* The study is based on shellphish how2heap repository */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int main(void) {
	char* chunk1= malloc(0x512);
	char* chunk2= malloc(0x256);
	char* chunk3;

	fprintf(stderr, "1st malloc(0x512): %p\n",chunk1);
	fprintf(stderr, "2st malloc(0x256): %p\n",chunk2);
	
	strcpy(chunk1, "huga buga");
	fprintf(stderr, "The first allocation %p points to: %s\n", chunk1,chunk1);
	printf("Freeing the first one\n");
	free(chunk1);
	
	printf("FIrst buffer: %p\n", chunk1);
	fprintf(stderr, "allocating 0x500 bytes in chunk3\n");
	chunk3 = malloc(0x500);

	printf("Putting another string\n");
	strcpy(chunk3, "huga buga two");
	printf("The third allocation %p points to %s\n", chunk3,chunk3);
	printf("First allocation %p points to %s\n", chunk1,chunk1);


	printf("\n\nMy explanation about the first-fit:" 
	"I declared two buffers at first, 0x512 and x256\n"
	"After the declaration I populate the first buffer with a string, this string into buffer points to an address, after that I free the buffer. Ok now the buffer is freed and we allocate the third buffer with 0x500, the chunk of the first buffer is clear and can be used to allocate an buffer to populate 0x500, so it will use the same space to do the allocation. So the third buffer has the same address of the first resulting on print of the same string\n");
	return 0;
}