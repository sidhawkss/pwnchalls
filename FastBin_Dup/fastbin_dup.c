#include <stdio.h>
#include <stdlib.h>
#include <assert.h>

int main(void){
	printf("Double-free with fastbin\n");

	//Loop to fill up tcache
	void *ptr[8];
	for(int i=0; i<8; i++){
		ptr[i] = malloc(8);
	}
	// Tcache only holds 7 chunks at a time.
	for(int i=0; i<7; i++){
		free(ptr[i]);
	}

	// calloc fill up the allocated memory with zeros.
	// calloc(number elements, element size);
	int *x = calloc(1,8);
	int *y = calloc(1,8);
	int *z = calloc(1,8);
	

	printf("Chunk x at [%p]\n",x);
	printf("Chunk y at [%p]\n",y);
	printf("Chunk z at [%p]\n",z);

	printf("\nFreeing x...\n");
	free(x);
	free(x);
	printf("Freeing y...\n");
	free(y);

	// When a chunk is freed, it goes to the top of the freelist, so, the chunk on top now is the chunk Y.
	printf("\nReference X: %p\n",x);
	printf("Reference Y: %p\n",y);

	printf("Freeing x again...");
    free(x);	

	printf("\n\nCurrent free list:\n %p\n %p\n %p\n",x,y,x);
	// Test
		
	x = calloc(1,8);
	y = calloc(1,8);
	z = calloc(1,8);
	printf("After allocate new chunks, a chunk z will be assigned to the same address of x\n");
	printf("chunk x: %p\n",x);
	printf("chunk y: %p\n",y);
	printf("chunk z: %p\n",z);	
	
}
