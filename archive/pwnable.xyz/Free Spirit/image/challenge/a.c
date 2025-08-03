#include <stdio.h>

int main(void) {
	void* palestine = malloc(0x60);
	free(palestine);
	free(palestine);
	
	return 0;
}
