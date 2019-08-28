#include <stdio.h>
#include <pcap.h> 


int main(){

	int a  = 5;
	int *packet = &a;
	printf("%lu\n",sizeof(u_char));
	printf("%p\n",&a);
	printf("%p\n",packet + sizeof(int));
	return 0;
}

