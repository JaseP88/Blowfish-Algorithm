/*$Author: jtpbyd $*/

/*
 * BlowFish encryption algorithm project
 * Jason Pham / cs4780 / Summer 2016
*/

#include <stdlib.h>
#include <stdio.h>
#include <string.h>

extern unsigned long parray[];
extern unsigned long sbox0[];
extern unsigned long sbox1[];
extern unsigned long sbox2[];
extern unsigned long sbox3[];


void long_to_hex(unsigned long num, char *n, int len);
void char_to_hex(char *m, char *n, int len);
unsigned long Function(char *Ri);
void Blowfish(char *Li_1, char *Ri_1, char *Li, char *Ri);
void Setup(unsigned long left_k, unsigned long right_k);



// MAIN function
int main (int argc, char *argv[]) {
	
/*
 If no key found in commandline argument
*/
	if(argc!=2) {
		printf("No key was used as argument\n");
		return 0;
	}

	int i, k;

/*
 	Array structures to hold the whole message
	The left 4 characters and the right 4
	characters
*/
	char message[9]; //8+1 for null char
	char l_message[5];
	char r_message[5];
	char lmess_hex[9];	//holds the left hex string of the message
	char rmess_hex[9];	//holds the right hex string of the message

/*
 	Take key string as command line argument
	Then parse the leftmost 8 chars and rightmost
	8 chars into an array
*/
	char *key_string = argv[1];
	char l_keyString[9];
	char r_keyString[9];
	unsigned long l_k;	//key converted into long ints
	unsigned long r_k;


//Read message from standard input
	printf("input a message to be encrypted.\n");
	fgets(message,9,stdin);
	
//Parse the message string into halfs
	for(i=0; i<strlen(message)/2; i++)
		l_message[i] = message[i];

	l_message[4] = '\0';

	for(i=strlen(message)/2, k=0 ; i<strlen(message); i++, k++)
		r_message[k] = message[i];

	r_message[4] = '\0';

/*
	Convert the left and right ascii message
	into a hex string
*/	
	char_to_hex(l_message,lmess_hex,9);
	char_to_hex(r_message,rmess_hex,9);
printf("lmess_hex is %s\n",lmess_hex);
printf("rmess_hex is %s\n",rmess_hex);

//Parse the key string into halfs
	for(i=0; i<strlen(key_string)/2; i++)
		l_keyString[i] = key_string[i];

	l_keyString[8] = '\0'; //add null char at end

	for(i=strlen(key_string)/2, k=0; i<strlen(key_string); i++, k++)
		r_keyString[k] = key_string[i];
	
	r_keyString[8] = '\0';


//Change hex key into long ints
	l_k = strtoul(l_keyString,NULL,16);
	r_k = strtoul(r_keyString,NULL,16);

	char output_l[9];
	char output_r[9];
//Setup changes the parrays and Sboxes
	Setup(l_k,r_k);
	Blowfish(lmess_hex,rmess_hex,output_l,output_r);
	printf("Encryption: %s %s\n",output_l,output_r);


return 0;
}


void Setup(unsigned long left_k, unsigned long right_k) {
	int i, counter, j;
	char l_output[9];
	char r_output[9];
	unsigned left, right;

//Create zero string in hex	
	char ml[9] = {'0','0','0','0','0','0','0','0','\0'}; 
	char mr[9] = {'0','0','0','0','0','0','0','0','\0'};

//Change the parrays 1st time
	for(i=0; i<18; i++) {
		if(i%2) //if i is odd 
			parray[i] = right_k^parray[i];
		else //else i is even
			parray[i] = left_k^parray[i];
	}
/*
printf("Parray 1st change\n");
for(i=0; i<18; i++) 
	printf("P[%d] = %x\n",i,parray[i]);
*/


//Change the parrays 2nd time
	for(counter=0, i=0, j=1; counter<9; counter++, i+=2, j+=2) {
			
		Blowfish(ml,mr,l_output,r_output); //run encryption

		left = strtoul(l_output,NULL,16);	//take return output & convert
		right = strtoul(r_output,NULL,16);

		parray[i] = left;	//change parray values
		parray[j] = right;

		//turn hex dec into a hex string
		long_to_hex(parray[i],ml,9);
		long_to_hex(parray[j],mr,9);
	}
/*
printf("Parray 2nd change\n");
for(i=0; i<18; i++)
	printf("P[%d] = %x\n",i,parray[i]);
*/


//Change the Sbox0
	for(counter=0, i=0, j=1; counter<128; counter++, i+=2, j+=2) {
		Blowfish(ml,mr,l_output,r_output);
		
		left = strtoul(l_output,NULL,16);
		right = strtoul(r_output,NULL,16);		

		sbox0[i] = left;
		sbox0[j] = right;

		long_to_hex(sbox0[i],ml,9);
		long_to_hex(sbox0[j],mr,9);
	}
/*	
printf("***Sbox0***\n");
for(i=0; i<256; i++)
	printf("S0[%d] = %x\n",i,sbox0[i]);
*/


//Change the Sbox1
	for(counter=0, i=0, j=1; counter<128; counter++, i+=2, j+=2) {
		Blowfish(ml,mr,l_output,r_output);
		
		left = strtoul(l_output,NULL,16);
		right = strtoul(r_output,NULL,16);

		sbox1[i] = left;
		sbox1[j] = right;

		long_to_hex(sbox1[i],ml,9);
		long_to_hex(sbox1[j],mr,9);
	}
/*
printf("***Sbox1***\n");
for(i=0; i<256; i++)
	printf("S1[%d] = %x\n",i,sbox1[i]);			
*/


//Change the Sbox2
	for(counter=0, i=0, j=1; counter<128; counter++, i+=2, j+=2) {
		Blowfish(ml,mr,l_output,r_output);

		left = strtoul(l_output,NULL,16);
    right = strtoul(r_output,NULL,16);

		sbox2[i] = left;
		sbox2[j] = right;
				
		long_to_hex(sbox2[i],ml,9);
		long_to_hex(sbox2[j],mr,9);
	}
/*		
printf("***Sbox2***\n");
for(i=0; i<256; i++)
	printf("S2[%d] = %x\n",i,sbox2[i]);	
*/


//Change the Sbox3
	for(counter=0, i=0, j=1; counter<128; counter++, i+=2, j+=2) {
		Blowfish(ml,mr,l_output,r_output);
		
		left = strtoul(l_output,NULL,16);
    right = strtoul(r_output,NULL,16);

		sbox3[i] = left;
		sbox3[j] = right;

		long_to_hex(sbox3[i],ml,9);
		long_to_hex(sbox3[j],mr,9);
	}
/*
printf("***Sbox3***\n");
for(i=0; i<256; i++)
	printf("S3[%d] = %x\n",i,sbox3[i]);				
*/
}


// Blowfish Encryption 
void Blowfish (char *Li_1, char *Ri_1, char *Li, char *Ri) {

	int i;
	char hexArray[9];	
	int size = sizeof(hexArray);

	unsigned long li_1, ri_1;
	unsigned long li, ri, F_Ri;

	li_1 = strtoul(Li_1,NULL,16);	//transform hex string into long int
	ri_1 = strtoul(Ri_1,NULL,16);

	for(i=0; i<16; i++) {
		ri = (li_1)^(parray[i]);		//Ri = Li-1 xOR Pi

//printf("R%d = L%d xOR P%d = %x xOR %x\n",i+1,i,i,li_1,parray[i]);

		long_to_hex(ri,hexArray,size);	//converts current ri into hex string
		F_Ri = Function(hexArray);		

		li = (F_Ri)^(ri_1);					//Li = F(Ri) xOR Ri-1
//printf("L%d = F(R%d) xOR R%d = F(%x) xOR %x = %x xOR %x = %x\n\n",i+1,i+1,i,ri,ri_1,F_Ri,ri_1,li);
		li_1 = li;
		ri_1 = ri;
//printf("after swap %x %x \n\n",li,ri);
	}

	li = (li)^(parray[16]);	//this is the resulting ri
	ri = (ri)^(parray[17]); //this is the resulting li

//printf("L16 is %x \n",ri);
//printf("R16 is %x \n",li);	
/*
	Return the new left and right message
*/

	long_to_hex(ri,Li,9);
	long_to_hex(li,Ri,9);
}

// Function of the Encryption Algorithm
unsigned long Function (char *Ri) {
//printf("Ri = %s\n",Ri);	
	unsigned long s0, s1, s2, s3;	//holds the value to perform operations
	unsigned long F_Ri_Result;	// Holds the result value of sbox operations

	int i, j, k, l, m;	

	int z, y, x, w; //integer value of hex
	char a[3]; //holds the first 2char hex digit
	char b[3];
	char c[3];
	char d[3];
	a[2]='\0'; b[2]='\0'; c[2]='\0'; d[2]='\0'; //set null char at end
		

	// loop the Ri elements into sub a,b,c,d array
	for(i=0, j=0, k=2, l=4, m=6; i<2; i++, k++, j++, l++, m++) {
		a[i] = Ri[j];
		b[i] = Ri[k];
		c[i] = Ri[l];
		d[i] = Ri[m];
	}

	z = strtoul(a,NULL,16);
	y = strtoul(b,NULL,16);
	x = strtoul(c,NULL,16);
	w = strtoul(d,NULL,16);
	
	s0 = sbox0[z];
	s1 = sbox1[y];
	s2 = sbox2[x];
	s3 = sbox3[w];

//printf("a = %s : Sbox0 = %x\n",a,sbox0[z]);
//printf("b = %s : Sbox1 = %x\n",b,sbox1[y]);
//printf("c = %s : Sbox2 = %x\n",c,sbox2[x]);
//printf("d = %s : Sbox3 = %x\n",d,sbox3[w]);
	
	return F_Ri_Result = ((s0+s1)^s2)+s3;
}


// Converts the unsigned long back into hex strings
void long_to_hex (unsigned long num, char *n, int len) {
	
	snprintf(n,len,"%08x",num);
}


// Converts the chars from *m into hex strings in *n
void char_to_hex (char *m, char *n, int len) {
	int i;
	
	for(i=0; i<4; i++) 
		snprintf(n+i*2,len,"%x",m[i]);
/*
	for(i=0; i<4; i++)
		printf("%c ",m[i]);
	
	printf("\n");

	for(i=0; i<8; i++) 
		printf("%c ",n[i]);
*/
}



