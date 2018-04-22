/*
 * AES-128 Encryption
 * Byte-Oriented
 * On-the-fly key schedule
 * Constant-time XTIME
 *
 * Pierre Karpman, 2016-04; 2017-10
 * Quentin Rühl & Alexandre Mouchet 2017-10
 */

#include "aes-128_enc.h"

/*
 * The AES S-box, duh
 */
static const uint8_t S[256] =
{
	0x63, 0x7C, 0x77, 0x7B, 0xF2, 0x6B, 0x6F, 0xC5, 0x30, 0x01, 0x67, 0x2B, 0xFE, 0xD7, 0xAB, 0x76,
	0xCA, 0x82, 0xC9, 0x7D, 0xFA, 0x59, 0x47, 0xF0, 0xAD, 0xD4, 0xA2, 0xAF, 0x9C, 0xA4, 0x72, 0xC0,
	0xB7, 0xFD, 0x93, 0x26, 0x36, 0x3F, 0xF7, 0xCC, 0x34, 0xA5, 0xE5, 0xF1, 0x71, 0xD8, 0x31, 0x15,
	0x04, 0xC7, 0x23, 0xC3, 0x18, 0x96, 0x05, 0x9A, 0x07, 0x12, 0x80, 0xE2, 0xEB, 0x27, 0xB2, 0x75,
	0x09, 0x83, 0x2C, 0x1A, 0x1B, 0x6E, 0x5A, 0xA0, 0x52, 0x3B, 0xD6, 0xB3, 0x29, 0xE3, 0x2F, 0x84,
	0x53, 0xD1, 0x00, 0xED, 0x20, 0xFC, 0xB1, 0x5B, 0x6A, 0xCB, 0xBE, 0x39, 0x4A, 0x4C, 0x58, 0xCF,
	0xD0, 0xEF, 0xAA, 0xFB, 0x43, 0x4D, 0x33, 0x85, 0x45, 0xF9, 0x02, 0x7F, 0x50, 0x3C, 0x9F, 0xA8,
	0x51, 0xA3, 0x40, 0x8F, 0x92, 0x9D, 0x38, 0xF5, 0xBC, 0xB6, 0xDA, 0x21, 0x10, 0xFF, 0xF3, 0xD2,
	0xCD, 0x0C, 0x13, 0xEC, 0x5F, 0x97, 0x44, 0x17, 0xC4, 0xA7, 0x7E, 0x3D, 0x64, 0x5D, 0x19, 0x73,
	0x60, 0x81, 0x4F, 0xDC, 0x22, 0x2A, 0x90, 0x88, 0x46, 0xEE, 0xB8, 0x14, 0xDE, 0x5E, 0x0B, 0xDB,
	0xE0, 0x32, 0x3A, 0x0A, 0x49, 0x06, 0x24, 0x5C, 0xC2, 0xD3, 0xAC, 0x62, 0x91, 0x95, 0xE4, 0x79,
	0xE7, 0xC8, 0x37, 0x6D, 0x8D, 0xD5, 0x4E, 0xA9, 0x6C, 0x56, 0xF4, 0xEA, 0x65, 0x7A, 0xAE, 0x08,
	0xBA, 0x78, 0x25, 0x2E, 0x1C, 0xA6, 0xB4, 0xC6, 0xE8, 0xDD, 0x74, 0x1F, 0x4B, 0xBD, 0x8B, 0x8A,
	0x70, 0x3E, 0xB5, 0x66, 0x48, 0x03, 0xF6, 0x0E, 0x61, 0x35, 0x57, 0xB9, 0x86, 0xC1, 0x1D, 0x9E,
	0xE1, 0xF8, 0x98, 0x11, 0x69, 0xD9, 0x8E, 0x94, 0x9B, 0x1E, 0x87, 0xE9, 0xCE, 0x55, 0x28, 0xDF,
	0x8C, 0xA1, 0x89, 0x0D, 0xBF, 0xE6, 0x42, 0x68, 0x41, 0x99, 0x2D, 0x0F, 0xB0, 0x54, 0xBB, 0x16
};

/*
 * Constant-time ``broadcast-based'' multiplication by $a$ in $F_2[a]/a^8 + a^4 + a^3 + a + 1$
 */
uint8_t xtime(uint8_t x)
{
	uint8_t m = x >> 7;

	m ^= 1;
	m -= 1;
	m &= 0x1B;

	return ((x << 1) ^ m);
}

/*
 * The round constants
 */
static const uint8_t RC[10] = {0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1B, 0x36};

/*
 *Invert the Shift Rows and SubBytes of a matrix
 */
void inv_half_round(uint8_t block[AES_BLOCK_SIZE]){
	uint8_t tmp;
	int i;

	for(i=0; i<AES_BLOCK_SIZE;i++){
		block[i]= Sinv[block[i]];
	}
}

void print_block(uint8_t txt[16]){
	printf("%x %x %x %x\n", txt[0], txt[4], txt[8], txt[12]);
	printf("%x %x %x %x\n", txt[1], txt[5], txt[9], txt[13]);
	printf("%x %x %x %x\n", txt[2], txt[6], txt[10], txt[14]);
	printf("%x %x %x %x\n", txt[3], txt[7], txt[11], txt[15]);
	printf("\n");
}

/*
 * Realises the attack on AES encrypted data.
 */
void aes_attack(uint8_t res[AES_128_KEY_SIZE][AES_128_KEY_SIZE], const uint8_t key[AES_128_KEY_SIZE]){
	int i,j,k,l;
	uint8_t xor_total = 0;
	uint8_t sum = 0;
	uint8_t blocks[256][AES_BLOCK_SIZE];
	uint8_t ctmp[256][AES_BLOCK_SIZE];
	uint8_t constants[AES_BLOCK_SIZE];
	uint8_t guessed_key[AES_128_KEY_SIZE];
	uint8_t ind = 0;

	/*Initialisation of constants*/
	for(i=1;i<AES_BLOCK_SIZE;i++){
		constants[i] = (rand()%255);
	}

	/*Initialisation of the cipher blocks*/
	for(i=0; i<=0xFF;i++){
		blocks[i][0] = i;
		for(k=1;k<AES_BLOCK_SIZE;k++){
			blocks[i][k] = constants[k];
		}
		aes128_enc(blocks[i],key,4,0);
	}

	for(i=0; i<AES_128_KEY_SIZE; i++){
		ind = 0;
		for(l=0;l<=0xFF;l++) {
			/*Creation of the guessed key*/
			for(k=0;k<AES_128_KEY_SIZE;k++){
				guessed_key[k] = 0;
			}
			guessed_key[i] = l;

			/*Inverse half round*/
			for(k=0; k<=0XFF; k++){
				for(j=0;j<AES_BLOCK_SIZE;j++){
					ctmp[k][j] = guessed_key[j] ^ blocks[k][j];
				}
				inv_half_round(ctmp[k]);
			}

			/*Compute sum*/
			sum = 0;
			for(j=0;j<=0xFF;j++){
				sum ^= ctmp[j][i];
			}

			/*Check if guessed_key[i] is correct*/
			if(sum==0) {
				res[i][ind] = guessed_key[i];
				ind++;
			}
		}
	}
}

void aes_round(uint8_t block[AES_BLOCK_SIZE], uint8_t round_key[AES_BLOCK_SIZE], int lastround)
{
	int i;
	uint8_t tmp;

	/*
	 * SubBytes + ShiftRow
	 */
	/* Row 0 */
	block[ 0] = S[block[ 0]];
	block[ 4] = S[block[ 4]];
	block[ 8] = S[block[ 8]];
	block[12] = S[block[12]];
	/* Row 1 */
	tmp = block[1];
	block[ 1] = S[block[ 5]];
	block[ 5] = S[block[ 9]];
	block[ 9] = S[block[13]];
	block[13] = S[tmp];
	/* Row 2 */
	tmp = block[2];
	block[ 2] = S[block[10]];
	block[10] = S[tmp];
	tmp = block[6];
	block[ 6] = S[block[14]];
	block[14] = S[tmp];
	/* Row 3 */
	tmp = block[15];
	block[15] = S[block[11]];
	block[11] = S[block[ 7]];
	block[ 7] = S[block[ 3]];
	block[ 3] = S[tmp];

	/*
	 * MixColumns
	 */
	for (i = lastround; i < 16; i += 4) /* lastround = 16 if it is the last round, 0 otherwise */
	{
		uint8_t *column = block + i;
		uint8_t tmp2 = column[0];
		tmp = column[0] ^ column[1] ^ column[2] ^ column[3];

		column[0] ^= tmp ^ xtime(column[0] ^ column[1]);
		column[1] ^= tmp ^ xtime(column[1] ^ column[2]);
		column[2] ^= tmp ^ xtime(column[2] ^ column[3]);
		column[3] ^= tmp ^ xtime(column[3] ^ tmp2);
	}

	/*
	 * AddRoundKey
	 */
	for (i = 0; i < 16; i++)
	{
		block[i] ^= round_key[i];
	}

}

/*
 * Compute the @(round + 1)-th round key in @next_key, given the @round-th key in @prev_key
 * @round in {0...9}
 * The ``master key'' is the 0-th round key
 */
void next_aes128_round_key(const uint8_t prev_key[16], uint8_t next_key[16], int round)
{
	/*Key Round*/
	int ronde,i;
	uint8_t* p_key_0 = prev_key;
	uint8_t* p_key_m1 = prev_key + AES_128_KEY_SIZE - AES_KEY_WORD_SIZE;

	p_key_0[0] ^= S[(p_key_m1[1])] ^ RC[round];
	p_key_0[1] ^= S[(p_key_m1[2])];
	p_key_0[2] ^= S[(p_key_m1[3])];
	p_key_0[3] ^= S[(p_key_m1[0])];

	for (ronde = 1; ronde < AES_128_KEY_SIZE / AES_KEY_WORD_SIZE; ++ronde)
	{
	  	p_key_m1 = p_key_0;
	    p_key_0 += AES_KEY_WORD_SIZE;

	    /* XOR in previous word */
	    p_key_0[0] ^= p_key_m1[0];
	    p_key_0[1] ^= p_key_m1[1];
	    p_key_0[2] ^= p_key_m1[2];
	    p_key_0[3] ^= p_key_m1[3];
	}
	for(i=0;i < 16;i++){
		next_key[i] = prev_key[i];
	}
}

/*
 * Compute the @round-th round key in @prev_key, given the @(round + 1)-th key in @next_key
 * @round in {0...9}
 * The ``master decryption key'' is the 10-th round key (for a full AES-128)
 */
void prev_aes128_round_key(const uint8_t next_key[16], uint8_t prev_key[16], int round)
{
	/*Inv Key Schedule*/
	int ronde;
	int counter;
	uint8_t* p_key_0 = next_key + AES_128_KEY_SIZE - AES_KEY_WORD_SIZE;
	uint8_t* p_key_m1 = p_key_0 - AES_KEY_WORD_SIZE;

	for (ronde = 1; ronde < AES_128_KEY_SIZE / AES_KEY_WORD_SIZE; ++ronde)
	{
		/* XOR in previous word */
		p_key_0[0] ^= p_key_m1[0];
		p_key_0[1] ^= p_key_m1[1];
		p_key_0[2] ^= p_key_m1[2];
		p_key_0[3] ^= p_key_m1[3];

		p_key_0 = p_key_m1;
		p_key_m1 -= AES_KEY_WORD_SIZE;
	}

	/* Rotate previous word and apply S-box. Also XOR Rcon for first byte. */
	p_key_m1 = next_key + AES_128_KEY_SIZE - AES_KEY_WORD_SIZE;
	p_key_0[0] ^= S[(p_key_m1[1])] ^ RC[round];
	p_key_0[1] ^= S[(p_key_m1[2])];
	p_key_0[2] ^= S[(p_key_m1[3])];
	p_key_0[3] ^= S[(p_key_m1[0])];

	int i;
	for(i=0;i<AES_128_KEY_SIZE;i++){
		prev_key[i]=next_key[i];
	}

	printf("Previous Key (Round %d): ", round);
	for(counter = 0; counter < AES_BLOCK_SIZE; counter++){
		printf("%x ",next_key[counter]);
	}
	printf("\n" );

}

/*
 * Encrypt @block with @key over @nrounds. If @lastfull is true, the last round includes MixColumn, otherwise it doesn't.$
 * @nrounds <= 10
 */
void aes128_enc(uint8_t block[AES_BLOCK_SIZE], const uint8_t key[AES_128_KEY_SIZE], unsigned nrounds, int lastfull)
{
	uint8_t ekey[32];
	int i, pk, nk;

	for (i = 0; i < 16; i++)
	{
		block[i] ^= key[i];
		ekey[i]   = key[i];
	}
	next_aes128_round_key(ekey, ekey + 16, 0);

	pk = 0;
	nk = 16;
	for (i = 1; i < nrounds; i++)
	{
		aes_round(block, ekey + nk, 0);
		pk = (pk + 16) & 0x10;
		nk = (nk + 16) & 0x10;
		next_aes128_round_key(ekey + pk, ekey + nk, i);
	}
	if (lastfull)
	{
		aes_round(block, ekey + nk, 0);
	}
	else
	{
		aes_round(block, ekey + nk, 16);
	}


}

void function_f(uint8_t block[AES_BLOCK_SIZE], const uint8_t key[AES_256_KEY_SIZE]) {
	uint8_t block1[AES_BLOCK_SIZE];
	uint8_t block2[AES_BLOCK_SIZE];
	uint8_t key1[AES_128_KEY_SIZE];
	uint8_t key2[AES_128_KEY_SIZE];
	int i = 0;

	/*Cut key into 2 keys of 128 bits*/
	for (i = 0; i < AES_128_KEY_SIZE; i++)
	{
		key1[i] = key[i];
	}
	for (i = AES_128_KEY_SIZE; i < AES_256_KEY_SIZE; i++)
	{
		key2[i%AES_128_KEY_SIZE] = key[i];
	}

	/*Copy block (x)*/
	memcpy(block1, block, AES_BLOCK_SIZE);
	memcpy(block2, block, AES_BLOCK_SIZE);

	/*Encrypt each block*/
	aes128_enc(block1, key1, 3, 0);
	aes128_enc(block2, key2, 3, 0);

	/*Display each block*/
	printf("Block1 : ");
	for (i = 0; i < 16; i++)
	{
		printf("%x", block1[i]);
	}
	printf("\n");

	printf("Block2 : ");
	for (i = 0; i < 16; i++)
	{
		printf("%x", block2[i]);
	}
	printf("\n");

    /*XOR block ciphers*/
	for (i = 0; i < 16; i++)
	{
		block[i] = block1[i] ^ block2[i];
	}

	printf("Block cipher: ");
	for (i = 0; i < 16; i++)
	{
		printf("%x", block[i]);
	}
	printf("\n");
}

bool isvalueinarray(uint8_t val, uint8_t* arr, int size) {
	int i;
	for (i=0;i<size;i++) {
		if (arr[i] == val) {
			return true;
		}
	}
	return false;
}

int main (int argc, char **argv) {
	/* Exercice 1 : Warming up --- Question 3 */
	printf("*** Exercice 1 : Warming up --- Question 3\n");
	uint8_t x[AES_BLOCK_SIZE] = {0x32, 0x43, 0xf6, 0xa8, 0x88, 0x5a, 0x30, 0x8d, 0x31, 0x31, 0x98, 0xa2, 0xe0, 0x37, 0x07, 0x34 };
	uint8_t key_256[AES_256_KEY_SIZE] = {0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6, 0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c, 0xff, 0x7e, 0x15, 0x16, 0xcc, 0xae, 0xd2, 0xa6, 0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c};

	function_f(x, key_256);
	printf("\n");

	/* Exercice 2 */
	printf("*** Exercice 2\n");
	uint8_t ind, i, j;
	uint8_t key[AES_128_KEY_SIZE] = {0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6, 0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c};
	uint8_t final_key[AES_128_KEY_SIZE];
	uint8_t potential_key[AES_128_KEY_SIZE];
	uint8_t tmp_key[AES_128_KEY_SIZE];
	uint8_t res1[AES_128_KEY_SIZE][AES_128_KEY_SIZE] = {0,0};
	uint8_t res2[AES_128_KEY_SIZE][AES_128_KEY_SIZE] = {0,0};
	uint8_t res3[AES_128_KEY_SIZE][AES_128_KEY_SIZE] = {0,0};

	for(i=0;i<3;i++) {
		srand(time(NULL));

		switch (i) {
			case 0:
				aes_attack(res1, key);
				break;
			case 1:
				aes_attack(res2, key);
				break;
			case 2:
				aes_attack(res3, key);
				break;
		}

		for(ind=0;ind<AES_BLOCK_SIZE;ind++) {
			for(j=0;j<AES_BLOCK_SIZE;j++) {
				if (res1[ind][j] != 0 && isvalueinarray(res1[ind][j], res2[ind], AES_BLOCK_SIZE) && isvalueinarray(res1[ind][j], res3[ind], AES_BLOCK_SIZE)) {
					potential_key[ind] = res1[ind][j];
				}
			}
		}

		printf("AES-ATTACK N°%d\n", i);
		sleep(1);
	}

	printf("\n");
	printf("Potential Key: \n");
	print_block(potential_key);

	prev_aes128_round_key(potential_key, final_key, 3);
	for(i=0;i<AES_128_KEY_SIZE;i++){
		tmp_key[i] = final_key[i];
	}
	prev_aes128_round_key(tmp_key, final_key, 2);
	for(i=0;i<AES_128_KEY_SIZE;i++){
		tmp_key[i] = final_key[i];
	}
	prev_aes128_round_key(tmp_key, final_key, 1);
	for(i=0;i<AES_128_KEY_SIZE;i++){
		tmp_key[i] = final_key[i];
	}
	prev_aes128_round_key(tmp_key, final_key, 0);
	printf("\n");

	printf("Initial Key: \n");
	print_block(final_key);

	return 0;
}
