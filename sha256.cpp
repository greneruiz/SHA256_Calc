/// sha256.cpp : SHA256 Calculator
/// Based on NIST_FIPS 180-4 (https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.180-4.pdf)
/// G.Ruiz 2025-02-26 v0.0
///

#include "sha256.h"


/// Common Operations:
#define ROTL( n, x )	(( x << n ) | ( x << ( ( sizeof(x) * 8 ) - n )))
#define ROTR( n, x )	(( x >> n ) | ( x << ( ( sizeof(x) * 8 ) - n )))
#define SHR( n, x )		( x >> n )


/// SHA256 Functions:
#define CH( x, y, z )	(( x & y ) ^ ( ~x & z ))
#define MAJ( x, y, z )	(( x & y ) ^ ( x & z ) ^ ( y & z ))
#define SIGMAU0( x )	(ROTR( 2, x ) ^ ROTR( 13, x ) ^ ROTR( 22, x ))
#define SIGMAU1( x )	(ROTR( 6, x ) ^ ROTR( 11, x ) ^ ROTR( 25, x ))
#define SIGMAL0( x )	(ROTR( 7, x ) ^ ROTR( 18, x ) ^ SHR( 3, x ))
#define SIGMAL1( x )	(ROTR(17, x ) ^ ROTR( 19, x ) ^ SHR(10, x ))


#define MSGBLOCK_BITS 512
#define WORD_BITS 32
#define MSGDIGEST_BITS 256
#define MSGSCHED 64
#define HASHWORD 8



const uint32_t K[64] =
{
	0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
	0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
	0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
	0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
	0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
	0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
	0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
	0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
};


const uint32_t H0[8] = 
{
	0x6a09e667,
	0xbb67ae85,
	0x3c6ef372,
	0xa54ff53a,
	0x510e527f,
	0x9b05688c,
	0x1f83d9ab,
	0x5be0cd19
};


/// Pre-Process #0: Determine byte sizes
bool pre_pad( uint64_t msgSize_byte, uint64_t &newSize_byte, uint64_t &zeroPadSize )
{
	bool isWithinSet = true;

	uint64_t bitlen = msgSize_byte * 8;															/// get bit size of msg
	zeroPadSize = 448 - ( bitlen - ( ( bitlen / MSGBLOCK_BITS ) * MSGBLOCK_BITS ) + 1 );		/// Calculate how many zero-bits are to be padded
	newSize_byte = ( bitlen + zeroPadSize + 1 + 64 ) / 8;

	if( bitlen > pow( 2, 64 ) )
		isWithinSet = false;
	
	return isWithinSet;
}

/// Pre-Process #1: Padding the Message
/// Ensure that the message is a multiple of 512 bits.
/// Maximum message length: 2^64 bits
void pad_msg( uint8_t * msg, uint64_t msgSize_byte, uint64_t newSize_byte, uint64_t bzeros, uint8_t * padmsg )
{
	uint64_t bitlen = msgSize_byte * 8;										/// get bit size of msg
	uint64_t index = 0;														/// index counter for the padded message
	

	for( ; index < msgSize_byte; index++ )									/// Transfer msg to padmsg
	{
		padmsg[index] = msg[index];
	}

	padmsg[index] = 0x80;													/// Pad 0b1 and 7 zeroes
	bzeros -= 7;															/// The first seven pad-zeroes are already added
	index++;

	for( ; index < ( msgSize_byte + 1 + ( bzeros / 8 ) ); index++ )
	{
		padmsg[index] = 0x00;
	}

	for( uint8_t k = 0; k < 8; k++ )										/// Pad the bitlen value as dword (64bits)
	{
		padmsg[index] = ( bitlen >> ( 7 - k ) * 8 ) & 0xFF;
		index++;
	}
}


/// Pre-Process #2: Parsing the Message
/// The padded message must be parsed into N m-bit blocks M
void parse_msg( uint8_t * padmsg, uint64_t blksize, uint32_t ** parsedMsg )
{

	for( uint64_t i = 0; i < blksize; i++ )
	{
		parsedMsg[i] = new uint32_t[16];

		for( uint32_t j = 0; j < MSGBLOCK_BITS / WORD_BITS; j++ )
		{
			parsedMsg[i][j] =	(	padmsg[(( MSGBLOCK_BITS / 8 ) * i) + ( j * 4 ) ]	<< 24 ) |
								(	padmsg[(( MSGBLOCK_BITS / 8 ) * i) + ( j * 4 ) + 1]	<< 16 )	|
								(	padmsg[(( MSGBLOCK_BITS / 8 ) * i) + ( j * 4 ) + 2]	<< 8  ) |
									padmsg[(( MSGBLOCK_BITS / 8 ) * i) + ( j * 4 ) + 3];
		}
	}
}


/// SHA256 Algorithm:
/// 1. Instantiate **H and set the initial hash value H[0].
/// 2. Prepare the message schedule.
/// 3. Initialize the working variables with the (i-1)th hash value.
/// 4. Byte boogaloo.
/// 5. Compute for the intermediate hash.
/// 6. Repeat 2-5 for N times.
/// 7. H[N][7..0] is the digest. Convert to **uint8_t.
void sha256_algo( uint32_t ** M, uint64_t N, uint8_t * digest )
{
	uint32_t W[MSGSCHED];					/// Message schedule
	uint32_t a, b, c, d, e, f, g, h;		/// Working variables
	uint32_t ** H = new uint32_t*[N + 1];	/// Hash value [N..0][7..0]


	/// Instantiate **H and set the initial hash value H[0]:
	for( uint64_t i = 0; i <= N; i++ )
	{
		H[i] = new uint32_t[HASHWORD];

		if( i == 0 )
		{
			for( uint8_t j = 0; j < HASHWORD; j++ )
			{
				H[i][j] = H0[j];
			}
		}
	}

	for( uint64_t i = 1; i <= N; i++ )					
	{
		/// Prepare the message schedule:
		for( uint8_t t = 0; t < MSGSCHED; t++ )
		{
			if( t < 16 )
				W[t] = M[i - 1][t];
			else
				W[t] = SIGMAL1( W[t - 2] ) + W[t - 7] + SIGMAL0( W[t - 15] ) + W[t - 16];
		}


		/// Initialize the working variables with the (i-1)th hash value:
		a = H[i - 1][0];
		b = H[i - 1][1];
		c = H[i - 1][2];
		d = H[i - 1][3];
		e = H[i - 1][4];
		f = H[i - 1][5];
		g = H[i - 1][6];
		h = H[i - 1][7];


		/// Byte boogaloo:
		for( uint8_t t = 0; t < MSGSCHED; t++ )
		{
			uint32_t T1 = h + SIGMAU1( e ) + CH( e, f, g ) + K[t] + W[t];
			uint32_t T2 = SIGMAU0( a ) + MAJ( a, b, c );
			h = g;
			g = f;
			f = e;
			e = d + T1;
			d = c;
			c = b;
			b = a;
			a = T1 + T2;
		}


		/// Compute for the intermediate hash:
		H[i][0] = a + H[i - 1][0];
		H[i][1] = b + H[i - 1][1];
		H[i][2] = c + H[i - 1][2];
		H[i][3] = d + H[i - 1][3];
		H[i][4] = e + H[i - 1][4];
		H[i][5] = f + H[i - 1][5];
		H[i][6] = g + H[i - 1][6];
		H[i][7] = h + H[i - 1][7];
	}

	/// H[N][7..0] is the digest. Convert to *uint8_t:
	for( uint8_t x = 0; x < MSGDIGEST_BITS / HASHWORD; x++ )
	{
		digest[x] = H[N][x / 4];
	}

	for( uint8_t x = 0; x < HASHWORD; x++ )
	{
		digest[(x * 4) + 3] =	H[N][x]			& 0xFF;
		digest[(x * 4) + 2] = ( H[N][x] >> 8 )	& 0xFF;
		digest[(x * 4) + 1] = ( H[N][x] >> 16 )	& 0xFF;
		digest[(x * 4) + 0] = ( H[N][x] >> 24 )	& 0xFF;
	}


	/// Cleanup:
	for( uint64_t z = 0; z <= N; z++ )
	{
		delete[] H[z];
	}
	delete[] H;
}


/// SHA256 algorithm
/// Message schedule : 64 32b words
/// Variables : 8 32b words
/// Hash value : 8 32b words
bool sha256( uint8_t * msg, uint64_t msg_ByteSize, uint8_t * digest )
{
	uint64_t newsize = 0;
	uint64_t zeroPadSize = 0;

	if( !pre_pad( msg_ByteSize, newsize, zeroPadSize ) )
		return false;
	
	uint8_t * padmsg = new uint8_t[newsize];
	pad_msg( msg, msg_ByteSize, newsize, zeroPadSize, padmsg );


	uint64_t blksize = ( newsize / ( WORD_BITS / 8 ) ) / 16;
	uint32_t ** parsemsg = new uint32_t*[blksize];
	parse_msg( padmsg, blksize, parsemsg );
	
	
	sha256_algo( parsemsg, blksize, digest );
	

	for( uint64_t z = 0; z < blksize; z++ )
	{
		delete[] parsemsg[z];
	}
	delete[] parsemsg;
	delete[] padmsg;


	return true;
}