/*
 * sabc.h
 *
 *  Created on: Oct 8, 2012
 *      Author: rune
 */

#ifndef SABC_H_
#define SABC_H_



#endif /* SABC_H_ */

int create_address_from_string(const unsigned char *string,
		unsigned char *address,
		unsigned char *priv_key,
		EC_GROUP *precompgroup,
		bool base58,
		bool debug);
void print_hex(u_int8_t * buffer, unsigned int len);
void base58_encode(unsigned char *data, unsigned int len, char *result);
void prepare_for_address(unsigned char *data, int datalen, char start_byte);
