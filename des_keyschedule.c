/* ===================================================================== */
/* This file is a little helper to compute DES key scheduling            */
/* from the first round key                                              */
/* Original authors: Charles Hubain <me@haxelion.eu>  2016               */
/*                   Philippe Teuwen <phil@teuwen.org> 2016              */
/*                                                                       */
/* Usage:                                                                */
/* des_keyschedule DES_key_in_hex                                        */
/* des_keyschedule Round1_key_in_hex plaintext_in_hex ciphertext_in_hex  */
/*                                                                       */
/* Examples:                                                             */
/* des_keyschedule 3032343234363236                                      */
/* des_keyschedule 502CACC603C7 1122334455667788 c403d32e2bc6cfee        */
/* des_keyschedule 14 02 32 2C 31 20 0F 07 \                             */
/*                 1122334455667788 c403d32e2bc6cfee                     */
/*                                                                       */
/* Note that parity bits are always ignored                              */
/*                                                                       */
/* Based on the unlicensed DES code https://github.com/mimoo/DES         */
/* (minus the bugs)                                                      */
/* and released under the following licensing terms:                     */
/*                                                                       */
/* This is free and unencumbered software released into the public domain*/
/*                                                                       */
/* Anyone is free to copy, modify, publish, use, compile, sell, or       */
/* distribute this software, either in source code form or as a compiled */
/* binary, for any purpose, commercial or non-commercial, and by any     */
/* means.                                                                */
/*                                                                       */
/* In jurisdictions that recognize copyright laws, the author or authors */
/* of this software dedicate any and all copyright interest in the       */
/* software to the public domain. We make this dedication for the benefit*/
/* of the public at large and to the detriment of our heirs and          */
/* successors. We intend this dedication to be an overt act of           */
/* relinquishment in perpetuity of all present and future rights to this */
/* software under copyright law.                                         */
/*                                                                       */
/* THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,       */
/* EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF    */
/* MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.*/
/* IN NO EVENT SHALL THE AUTHORS BE LIABLE FOR ANY CLAIM, DAMAGES OR     */
/* OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, */
/* ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR */
/* OTHER DEALINGS IN THE SOFTWARE.                                       */
/*                                                                       */
/* For more information, please refer to <http://unlicense.org/>         */
/* ===================================================================== */

#include "DES.c"
#include <inttypes.h>
#include <stdlib.h>
#include <stdio.h>


int main(int argc, char **argv) {
    uint64_t key, round_key, next_key, possible_keys[256], plain, cipher, scratch;
    if((argc != 2) && (argc != 4) && (argc != 11)) {
        printf("Usage: \n%s DES_key_in_hex\n", argv[0]);
        printf("%s Round1_key_in_hex plaintext_in_hex ciphertext_in_hex\n", argv[0]);
        printf("%s R1.1 R1.2 R1.3 R1.4 R1.5 R1.6 R1.7 R1.8 plaintext_in_hex ciphertext_in_hex\n", argv[0]);
        return EXIT_FAILURE;
    }
    if (argc==2) { // normal mode
        key = strtoull(argv[1], NULL, 16);
        printf("Input key: %016" PRIx64 "\n", key);
        round_key = key;
        key_schedule(&round_key, &next_key, 0);
    } else { // reverse mode
        if (argc==4) { // 48-bit round key
            round_key = strtoull(argv[1], NULL, 16) << 16;
            plain = strtoull(argv[2], NULL, 16);
            cipher = strtoull(argv[3], NULL, 16);
        } else { // 8 * 6-bit round key
            round_key = 0;
            int i;
            for (i=0;i<8;i++) {
                round_key <<=6;
                round_key += strtoul(argv[i+1], NULL, 16);
            }
            round_key <<= 16;
            plain = strtoull(argv[9], NULL, 16);
            cipher = strtoull(argv[10], NULL, 16);
        }
    }
    printf("Round1 key: %08X%04X == %02X %02X %02X %02X %02X %02X %02X %02X\n",
        (uint32_t)(round_key >> 32), (uint32_t)((round_key >> 16) & 0xffff),
        (uint8_t)((round_key >> (42+16)) & 0x3F),
        (uint8_t)((round_key >> (36+16)) & 0x3F),
        (uint8_t)((round_key >> (30+16)) & 0x3F),
        (uint8_t)((round_key >> (24+16)) & 0x3F),
        (uint8_t)((round_key >> (18+16)) & 0x3F),
        (uint8_t)((round_key >> (12+16)) & 0x3F),
        (uint8_t)((round_key >> ( 6+16)) & 0x3F),
        (uint8_t)((round_key >> ( 0+16)) & 0x3F));
    if (argc==2) { // normal mode
        return EXIT_SUCCESS;
    } else { // reverse mode
        printf("Plain:  %016" PRIx64 "\n", plain);
        printf("Cipher: %016" PRIx64 "\n", cipher);
        printf("Reversing key scheduling...\n");
        reverse_key_schedule(round_key, 0, possible_keys);
        for(int i = 0; i < 256; i++) {
            scratch = plain;
            round_key = possible_keys[i];
            Permutation(&scratch, 1);
            for (int j=0;j<16;j++) {
                key_schedule(&round_key, &next_key, j);
                rounds(&scratch, round_key);
                round_key = next_key;
            }
            scratch = (scratch >> 32) + (scratch << 32);
            Permutation(&scratch, 0);
//            printf("%016" PRIx64 ": %016" PRIx64 " -> %016" PRIx64 " =? %016" PRIx64 "\n",
//                possible_keys[i], plain, scratch, cipher);
            if(scratch == cipher) {
                printf("Key found at offset %d: ", i);
                printf("%016" PRIx64 "\n", possible_keys[i]);
                return EXIT_SUCCESS;
            }
        }
        printf("Key not found :(\n");
        return EXIT_FAILURE;
    }
}
