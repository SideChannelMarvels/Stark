/* ===================================================================== */
/* This file is a little helper to compute AES key scheduling            */
/* from any round key                                                    */
/* Original author:   Philippe Teuwen <phil@teuwen.org> 2016             */
/*                                                                       */
/* Usage:                                                                */
/* aes_keyschedule AES_key_in_hex                                        */
/* aes_keyschedule Round_key_in_hex Round_key_number_between_0_and_10    */
/*                                                                       */
/* Examples:                                                             */
/* aes_keyschedule 11223344556677881122334455667788                      */
/* aes_keyschedule 23D7F7B876B180306793B37432F5C4FC 1                    */
/* aes_keyschedule 43EDA420DD033E7627347DC2CC6E0B4E 9                    */
/* aes_keyschedule EAC68B6B37C5B51D10F1C8DFDC9FC391 10                   */
/*                                                                       */
/* Based on the Tiny AES128 in C https://github.com/kokke/tiny-AES128-C  */
/* and released under the same licensing terms:                          */
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




/*****************************************************************************/
/* Includes:                                                                 */
/*****************************************************************************/
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>


/*****************************************************************************/
/* Defines:                                                                  */
/*****************************************************************************/
// The number of columns comprising a state in AES. This is a constant in AES. Value=4
#define Nb 4

/*****************************************************************************/
/* Private variables:                                                        */
/*****************************************************************************/
// state - array holding the intermediate results during decryption.
// The array that stores the round keys.
static uint8_t RoundKey[240];

// The Key input to the AES Program
static uint8_t Key[32];

// The lookup-tables are marked const so they can be placed in read-only storage instead of RAM
// The numbers below can be computed dynamically trading ROM for RAM - 
// This can be useful in (embedded) bootloader applications, where ROM is often limited.
static const uint8_t sbox[256] =   {
  //0     1    2      3     4    5     6     7      8    9     A      B    C     D     E     F
  0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
  0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,
  0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
  0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75,
  0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84,
  0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
  0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8,
  0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2,
  0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
  0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb,
  0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,
  0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
  0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a,
  0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e,
  0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
  0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16 };

// The round constant word array, Rcon[i], contains the values given by 
// x to th e power (i-1) being powers of x (x is denoted as {02}) in the field GF(2^8)
// Note that i starts at 1, not 0).
static const uint8_t Rcon[11] = { 0x8d, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36 };


// This function produces Nb(Nr+1) round keys. The round keys are used in each round to decrypt the states. 
void KeyExpansion(uint8_t start, uint16_t AesSize)
{

  uint32_t i, j, k;
  uint8_t tempa[4]; // Used for the column/row operations
  uint8_t Nk = AesSize / 32;
  // Nr: The number of rounds in AES Cipher: 10, 12 or 14
  uint8_t Nr = Nk+6;
  start *=4;
  // The first round key is the key itself.
  for(i = start; i < (Nk+start); ++i)
  {
    RoundKey[(i * 4) + 0] = Key[((i-start) * 4) + 0];
    RoundKey[(i * 4) + 1] = Key[((i-start) * 4) + 1];
    RoundKey[(i * 4) + 2] = Key[((i-start) * 4) + 2];
    RoundKey[(i * 4) + 3] = Key[((i-start) * 4) + 3];
  }
  // All other round keys are found from the previous round keys.
  for(; (i < (Nb * (Nr + 1))); ++i)
  {
    for(j = 0; j < 4; ++j)
    {
      tempa[j]=RoundKey[(i-1) * 4 + j];
    }
    if (i % Nk == 0)
    {
      // This function rotates the 4 bytes in a word to the left once.
      // [a0,a1,a2,a3] becomes [a1,a2,a3,a0]

      // Function RotWord()
      {
        k = tempa[0];
        tempa[0] = tempa[1];
        tempa[1] = tempa[2];
        tempa[2] = tempa[3];
        tempa[3] = k;
      }

      // SubWord() is a function that takes a four-byte input word and 
      // applies the S-box to each of the four bytes to produce an output word.

      // Function Subword()
      {
        tempa[0] = sbox[tempa[0]];
        tempa[1] = sbox[tempa[1]];
        tempa[2] = sbox[tempa[2]];
        tempa[3] = sbox[tempa[3]];
      }

      tempa[0] =  tempa[0] ^ Rcon[i/Nk];
    }
    else if (Nk > 6 && i % Nk == 4)
    {
      // Function Subword()
      {
        tempa[0] = sbox[tempa[0]];
        tempa[1] = sbox[tempa[1]];
        tempa[2] = sbox[tempa[2]];
        tempa[3] = sbox[tempa[3]];
      }
    }
    RoundKey[i * 4 + 0] = RoundKey[(i - Nk) * 4 + 0] ^ tempa[0];
    RoundKey[i * 4 + 1] = RoundKey[(i - Nk) * 4 + 1] ^ tempa[1];
    RoundKey[i * 4 + 2] = RoundKey[(i - Nk) * 4 + 2] ^ tempa[2];
    RoundKey[i * 4 + 3] = RoundKey[(i - Nk) * 4 + 3] ^ tempa[3];
  }
  for(i=(Nk+start-1); i>(Nk-1); i--)
  {
    for(j = 0; j < 4; ++j)
    {
      tempa[j]=RoundKey[(i-1) * 4 + j];
    }
    if (i % Nk == 0)
    {
      // This function rotates the 4 bytes in a word to the left once.
      // [a0,a1,a2,a3] becomes [a1,a2,a3,a0]

      // Function RotWord()
      {
        k = tempa[0];
        tempa[0] = tempa[1];
        tempa[1] = tempa[2];
        tempa[2] = tempa[3];
        tempa[3] = k;
      }

      // SubWord() is a function that takes a four-byte input word and 
      // applies the S-box to each of the four bytes to produce an output word.

      // Function Subword()
      {
        tempa[0] = sbox[tempa[0]];
        tempa[1] = sbox[tempa[1]];
        tempa[2] = sbox[tempa[2]];
        tempa[3] = sbox[tempa[3]];
      }

      tempa[0] =  tempa[0] ^ Rcon[i/Nk];
    }
    else if (Nk > 6 && i % Nk == 4)
    {
      // Function Subword()
      {
        tempa[0] = sbox[tempa[0]];
        tempa[1] = sbox[tempa[1]];
        tempa[2] = sbox[tempa[2]];
        tempa[3] = sbox[tempa[3]];
      }
    }
    RoundKey[(i - Nk) * 4 + 0] = RoundKey[i * 4 + 0] ^ tempa[0];
    RoundKey[(i - Nk) * 4 + 1] = RoundKey[i * 4 + 1] ^ tempa[1];
    RoundKey[(i - Nk) * 4 + 2] = RoundKey[i * 4 + 2] ^ tempa[2];
    RoundKey[(i - Nk) * 4 + 3] = RoundKey[i * 4 + 3] ^ tempa[3];
  }
  for(j = 0; j < 16*(Nr+1); ++j)
  {
    if (j%16==0)
      printf("K%02i: ", j/16);
    printf("%02X", RoundKey[j]);
    if (j%16==15)
      printf("\n");
  }
}

unsigned char is_hex_char(char c)
{
    return (
        (c >= '0' && c <= '9') ||
        (c >= 'a' && c <= 'f') ||
        (c >= 'A' && c <= 'F')
    );
}

int main(int argc, char *argv[])
{
    uint8_t i;
    uint8_t round=0;
    if (argc<2) {
        printf("Usage: \n%s AES_key_in_hex\n", argv[0]);
        printf("%s Round_key(s)_in_hex Initial_round_key_number_between_0_and_10#11#13\n", argv[0]);
        printf("Examples:\n");
        printf("- AES-128: (provide 1 round key)\n");
        printf("  %s B1BA2737C83233FE7F7A7DF0FBB01D4A\n", argv[0]);
        printf("  %s 97F926D5677B324AC439D77C8B03FDF8 5\n", argv[0]);
        printf("  %s FAEF63792F9A97A1FB78C88C4CA7048F 10\n", argv[0]);
        printf("- AES-192: (provide 1.5 round keys)\n");
        printf("  %s B1BA2737C83233FE7F7A7DF0FBB01D4A7835FA62BE9726A1\n", argv[0]);
        printf("  %s D42AAFEB1510F368D8AA1354A707697696D6CC20F7737995 5\n", argv[0]);
        printf("  %s 504B601C4EEB5C33B3D208B8E4966BA37B07118538961350 11\n", argv[0]);
        printf("  Tip: check if the second half round key is the same as yours. If not => AES-256\n");
        printf("- AES-256: (provide 2 round keys)\n");
        printf("  %s B1BA2737C83233FE7F7A7DF0FBB01D4A7835FA62BE9726A1BB39F261BAC4729C\n", argv[0]);
        printf("  %s F2E96B6FD53C1BBB49D0990E6FF86927DF8F909C21310695C43D2751C133AC12 5\n", argv[0]);
        printf("  %s 4D69A4975189FCA00DB0AC8F686EE58C033BE6307A3C13C226DF38591EEAC857 13\n", argv[0]);
        return EXIT_FAILURE;
    }

    uint32_t arglen = strlen(argv[1]);
    if( (arglen != 32) && (arglen != 48) && (arglen != 64)) {
        printf("Error: AES_key must be 16, 24 or 32-byte long\n");
        return EXIT_FAILURE;
    }
    uint16_t AesSize = arglen * 4;
    for(i = 0; i < arglen; i += 2)
    {
        if(is_hex_char(argv[1][i]) == 0 || is_hex_char(argv[1][i + 1]) == 0)
            return EXIT_FAILURE;
        unsigned char str_bytes[3] = {
            argv[1][i],
            argv[1][i + 1],
            0
        };
        Key[ i / 2] = strtoul((const char*)str_bytes, NULL, 16);
    }

    if (argc > 2)
        round = atoi(argv[2]);
    KeyExpansion(round, AesSize);
}
