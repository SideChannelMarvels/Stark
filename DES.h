// 
/* Unlicensed original code taken from https://github.com/mimoo/DES
 * Original contributors:
 * - David Wong, moi@davidwong.fr
 * - Jacques Monin, jacques.monin@u-bordeaux.fr
 * - Hugo Bonnin, hugo.bonnin@u-bordeaux.fr
 *
 * Additional modifications by: Charles Hubain <github@haxelion.eu>
*/

// Implementation of DES coded by:
//     - David Wong, moi@davidwong.fr
//     - Jacques Monin, jacques.monin@u-bordeaux.fr
//     - Hugo Bonnin, hugo.bonnin@u-bordeaux.fr
//
#include <inttypes.h>
#include <stdbool.h>

#ifndef DES_H
#define DES_H

//////////////////////////////////////////////////////
//               USEFUL DEFINES                    //
////////////////////////////////////////////////////

#define FIRSTBIT 0x8000000000000000 // 1000000000...

//////////////////////////////////////////////////////
//                 PROTOTYPES                      //
////////////////////////////////////////////////////

// Addbit helper
// Takes the bit number "position_from" from "from"
// adds it to "block" in position "position_to"
void addbit(uint64_t *block, uint64_t from,
            int position_from, int position_to);

// Initial and Final Permutations
void Permutation(uint64_t* data, bool initial);

// Verify if the parity bits are okay
bool key_parity_verify(uint64_t key);

// Key Schedule ( http://en.wikipedia.org/wiki/File:DES-key-schedule.png )
// input :
//   * encrypt : false if decryption
//   * next_key : uint64_t next_key 0
//   * round : [[0, 15]]
// changes :
//   * [key] is good to be used in the XOR in the rounds
//   * [next_key] is the combined leftkey+rightkey to be used
//     in the key_schedule for next round
void key_schedule(uint64_t* key, uint64_t* next_key, int round);

/* Reverse the key schedule from a round key and gives the 256 possible keys as output.
*/
void reverse_key_schedule(uint64_t round_key, int round, uint64_t* possible_keys);

void rounds(uint64_t *data, uint64_t key);

#endif
