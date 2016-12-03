# Stark
*Stark Industries is a technology company that develops and manufactures advanced weapon and defense technologies.*

The Stark repository is a collection of tools related to cryptanalysis.

## Key scheduling reversers

### DES

DES key scheduling reverser can

* print all round keys from the DES key;
* bruteforce the DES key from the first round key and a pair of plaintext/ciphertext.

Round keys (or subkeys) are 48-bit large and split into eight 6-bit values for mixing with the expanded state. 
So there are typically two possible representation of a subkey:

* one 48-bit word
* eight 6-bit words

Usage:

```
des_keyschedule DES_key_in_hex
des_keyschedule Round1_key_in_hex plaintext_in_hex ciphertext_in_hex
des_keyschedule R1.1 R1.2 R1.3 R1.4 R1.5 R1.6 R1.7 R1.8 plaintext_in_hex ciphertext_in_hex
```

Examples:

```
des_keyschedule 3032343234363236
des_keyschedule 502CACC603C7 1122334455667788 c403d32e2bc6cfee
des_keyschedule 14 02 32 2C 31 20 0F 07 1122334455667788 c403d32e2bc6cfee
```

### AES

AES key scheduling reverser can

* print all round keys from the AES key;
* print all round keys from any intermediate or final round key(s).

Usage:

```
aes_keyschedule AES_key_in_hex
aes_keyschedule Round_key(s)_in_hex Initial_round_key_number_between_0_and_10#11#13
```

The AES key size is deduced from the size of the parameter, so

* for AES-128, provide one round key and its index
* for AES-192, provide one round key concatenated with the first half of the next round key and the index of the starting round key
* for AES-256, provide two concatenated round keys and the index of the starting round key

Examples:

* AES-128: (provide 1 round key)

```
aes_keyschedule B1BA2737C83233FE7F7A7DF0FBB01D4A
aes_keyschedule 97F926D5677B324AC439D77C8B03FDF8 5
aes_keyschedule FAEF63792F9A97A1FB78C88C4CA7048F 10
```

* AES-192: (provide 1.5 round keys)

```
aes_keyschedule B1BA2737C83233FE7F7A7DF0FBB01D4A7835FA62BE9726A1
aes_keyschedule D42AAFEB1510F368D8AA1354A707697696D6CC20F7737995 5
aes_keyschedule 504B601C4EEB5C33B3D208B8E4966BA37B07118538961350 11
```

* AES-256: (provide 2 round keys)

```
aes_keyschedule B1BA2737C83233FE7F7A7DF0FBB01D4A7835FA62BE9726A1BB39F261BAC4729C
aes_keyschedule F2E96B6FD53C1BBB49D0990E6FF86927DF8F909C21310695C43D2751C133AC12 5
aes_keyschedule 4D69A4975189FCA00DB0AC8F686EE58C033BE6307A3C13C226DF38591EEAC857 13
```
