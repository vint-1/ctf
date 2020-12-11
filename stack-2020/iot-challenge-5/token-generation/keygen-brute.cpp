
// Used by Sig0ct for Stack the Flags IOT-RSA Challenge
// Least Significant First byte order is assumed

/* (c) 1999-3001 I.C. Wiener */
/* modified by vint */

#ifdef _MSC_VER
    #pragma intrinsic           (_lrotr, _lrotl)
#else /* GCC or CC */
    #define __int64             long long
    #define __forceinline       __inline__
    #define _lrotr(x, n)        ((((unsigned long)(x)) >> ((int) ((n) & 31))) | (((unsigned long)(x)) << ((int) ((-(n)) & 31))))
    #define _lrotl(x, n)        ((((unsigned long)(x)) << ((int) ((n) & 31))) | (((unsigned long)(x)) >> ((int) ((-(n)) & 31))))
#endif

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <iterator>
#include <vector>
#include <unordered_map>
#include <iostream>
#include <algorithm>

#define ror32(x, n)             _lrotr (x, n)
#define rol32(x, n)             _lrotl (x, n)
#define bswap32(x)              (rol32 ((unsigned long)(x), 8) & 0x00ff00ff | ror32 ((unsigned long)(x), 8) & 0xff00ff00)

static __forceinline unsigned char      ror8 (const unsigned char x, const int n) { return (x >> (n & 7)) | (x << ((-n) & 7)); }
static __forceinline unsigned __int64   rol64 (const unsigned __int64 x, const int n) { return (x << (n & 63)) | (x >> ((-n) & 63)); }
static __forceinline unsigned __int64   bswap64 (const unsigned __int64 x) { unsigned long a = (unsigned long) x, b = (unsigned long) (x >> 32); return (((unsigned __int64) bswap32 (a)) << 32) | bswap32(b); }

typedef union _OCTET
{
    unsigned __int64            Q[1];
    unsigned long               D[2];
    unsigned short              W[4];
    unsigned char               B[8];
}   OCTET;

void securid_expand_key_to_4_bit_per_byte (const OCTET source, char *target)
{
    int     i;

    for (i = 0; i < 8; i++)
    {
        target[i*2  ] = source.B[i] >> 4;
        target[i*2+1] = source.B[i] & 0x0F;
    }
}

void securid_expand_data_to_1_bit_per_byte (const OCTET source, char *target)
{
    int     i, j, k;

    for (i = 0, k = 0; i < 8; i++) for (j = 7; j >= 0; j--) target[k++] = (source.B[i] >> j) & 1;
}

void securid_reassemble_64_bit_from_64_byte (const unsigned char *source, OCTET *target)
{
    int     i = 0, j, k = 0;

    for (target->Q[0] = 0; i < 8; i++) for (j = 7; j >= 0; j--) target->B[i] |= source[k++] << j;
}

void securid_permute_data (OCTET *data, const OCTET key)
{
    unsigned char       bit_data[128];
    unsigned char       hex_key[16];

    unsigned long       i, k, b, m, bit;
    unsigned char       j;
    unsigned char       *hkw, *permuted_bit;

    memset (bit_data, 0, sizeof (bit_data));

    securid_expand_data_to_1_bit_per_byte (*data, (char *)bit_data);
    securid_expand_key_to_4_bit_per_byte (key, (char *)hex_key);

    for (bit = 32, hkw = hex_key, m = 0; bit <= 32; hkw += 8, bit -= 32)
    {
        permuted_bit = bit_data + 64 + bit;
        for (k = 0, b = 28; k < 8; k++, b -= 4)
        {
            for (j = hkw[k]; j; j--)
            {
                bit_data[(bit + b + m + 4) & 0x3F] = bit_data[m];
                m = (m + 1) & 0x3F;
            }

            for (i = 0; i < 4; i++)
            {
                permuted_bit[b + i] |= bit_data[(bit + b + m + i) & 0x3F];
            }
        }
    }

    securid_reassemble_64_bit_from_64_byte (bit_data + 64, data);
}

void securid_do_4_rounds (OCTET *data, OCTET *key)
{
    unsigned char       round, i, j;
    unsigned char       t;

    for (round = 0; round < 4; round++)
    {
        for (i = 0; i < 8; i++)
        {
            for (j = 0; j < 8; j++)
            {
                if ((((key->B[i] >> (j ^ 7)) ^ (data->B[0] >> 7)) & 1) != 0)
                {
                    t = data->B[4];
                    data->B[4] = 100 - data->B[0];
                    data->B[0] = t;
                }
                else
                {
                    data->B[0] = (unsigned char) (ror8 ((unsigned char) (ror8 (data->B[0], 1) - 1), 1) - 1) ^ 
data->B[4];
                }
                data->Q[0] = bswap64 (rol64 (bswap64 (data->Q[0]), 1));
            }
        }
        key->Q[0] ^= data->Q[0];
    }
}

void securid_convert_to_decimal (OCTET *data, const OCTET key)
{
    unsigned long       i;
    unsigned char       c, hi, lo;

    c = (key.B[7] & 0x0F) % 5;

    for (i = 0; i < 8; i++)
    {
        hi = data->B[i] >>   4;
        lo = data->B[i] & 0x0F;
        c = (c + (key.B[i] >>   4)) % 5; if (hi > 9) data->B[i] = ((hi = (hi - (c + 1) * 2) % 10) << 4) | lo;
        c = (c + (key.B[i] & 0x0F)) % 5; if (lo > 9) data->B[i] = (lo = ((lo - (c + 1) * 2) % 10)) | (hi << 4);
    }
}

void securid_hash_data (OCTET *data, OCTET key, unsigned char convert_to_decimal)
{
    securid_permute_data (data, key); // data bits are permuted depending on the key
    securid_do_4_rounds (data, &key); // key changes as well
    securid_permute_data (data, key); // final permutation is based on the new key
    if (convert_to_decimal)
        securid_convert_to_decimal (data, key); // decimal conversion depends on the key too
}

void securid_hash_time (unsigned long time, OCTET *hash, OCTET key)
{
    hash->B[0] = (unsigned char) (time >> 16);
    hash->B[1] = (unsigned char) (time >> 8);
    hash->B[2] = (unsigned char) time;
    hash->B[3] = (unsigned char) time;
    hash->B[4] = (unsigned char) (time >> 16);
    hash->B[5] = (unsigned char) (time >> 8);
    hash->B[6] = (unsigned char) time;
    hash->B[7] = (unsigned char) time;

    securid_hash_data (hash, key, 1);
}

unsigned char hex (const char c)
{
    unsigned char n = c - '0';

    if (n < 10) return n;
    n -= 7;
    if ((n > 9) && (n < 16)) return n;
    n -= 32;
    if ((n > 9) && (n < 16)) return n;
    exit (17);
}

unsigned char read_line (FILE *fi, OCTET *outb)
{
    unsigned char       n;
    unsigned long       i;
    char                ins[80], *s;

    if (!fgets (ins, sizeof (ins), fi)) return -1;
    s = ins;
    if (*s == '#') s++;
    if (strncmp (ins, "0000:", 5) == 0) return -1;
    for (i = 0; i < 38; i++)
    {
        n = hex (*s++) << 4;
        n |= hex (*s++);
        outb->B[i] = n;
    }

    // securid bullshit import file decryption (how much do they pay their programmers???)
    // anyway, I replaced their 16 stupid xor-D69E36D2/rol-1 "rounds" with one rol-16/xor
    // doing exactly the same thing (I wonder what they used to generate their token secrets? ;)

    // btw, we ignore the last two bytes that are just a silly checksum

    for (i = 0; i < 9; i++) outb->D[i] = rol32 (outb->D[i], 16) ^ 0x88BF88BF;
    return 0;
}

unsigned long convert_time(signed long t){
    signed long t0=1604889720;
    return ( ((t-t0)/120)*3*120 ) + t0;
}

signed long unconvert_time(signed long t){
    signed long t0=1604889720;
    return ( ((t-t0)/(120*3))*120 ) + t0;
}

bool cmp(std::pair<int,int>& a,std::pair<int,int>& b){
    return a.second>b.second;
}

std::vector<std::pair<int,int>> map_to_vector(std::unordered_map<int,int> map1){
    using namespace std;
    vector<pair<int,int>> output;
    for(auto it=map1.begin();it!=map1.end();it++){
        // printf("%06d:\t%d\n",it->first,it->second);
        output.push_back(*it);
    }
    return output;
}

void print_vector(std::vector<std::pair<int,int>> vect1){
    using namespace std;
    for(auto it=vect1.begin();it!=vect1.end();it++){
        printf("%06d\t%d\n",it->first,it->second);
    }
}

int main (int argc, char **argv)
{
    using namespace std;
    signed long         i, j, k, t, serial;
    OCTET               key, hi, hj, token, input, data[5];
    FILE                *fi;
    char                *s;

    // So, we need:
    // key needs to be set to the key: de ed a1 13 7a b0 12 02
    // j needs to be set to serial number, which is D[1] of key
    // input needs to be current 6-digit number on the token (supplied as base 10, read as base 16?)
    // time needs to be set to something close to token's time

    unsigned char keyb[]={0xde,0xed,0xa1,0x13,0x7a,0xb0,0x12,0x02}; //this is definitely correct
    // unsigned char keyb[]={0x02,0x12,0xb0,0x7a,0x13,0xa1,0xed,0xde};
    for (int xx=0;xx<8;xx++){
        key.B[xx]=keyb[xx];
    }
    // j = key.D[1];
    input.D[0] = strtoul ("461177", &s, 16);

    unsigned long timestamp=1604889890; //10:44:50
    // unsigned long timestamp=1604890010; //10:46:50

    // Magic number: 
    // Govtech founded on 1 Oct 2016, 9:06:50 GMT+8 
    // timestamp is 1475284010
    // magic number is therefore 24588066

    // t = (timestamp / 60 - 0x806880)*2;
       
    signed long t1=time(NULL);
    signed long t0=1604889720;
    printf("Time now: %s",ctime((time_t *)&t1));
    printf("T_0: %s",ctime((time_t *)&t0));
    unordered_map<int,int> freqMap;
    
    // for (unsigned long tx = t0-(200*3600); tx < t1+(200*3600); tx += 120)
    int number_of_keys=0;
    for (unsigned long tx = t0-(2*3600); tx < t1+(2*3600); tx += 120)
    {
        OCTET ans;
        signed long i_space=(tx / 60 - 0x806880)*2;
        securid_hash_time (i_space, &ans, key);

        time_t t1=60*((i_space)/2 + 0x806880);
        time_t t2=60*((i_space)/2 + 0x806880)+60;
        
        char new_key[7];
        snprintf(new_key,7,"%02X%02X%02X",ans.B[0], ans.B[1], ans.B[2]);
        int token_out=atoi(new_key);
        freqMap[token_out]++;
        number_of_keys++;
        // printf ("\t\t\t\t\t\t%d\n",token_out);
        // printf ("%s\t%lu\t%02X%02X%02X\n", strtok(ctime(&t1),"\n"), 60*((i_space)/2 + 0x806880), ans.B[0], ans.B[1], ans.B[2]);
        // printf ("%s\t%lu\t%02X%02X%02X\n", strtok(ctime(&t2),"\n"), 60*((i_space)/2 + 0x806880), ans.B[3], ans.B[4], ans.B[5]);

    }
    
    vector<pair<int,int>> freqVector;
    
    freqVector=map_to_vector(freqMap);
    printf("Total keys generated:\t%d\n",number_of_keys);
    printf("Number of unique keys:\t%d\n",(int)freqVector.size());

    sort(freqVector.begin(),freqVector.end(),cmp);
    print_vector(freqVector);
    return 0;
}

