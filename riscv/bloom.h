#ifndef IST_H
#define IST_H

#ifndef reg_t
#include <stdint.h>
#include <assert.h>

typedef uint64_t reg_t;
#endif
#include "ibda_hash.h"
#include <unordered_set>
#include <bits/stdc++.h> 


#define MAX_BLOOM_FILTER 2048


class BloomFilter
{
public:
    BloomFilter(
        int k, //hash_funcs
        int m, //output bits
        float fp_rate,
        int seed,
        bool random,
        reg_t pc_mask,
        reg_t insn_mask,
        bool compare_perfect,
        reg_t * false_positives,
        reg_t * false_negatives,
        reg_t * bloom_flushes
    );
    void add(reg_t pc, reg_t insn);
    bool exists(reg_t pc, reg_t insn);
    void flush();

    void test_incr_fp(){(*(this->false_positives))++;}
    void test_incr_np(){(*(this->false_negatives))++;}
    std::bitset<MAX_BLOOM_FILTER>** get_bitset() {return this->ist;}
    int get_count() {return this->ist_counter;}
    int get_nmax() {return this->n_max;}

private:
    bool compare_perfect;
    int k;
    int m;
    int n_max;
    int seed;
    int random;
    
    IbdaHashBinaryMatrix **hash_funcs;
    std::bitset<MAX_BLOOM_FILTER> ** ist;
    int ist_counter;
    std::unordered_set<reg_t> * ist_tag_gm;

    reg_t *false_positives;
    reg_t *false_negatives;
    reg_t *bloom_flushes;
};


#endif