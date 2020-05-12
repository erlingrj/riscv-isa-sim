#ifndef IBDA_HASH_H
#define IBDA_HASH_H

#ifndef reg_t
#include <stdint.h>
#include <assert.h>
#include <stdio.h>

typedef uint64_t reg_t;
#endif

class IbdaHash
{
public:
    IbdaHash(  
               int bitsOut, 
                reg_t pc_mask,
                reg_t insn_mask
            ) 
    : bits_out(bitsOut), insn_mask(insn_mask), pc_mask(pc_mask)
{
    // The PC and Insn mask defines what is the number of bits 
    //  as the input to the hash function. (Used by BinaryMatrixpc_)
    int popcnt = 0;
    for (int i = 0; i <64; i++) {
        if ((pc_mask & 0x01) == 0x01) {
            ++popcnt;
        }
        if ((insn_mask & 0x01) == 0x01) {
            ++popcnt;
        }
        pc_mask >>= 1;
        insn_mask >>=1;
    }
    this->bits_in = popcnt;

}
    
    reg_t hash(reg_t pc, reg_t insn);
    reg_t combine(reg_t pc, reg_t insn);
    virtual reg_t _hash(reg_t in) = 0;

    // Helper function
    reg_t get_set_index(reg_t hash, int set_sz);
    reg_t get_tag(reg_t hash, int set_sz);

protected:
    int bits_in;
    int bits_out;
    reg_t pc_mask;
    reg_t insn_mask;
};


class IbdaHashSimple : public IbdaHash
{
public:
    IbdaHashSimple(
                int bitsOut, 
                reg_t pc_mask,
                reg_t insn_mask)
    : IbdaHash(bitsOut,pc_mask,insn_mask) {

    }
    reg_t _hash(reg_t in);
};



class IbdaHashBinaryMatrix : public IbdaHash
{
public:
    IbdaHashBinaryMatrix(
                int bitsOut, 
                reg_t pc_mask,
                reg_t insn_mask,
                int seed, 
                bool random);
    reg_t _hash(reg_t in);

private:
    int seed;
    reg_t * hash_matrix;

};


class IbdaHashNone : public IbdaHash
{
public:
    IbdaHashNone(reg_t pc_mask,
                   reg_t insn_mask
    ) : IbdaHash(0,pc_mask, insn_mask) {}
    reg_t _hash(reg_t in){return in;}
};



class IbdaHashXor : public IbdaHash
{
public:
       IbdaHashXor(reg_t pc_mask,
                   reg_t insn_mask
    ) : IbdaHash(0,pc_mask, insn_mask) {}
  
    reg_t _hash(reg_t in){return in;}


    reg_t get_set_index(reg_t hash, int set_sz) {
        reg_t res =  (((hash >> 1) ^ (hash >> (set_sz + 1 ))) & ((1 << set_sz) - 1));
        return res;
    }

    reg_t get_tag(reg_t hash, int set_sz) {
        return  hash >> (set_sz + 1);
    }

    
};

#endif