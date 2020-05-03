#include "ibda_hash.h"
#include <stdio.h>
#include <stdlib.h>
#include <random>


reg_t IbdaHash::hash(reg_t pc, reg_t insn) {
    reg_t input = this->combine(pc, insn);
    return this->_hash(input); 
}

reg_t IbdaHash::combine(reg_t pc, reg_t insn) {
    reg_t result = 0;
    reg_t pc_mask = this->pc_mask;
    reg_t insn_mask = this->insn_mask;

    int j = 0;
    for (int i = 0; i <64; i++) {
        if (pc_mask & 0x01 == 0x01) {
            result |= (((pc >> i) & 0x01) << j);
            ++j;
        }
        pc_mask >>= 1;
    }

    for (int i = 0; i<32; i++) {
        if ((insn_mask & 0x01) == 0x01) {
            result |= (((insn >> i) & 0x01) << j);
            ++j;
        }
        insn_mask >>= 1;
    }
    printf("%i : %i\n",j,this->bits_in);
    assert(j == this->bits_in);
    return result;

}

reg_t IbdaHash::get_set_index(reg_t hash, int set_sz) {
    return hash & ((1 << set_sz) - 1);
}

reg_t IbdaHash::get_tag(reg_t hash, int set_sz) {
    return (hash & ~((1 << set_sz) - 1)) >> set_sz;
}



reg_t IbdaHashSimple::_hash(reg_t in) {
    
    return (in & ( (1ULL << (this->bits_out )) - 1) );
    
}

IbdaHashBinaryMatrix::IbdaHashBinaryMatrix(
                int bitsOut, 
                reg_t pc_mask,
                reg_t insn_mask,
                int seed, 
                bool random)
: IbdaHash(bitsOut,pc_mask, insn_mask) {
    
    if (random) {
        this->seed = seed;
        /* Seed */
        std::random_device rd;

        /* Random number generator */
        std::default_random_engine generator(rd());
        /* Distribution on which to apply the generator */
        std::uniform_int_distribution<reg_t> distribution(0,0xFFFFFFFFFFFFFFFF);

        this->hash_matrix = new reg_t[this->bits_in];

        for (int i = 0; i<this->bits_in; ++i) {
            this->hash_matrix[i] = distribution(generator);
        }
    } else {
        this->hash_matrix = new reg_t[this->bits_in];
        this->hash_matrix[0] = 0x6FFFFFFFFFFFFFFF;
        this->hash_matrix[1] = 0xAFFFFFFFFFFFFFFF;
        this->hash_matrix[2] = 0x4FFFFFFFFFFFFFFF; 
        this->hash_matrix[3] = 0x6FFFFFFFFFFFFFFF;
    }
     
}


reg_t IbdaHashBinaryMatrix::_hash(reg_t in) {
    reg_t sum = 0;
    for (int i = 0; i < this->bits_in; i++)
    {
        if ((in & 0x01) == 0x01)
        {
            sum ^=this->hash_matrix[i];
        }
        in >>= 1;
    }
    return sum>>(64 - this->bits_out);
}