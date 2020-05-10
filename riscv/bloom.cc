#include "bloom.h"

BloomFilter::BloomFilter(
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
    )
    : k(k), m(m), seed(seed), 
    random(random), compare_perfect(compare_perfect), 
    false_positives(false_positives), false_negatives(false_negatives), bloom_flushes(bloom_flushes)
{

    this->n_max = (-m * log(1 - pow(fp_rate, 1.0 / k)));


    this->hash_funcs = new IbdaHashBinaryMatrix *[k];
    for (int i = 0; i <k; ++i) {
        this->hash_funcs[i] = new IbdaHashBinaryMatrix(
            (int) log2(m),
            pc_mask,
            insn_mask,
            seed + i,
            random
        );
    }

    this->ist = new std::bitset<MAX_BLOOM_FILTER> *[k];
    for (int i = 0; i<k; ++i) {
        this->ist[i] = new std::bitset<MAX_BLOOM_FILTER>;
    }
    this->ist_counter = 0;


    if (compare_perfect) {
        this->ist_tag_gm = new std::unordered_set<reg_t>;
    }

}

void BloomFilter::flush() {
    for (int i = 0; i<k; ++i) {
        this->ist[i]->reset();
    }
    this->ist_counter = 0;
    (*(this->bloom_flushes))++;
}

void BloomFilter::add(reg_t pc, reg_t insn) {
    // Combine pc and insn to correct mask
    reg_t hash_in = this->hash_funcs[0]->combine(pc,insn);

    // Check if we need to flush
    if (this->ist_counter >= this->n_max) {
        this->flush();
    }


    // Loop through hash functions and set the correct bits
    for (int i = 0; i<this->k; ++i) {
        this->ist[i]->set(this->hash_funcs[i]->_hash(hash_in));
    }

    // Add to perfect IBDA also
    if (this->compare_perfect) {
        this->ist_tag_gm->insert(pc);
    }
    // Increment counter
    this->ist_counter++;
}



bool BloomFilter::exists(reg_t pc, reg_t insn) {
    reg_t hash_in = this->hash_funcs[0]->combine(pc,insn);

    bool found = true;
    for (int i = 0; i<k; ++i) {
        if((this->ist[i]->test(this->hash_funcs[i]->_hash(hash_in))) == 0) {
            found =  false;
        }
    }

    if (this->compare_perfect) {
        std::unordered_set<reg_t>::iterator in_ist = this->ist_tag_gm->find(pc);
          if (in_ist != this->ist_tag_gm->end()) {
            if (!found) {
                (*(this->false_negatives))++;
            }
          } else {
              if (found) {
                (*(this->false_positives))++;
              }
          }
    }
    return found;
}
