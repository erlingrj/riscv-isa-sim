#ifndef IBDA_H
#define IBDA_H
struct ibda_params {
    bool ist_fully_associative;
    bool ist_set_associative;
    reg_t ist_sz;
    reg_t ist_ways;
    reg_t ist_wp;
    reg_t tag_sz;
    reg_t ist_vb_sz;
    reg_t ist_sets;
    bool ist_vb;    
    bool ibda_compare_perfect;
    bool ist_perfect;
    bool ibda_ist_hash_xor_david;
    reg_t ibda_tag_bits;
    reg_t trace_level;
    bool calculate_instruction_entropy;
    bool calculate_ist_instruction_entropy;

    reg_t ibda_hash_pc_mask;
    reg_t ibda_hash_insn_mask;
    bool ibda_simple_hash;
    bool ibda_binary_matrix_hash;
    bool ibda_no_hash;
    reg_t seed;

    bool count_wp_usage;

    bool ibda_hash_bloom;
    reg_t bloom_k;
    reg_t bloom_m;
    float bloom_fp_rate;
  };

#endif