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
    bool dump_instruction_trace;
    bool dump_load_slice_instruction_trace;
  };

#endif