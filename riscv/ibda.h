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
int ist_sets;
reg_t ibda_tag_pc_bits;
bool ist_vb;
bool ibda_tag_pc;
bool ibda_compare_perfect;
bool ist_perfect;
int trace_level;
  };

#endif