// See LICENSE for license details.

#include "processor.h"
#include "extension.h"
#include "common.h"
#include "config.h"
#include "simif.h"
#include "mmu.h"
#include "disasm.h"
#include <cinttypes>
#include <cmath>
#include <cstdlib>
#include <iostream>
#include <assert.h>
#include <limits.h>
#include <stdexcept>
#include <string>
#include <algorithm>
#include <stdarg.h>

#undef STATE
#define STATE state



//printf("trace_level=%d\nist_sz=%lu\nist_ways=%lu\nist_wp=%lu\nibda_tag_pc=%d\nist_perfect=%d\nist_fully_associative=%d\nist_set_associative=%d\nist_vb=%d\nist_vb_sz=%lu\nibda_compare_perfect=%d\n",
//      ibda_p.trace_level, ibda_p.ist_sz, ibda_p.ist_ways, ibda_p.ist_wp, ibda_p.ibda_tag_pc,ibda_p.ist_perfect, ibda_p.ist_fully_associative, ibda_p.ist_set_associative, ibda_p.ist_vb, ibda_p.ist_vb_sz, ibda_p.ibda_compare_perfect);

void state_t::debug_print(const char *fmt, ...) {
  
    if (ibda_p.trace_level > 0) {
      va_list args;
      va_start(args, fmt);
      fprintf(stderr,fmt, args);
      va_end(args);
    }
}

processor_t::processor_t(const char* isa, const char* varch, simif_t* sim,
                         uint32_t id, struct ibda_params ibda, bool halt_on_reset)
  : debug(false), halt_request(false), sim(sim), ext(NULL), id(id),
  halt_on_reset(halt_on_reset), last_pc(1), executions(1)
{
  VU.p = this;
  parse_isa_string(isa);
  parse_varch_string(varch);
  register_base_instructions();
  mmu = new mmu_t(sim, this);


  disassembler = new disassembler_t(max_xlen);
  if (ext)
    for (auto disasm_insn : ext->get_disasms())
      disassembler->add_insn(disasm_insn);

  
  reset(ibda);
}

processor_t::~processor_t()
{
#ifdef RISCV_ENABLE_HISTOGRAM
  if (histogram_enabled)
  {
    fprintf(stderr, "PC Histogram size:%zu\n", pc_histogram.size());
    for (auto it : pc_histogram)
      fprintf(stderr, "%0" PRIx64 " %" PRIu64 "\n", it.first, it.second);
  }
#endif

  delete mmu;
  delete disassembler;
}

static void bad_isa_string(const char* isa)
{
  fprintf(stderr, "error: bad --isa option %s\n", isa);
  abort();
}

static void bad_varch_string(const char* varch)
{
  fprintf(stderr, "error: bad --varch option %s\n", varch);
  abort();
}

static int parse_varch(std::string &str){
  int val = 0;
  if(!str.empty()){
    std::string sval = str.substr(1);
    val = std::stoi(sval);
    if ((val & (val - 1)) != 0) // val should be power of 2
      bad_varch_string(str.c_str());
  }else{
    bad_varch_string(str.c_str());
  }
  return val;
}

void processor_t::parse_varch_string(const char* s)
{
  std::string str, tmp;
  for (const char *r = s; *r; r++)
    str += std::tolower(*r);

  std::string delimiter = ":";

  size_t pos = 0;
  int vlen = 0;
  int elen = 0;
  int slen = 0;
  std::string token;
  while (!str.empty() && token != str) {
    pos = str.find(delimiter);
    if (pos == std::string::npos){
      token = str;
    }else{
      token = str.substr(0, pos);
    }
    if (token[0] == 'v'){
      vlen = parse_varch(token);
    }else if (token[0] == 'e'){
      elen = parse_varch(token);
    }else if (token[0] == 's'){
      slen = parse_varch(token);
    }else{
      bad_varch_string(str.c_str());
    }
    str.erase(0, pos + delimiter.length());
  }

  if (!(vlen >= 32 || vlen <= 4096) && !(slen >= vlen || slen <= vlen) && !(elen >= slen || elen <= slen)){
    bad_varch_string(s);
  }

  VU.VLEN = vlen;
  VU.ELEN = elen;
  VU.SLEN = slen;
}

void processor_t::parse_isa_string(const char* str)
{
  std::string lowercase, tmp;
  for (const char *r = str; *r; r++)
    lowercase += std::tolower(*r);

  const char* p = lowercase.c_str();
  const char* all_subsets = "imafdqc"
#ifdef __SIZEOF_INT128__
    "v"
#endif
    "";

  max_xlen = 64;
  state.misa = reg_t(2) << 62;

  if (strncmp(p, "rv32", 4) == 0)
    max_xlen = 32, state.misa = reg_t(1) << 30, p += 4;
  else if (strncmp(p, "rv64", 4) == 0)
    p += 4;
  else if (strncmp(p, "rv", 2) == 0)
    p += 2;

  if (!*p) {
    p = "imafdc";
  } else if (*p == 'g') { // treat "G" as "IMAFD"
    tmp = std::string("imafd") + (p+1);
    p = &tmp[0];
  } else if (*p != 'i') {
    bad_isa_string(str);
  }

  isa_string = "rv" + std::to_string(max_xlen) + p;
  state.misa |= 1L << ('s' - 'a'); // advertise support for supervisor mode
  state.misa |= 1L << ('u' - 'a'); // advertise support for user mode

  while (*p) {
    state.misa |= 1L << (*p - 'a');

    if (auto next = strchr(all_subsets, *p)) {
      all_subsets = next + 1;
      p++;
    } else if (*p == 'x') {
      const char* ext = p+1, *end = ext;
      while (islower(*end))
        end++;
      register_extension(find_extension(std::string(ext, end - ext).c_str())());
      p = end;
    } else {
      bad_isa_string(str);
    }
  }

  if (supports_extension('D') && !supports_extension('F'))
    bad_isa_string(str);

  if (supports_extension('Q') && !supports_extension('D'))
    bad_isa_string(str);

  max_isa = state.misa;
}

void state_t::reset(reg_t max_isa, struct ibda_params ibda)
{
  memset(this, 0, sizeof(*this));
  ibda_p = ibda;
  misa = max_isa;
  prv = PRV_M;
  pc = DEFAULT_RSTVEC;
  tselect = 0;
  for (unsigned int i = 0; i < num_triggers; i++)
    mcontrol[i].type = 2;

  pmpcfg[0] = PMP_R | PMP_W | PMP_X | PMP_NAPOT;
  pmpaddr[0] = ~reg_t(0);

  if (ibda_p.ist_vb) {
    ist_victim_buffer = new std::list<reg_t>;
    vb_hits = 0;
  }
  

  if (ibda_p.ist_fully_associative) {
    ist_tag_fa = new std::list<reg_t>;
    ist_evictions_fa = 0;
  }

  if (ibda_p.ist_set_associative) {
    ist_tag_sa = new std::list<reg_t>*[ibda_p.ist_sets];
    ist_evictions_sa = new reg_t[ibda_p.ist_sets];
    for (int i = 0; i <ibda_p.ist_sets; ++i) {
      ist_tag_sa[i] = new std::list<reg_t>; 
      ist_evictions_sa[i] = 0;
    }
  }
  
  if (ibda_p.ist_perfect || ibda_p.ibda_compare_perfect) {
    ist_tag_gm = new std::unordered_set<reg_t>; // Use map to also store number of lookups
  }
  false_negatives = 0;
  false_positives = 0;
  core_idx = 0;
}

void state_t::init_ibda(){
    rd[core_idx] = 0;
    rs1[core_idx] = 0;
    rs2[core_idx] = 0;
    agi[core_idx] = 0;
    ibda[core_idx] = 0;
    instruction_pc[core_idx] = 0;
    instruction_bits[core_idx] = 0;
    store[core_idx] = false;
    load[core_idx] = false;
    amo[core_idx] = false;
    rdt_bypass[core_idx] = 0;
    rdt_marked_bypass[core_idx] = false;
  }



//#define IST_INDEX(x) (((x^(x/(IST_SIZE/2)))>>1)&(IST_SIZE/2-1))

reg_t state_t::ist_get_index(reg_t addr) {
  if (ibda_p.ibda_ist_hash_xor_david) {
    reg_t res =  (((addr >> 1) ^ (addr >> ( (int) log2(ibda_p.ist_sets) + 1 ))) & (ibda_p.ist_sets-1));
    assert(res >= 0UL && res < ibda_p.ist_sets);
    return res;
  return res;
  } else {
    assert(false);
  }
  
}

reg_t state_t::ist_get_tag(reg_t addr, reg_t bits) {

  if (ibda_p.ibda_ist_hash_xor_david) {
  uint64_t set_mask = ~(ibda_p.ist_sets - 1);
  uint64_t tag_mask = (1UL << (bits + (uint64_t) log2(ibda_p.ist_sets))) - 1;
  uint64_t masked_pc = (addr >> 1);
  return (masked_pc & set_mask & tag_mask) >> ( (int) log2(ibda_p.ist_sets) );
  }

  assert(false);
  
}
  bool state_t::in_ist(reg_t addr){

 
    if (ibda_p.ist_fully_associative) {
      std::list<reg_t>::iterator it = std::find(ist_tag_fa->begin(), ist_tag_fa->end(),addr);
      if (it != ist_tag_fa->end()) {
        ist_tag_fa->erase(it);
        ist_tag_fa->push_front(addr);
        if (ibda_p.ibda_compare_perfect) {
          std::unordered_set<reg_t>::iterator in_ist = ist_tag_gm->find(addr);
          if (in_ist == ist_tag_gm->end()) {
            false_positives += 1;
          }
        }
        return true;
    } else {
      if (ibda_p.ibda_compare_perfect) {
          std::unordered_set<reg_t>::iterator in_ist = ist_tag_gm->find(addr);
          if (in_ist != ist_tag_gm->end()) {
            false_negatives += 1;
          }
        }
      return false;
    }

    } else if (ibda_p.ist_set_associative) {
      reg_t tag = ist_get_tag(addr, ibda_p.ibda_tag_bits);
      reg_t ist_index = ist_get_index(addr);
      std::list<reg_t>::iterator it = std::find (ist_tag_sa[ist_index]->begin(), ist_tag_sa[ist_index]->end(),tag); 

      if (it != ist_tag_sa[ist_index]->end()) {
        // Found it

        ist_tag_sa[ist_index]->erase(it);
        ist_tag_sa[ist_index]->push_front(tag);

        if (ibda_p.ibda_compare_perfect) {
          std::unordered_set<reg_t>::iterator in_ist = ist_tag_gm->find(addr);
          if (in_ist == ist_tag_gm->end()) {
            false_positives += 1;
          }
        }
        return true;
      } else {
        
        if (ibda_p.ist_vb) {
          if (in_vb(tag)) {
            if (ibda_p.ibda_compare_perfect) {
              std::unordered_set<reg_t>::iterator in_ist = ist_tag_gm->find(addr);
              if (in_ist == ist_tag_gm->end()) {
                false_positives += 1;
              }
            }
            return true;
          }          
        }

      if (ibda_p.ibda_compare_perfect) {
        std::unordered_set<reg_t>::iterator in_ist = ist_tag_gm->find(addr);
        if (in_ist != ist_tag_gm->end()) {
          false_negatives += 1;
        }
      }
      return false;
    }

    } else if (ibda_p.ist_perfect) {
      std::unordered_set<reg_t>::iterator in_ist = ist_tag_gm->find(addr);
      if (in_ist != ist_tag_gm->end()) {
        return true;
      } else {
        return false;
      } 
    }
  }


  void state_t::ist_add(reg_t addr){
    if (ibda_p.ist_perfect) {
      ist_tag_gm->insert({addr, 0});

      if (ibda_p.trace_level > 0) {
          fprintf(stderr, "ist adding " "0x%016" PRIx64 "\n", addr);
        }
    } else if (ibda_p.ist_fully_associative) {
        
      std::list<reg_t>::iterator it = std::find(ist_tag_fa->begin(), ist_tag_fa->end(), addr);
      if (it != ist_tag_fa->end()) {
        ist_tag_fa->erase(it);
      } else if (ist_tag_fa->size() >= ibda_p.ist_sz) {
        ist_tag_fa->pop_back();
        ist_evictions_fa++;
      }
      ist_tag_fa->push_front(addr);
      assert(!(ist_tag_fa->size() > ibda_p.ist_sz));
      if (ibda_p.ibda_compare_perfect) { 
        ist_tag_gm->insert({addr, 0});
      }
    } else if (ibda_p.ist_set_associative) {
      reg_t tag = ist_get_tag(addr, ibda_p.ibda_tag_bits);
      reg_t ist_index = ist_get_index(addr);
      std::list<reg_t>::iterator it = std::find (ist_tag_sa[ist_index]->begin(), ist_tag_sa[ist_index]->end(), tag);
      if (it != ist_tag_sa[ist_index]->end()) {
        // Found it
        ist_tag_sa[ist_index]->erase(it);
      } else if (ist_tag_sa[ist_index]->size() >= ibda_p.ist_ways) {
        // Delete LRU
        reg_t evict = ist_tag_sa[ist_index]->back();
        if (ibda_p.trace_level > 0) {
          fprintf(stderr, "ist adding " "0x%016" PRIx64 " evicting " "0x%016" PRIx64 "\n", addr, evict);
        }
        ist_tag_sa[ist_index]->pop_back();

        if (ibda_p.ist_vb) {
          vb_add(evict);
        }
      }

      // Add new entry to head of LRU queue
      ist_tag_sa[ist_index]->push_front(tag);
      assert(ist_tag_sa[ist_index]->size() <= ibda_p.ist_ways);
      
      if (ibda_p.ibda_compare_perfect) { 
        ist_tag_gm->insert({addr, 0});
      }
    }


  }

  void state_t::vb_add(reg_t addr) {
    if (ist_victim_buffer->size() >= ibda_p.ist_vb_sz) {
          ist_victim_buffer->pop_back();
        }
        ist_victim_buffer->push_front(addr);
        assert(!(ist_victim_buffer->size() > ibda_p.ist_vb_sz));
  }

  bool state_t::in_vb(reg_t addr) {
    std::list<reg_t>::iterator it = std::find (ist_victim_buffer->begin(), ist_victim_buffer->end(), addr);
    if( it != ist_victim_buffer->end()) {
      // Found it in the victim buffer
      ist_victim_buffer->erase(it);
      ist_add(addr);
      vb_hits += 1;
      return true;
    } else {
      return false;
    }   
  }

  void state_t::update_ibda(insn_t insn, processor_t* p, reg_t insn_pc){
    agi[core_idx] = in_ist(insn_pc);
    ibda[core_idx] = ((load[core_idx] || store[core_idx] ) && !amo[core_idx]) || agi[core_idx];
    instruction_pc[core_idx] = insn_pc;
    uint64_t bits = insn.bits() & ((1ULL << (8 * insn_length(insn.bits()))) - 1);
    instruction_bits[core_idx] = bits;
    if (ibda_p.trace_level > 1) {
      fprintf(stderr, "0x%016" PRIx64 " (0xcd%08" PRIx64 ") core_idx:%d ibda:%d %s\n",
                       insn_pc, bits, core_idx, ibda[core_idx],p->disassembler->disassemble(insn).c_str());  
    }
    
   //fprintf(stderr, "insn_pc: 0x%016" PRIx64 " rd: %d rs1: %d rs2: %d\n", insn_pc, rd, rs1, rs2);
    
    if(core_idx == (CORE_WIDTH - 1)) {
      // Core width is "full" we can now do IBDA and emulate n-wide cores
      size_t mark_cnt = 0;
      size_t i = 0;
      while (i < CORE_WIDTH && mark_cnt <ibda_p.ist_wp) {
        if(ibda[i]){

          if(rs1[i]) {
            bool is_marked = rdt_marked[rs1[i]];
            reg_t pc = rdt[rs1[i]];
            reg_t insn = rdt_insn[rs1[i]];

            // If we have a bypassable queue. We have to check previous
            // candidates
            for(size_t j = 0; j<i; ++j) {
              if (rdt_bypass[j] == rs1[i]) {
                pc = instruction_pc[j];
                insn = instruction_bits[j];
                is_marked = rdt_marked_bypass[j];
              }
            }
            
            if(!is_marked) {
              rdt_marked[rs1[i]] = true;
              if (ibda_p.trace_level > 0) {
                fprintf(stderr, "ibda added rs1 %d: 0x%016" PRIx64 " by: 0x%016" PRIx64 "\n", rs1[i], pc, instruction_pc[i]);
              }
              if (ibda_p.dump_load_slice_instruction_trace) {
               fprintf(stderr, "pc " "0x%016" PRIx64 " inst %x\n", pc, insn);
              }

              ist_add(pc);
              // avoid unnecessary rdt additions
              mark_cnt++;

 

            }
          
          }

          
          if (!(mark_cnt < ibda_p.ist_wp)) break;


          if(rs2[i] && (!store[i] || amo[i]))  {
            bool is_marked = rdt_marked[rs2[i]];
            reg_t pc = rdt[rs2[i]];
            reg_t insn = rdt_insn[rs2[i]];
            // If we have a bypassable queue. We have to check previous
            // candidates
              for(size_t j = 0; j<i; ++j) {
                if (rdt_bypass[j] == rs2[i]) {
                  pc = instruction_pc[j];
                  insn = instruction_bits[j];
                  is_marked = rdt_marked_bypass[j];
                }
              }

            if(!is_marked) {
              rdt_marked[rs2[i]] = true;
              if (ibda_p.trace_level > 0) {
                fprintf(stderr, "ibda added rs2 %d: 0x%016" PRIx64 " by: 0x%016" PRIx64 "\n", rs2[i], pc, instruction_pc[i]);
              
              }
              
              if (ibda_p.trace_level > 0) {
                fprintf(stderr, "ibda added rs2 %d: 0x%016" PRIx64 " by: 0x%016" PRIx64 "\n", rs1[i], pc, instruction_pc[i]);
              }
              
              ist_add(pc);
              // avoid unnecessary rdt additions
              mark_cnt++;
            
              
            }
          
          }
        } //endif(ibda(i))

        ++i;
      }
      // Updating RDT
      for (int i = 0; i<CORE_WIDTH; i++) {
        if(rd[i]){
          rdt[rd[i]] = instruction_pc[i];
          rdt_insn[rd[i]] = instruction_bits[i];
          rdt_marked[rd[i]] = ibda[i];
        }
      }

       if (ibda_p.trace_level > 0) {
          for (int i = 0; i<32; i++) {
            fprintf(stderr, "rs%d pc:%x insn:%x\n", i, rdt[i], rdt_insn[i]);
          }
        }
              

  
    }


    // Update RDT
    if (rd[core_idx]) {
      rdt_bypass[core_idx] = rd[core_idx];
      rdt_marked_bypass[core_idx] = ibda[core_idx];
    }
      // update counter
    if(ibda[core_idx]) {
        b_cnt++;
    } else {
        a_cnt++;
    }

    // write rdt last
 
//    if(load && !amo){
//        load_cnt++;
////        fprintf(stderr, "load: 0x%016" PRIx64 " (0x%08" PRIx64 ") %s\n",
////                    insn_pc, bits, p->disassembler->disassemble(insn).c_str());
//    }
//    if(store && !amo){
//        store_cnt++;
////        fprintf(stderr, "store: 0x%016" PRIx64 " (0x%08" PRIx64 ") %s\n",
////                    insn_pc, bits, p->disassembler->disassemble(insn).c_str());
//    }
//    if(agi){
//        agi_cnt++;
//    }
//    if(store && load && !amo){
//        load_store_cnt++;
//    }
    
  }

// For IBDA. Increases the CORE_WIDTH_count counter and wraps around
void state_t::advance_core_idx() {
  if (++core_idx == CORE_WIDTH) {
    core_idx = 0;
  }
}

void vectorUnit_t::reset(){
  free(reg_file);
  VLEN = get_vlen();
  ELEN = get_elen();
  SLEN = get_slen(); // registers are simply concatenated
  reg_file = malloc(NVPR * (VLEN/8));

  vtype = 0;
  set_vl(-1, 0, -1); // default to illegal configuration
}

reg_t vectorUnit_t::set_vl(uint64_t regId, reg_t reqVL, reg_t newType){
  if (vtype != newType){
    vtype = newType;
    vsew = 1 << (BITS(newType, 4, 2) + 3);
    vlmul = 1 << BITS(newType, 1, 0);
    vediv = 1 << BITS(newType, 6, 5);
    vlmax = VLEN/vsew * vlmul;
    vmlen = vsew / vlmul;
    reg_mask = (NVPR-1) & ~(vlmul-1);

    vill = vsew > e64 || vediv != 1 || (newType >> 7) != 0;
    if (vill)
      vlmax = 0;
  }
  vl = reqVL <= vlmax && regId != 0 ? reqVL : vlmax;
  vstart = 0;
  setvl_count++;
  return vl;
}

void processor_t::set_debug(bool value)
{
  debug = value;
  if (ext)
    ext->set_debug(value);
}

void processor_t::set_histogram(bool value)
{
  histogram_enabled = value;
#ifndef RISCV_ENABLE_HISTOGRAM
  if (value) {
    fprintf(stderr, "PC Histogram support has not been properly enabled;");
    fprintf(stderr, " please re-build the riscv-isa-sim project using \"configure --enable-histogram\".\n");
    abort();
  }
#endif
}

void processor_t::set_log_commits(bool value)
{
  log_commits_enabled = value;
#ifndef RISCV_ENABLE_COMMITLOG
  if (value) {
    fprintf(stderr, "Commit logging support has not been properly enabled;");
    fprintf(stderr, " please re-build the riscv-isa-sim project using \"configure --enable-commitlog\".\n");
    abort();
  }
#endif
}

void processor_t::reset(struct ibda_params ibda)
{
  if (ibda.ist_set_associative) {
    assert(ibda.ist_ways > 0);
    assert(ibda.ist_sz > 0);
  }
  
  assert(ibda.ist_set_associative || ibda.ist_fully_associative || ibda.ist_perfect);

  assert(ibda.ist_wp>0);
  assert(! (ibda.ist_set_associative && ibda.ist_fully_associative));
  assert(! (ibda.ist_perfect &&  (ibda.ist_sz>0)));

  state.reset(max_isa, ibda);
  state.dcsr.halt = halt_on_reset;
  halt_on_reset = false;
  set_csr(CSR_MSTATUS, state.mstatus);
  VU.reset();

  if (ext)
    ext->reset(); // reset the extension

  if (sim)
    sim->proc_reset(id);
}

// Count number of contiguous 0 bits starting from the LSB.
static int ctz(reg_t val)
{
  int res = 0;
  if (val)
    while ((val & 1) == 0)
      val >>= 1, res++;
  return res;
}

void processor_t::take_interrupt(reg_t pending_interrupts)
{
  reg_t mie = get_field(state.mstatus, MSTATUS_MIE);
  reg_t m_enabled = state.prv < PRV_M || (state.prv == PRV_M && mie);
  reg_t enabled_interrupts = pending_interrupts & ~state.mideleg & -m_enabled;

  reg_t sie = get_field(state.mstatus, MSTATUS_SIE);
  reg_t s_enabled = state.prv < PRV_S || (state.prv == PRV_S && sie);
  // M-ints have highest priority; consider S-ints only if no M-ints pending
  if (enabled_interrupts == 0)
    enabled_interrupts = pending_interrupts & state.mideleg & -s_enabled;

  if (!state.debug_mode && enabled_interrupts) {
    // nonstandard interrupts have highest priority
    if (enabled_interrupts >> IRQ_M_EXT)
      enabled_interrupts = enabled_interrupts >> IRQ_M_EXT << IRQ_M_EXT;
    // standard interrupt priority is MEI, MSI, MTI, SEI, SSI, STI
    else if (enabled_interrupts & MIP_MEIP)
      enabled_interrupts = MIP_MEIP;
    else if (enabled_interrupts & MIP_MSIP)
      enabled_interrupts = MIP_MSIP;
    else if (enabled_interrupts & MIP_MTIP)
      enabled_interrupts = MIP_MTIP;
    else if (enabled_interrupts & MIP_SEIP)
      enabled_interrupts = MIP_SEIP;
    else if (enabled_interrupts & MIP_SSIP)
      enabled_interrupts = MIP_SSIP;
    else if (enabled_interrupts & MIP_STIP)
      enabled_interrupts = MIP_STIP;
    else
      abort();

    throw trap_t(((reg_t)1 << (max_xlen-1)) | ctz(enabled_interrupts));
  }
}

static int xlen_to_uxl(int xlen)
{
  if (xlen == 32)
    return 1;
  if (xlen == 64)
    return 2;
  abort();
}

reg_t processor_t::legalize_privilege(reg_t prv)
{
  assert(prv <= PRV_M);

  if (!supports_extension('U'))
    return PRV_M;

  if (prv == PRV_H || !supports_extension('S'))
    return PRV_U;

  return prv;
}

void processor_t::set_privilege(reg_t prv)
{
  mmu->flush_tlb();
  state.prv = legalize_privilege(prv);
}

void processor_t::enter_debug_mode(uint8_t cause)
{
  state.debug_mode = true;
  state.dcsr.cause = cause;
  state.dcsr.prv = state.prv;
  set_privilege(PRV_M);
  state.dpc = state.pc;
  state.pc = DEBUG_ROM_ENTRY;
}

void processor_t::take_trap(trap_t& t, reg_t epc)
{
  if (debug) {
    fprintf(stderr, "core %3d: exception %s, epc 0x%016" PRIx64 "\n",
            id, t.name(), epc);
    if (t.has_tval())
      fprintf(stderr, "core %3d:           tval 0x%016" PRIx64 "\n", id,
          t.get_tval());
  }

  if (state.debug_mode) {
    if (t.cause() == CAUSE_BREAKPOINT) {
      state.pc = DEBUG_ROM_ENTRY;
    } else {
      state.pc = DEBUG_ROM_TVEC;
    }
    return;
  }

  if (t.cause() == CAUSE_BREAKPOINT && (
              (state.prv == PRV_M && state.dcsr.ebreakm) ||
              (state.prv == PRV_S && state.dcsr.ebreaks) ||
              (state.prv == PRV_U && state.dcsr.ebreaku))) {
    enter_debug_mode(DCSR_CAUSE_SWBP);
    return;
  }

  // by default, trap to M-mode, unless delegated to S-mode
  reg_t bit = t.cause();
  reg_t deleg = state.medeleg;
  bool interrupt = (bit & ((reg_t)1 << (max_xlen-1))) != 0;
  if (interrupt)
    deleg = state.mideleg, bit &= ~((reg_t)1 << (max_xlen-1));
  if (state.prv <= PRV_S && bit < max_xlen && ((deleg >> bit) & 1)) {
    // handle the trap in S-mode
    reg_t vector = (state.stvec & 1) && interrupt ? 4*bit : 0;
    state.pc = (state.stvec & ~(reg_t)1) + vector;
    state.scause = t.cause();
    state.sepc = epc;
    state.stval = t.get_tval();

    reg_t s = state.mstatus;
    s = set_field(s, MSTATUS_SPIE, get_field(s, MSTATUS_SIE));
    s = set_field(s, MSTATUS_SPP, state.prv);
    s = set_field(s, MSTATUS_SIE, 0);
    set_csr(CSR_MSTATUS, s);
    set_privilege(PRV_S);
  } else {
    reg_t vector = (state.mtvec & 1) && interrupt ? 4*bit : 0;
    state.pc = (state.mtvec & ~(reg_t)1) + vector;
    state.mepc = epc;
    state.mcause = t.cause();
    state.mtval = t.get_tval();

    reg_t s = state.mstatus;
    s = set_field(s, MSTATUS_MPIE, get_field(s, MSTATUS_MIE));
    s = set_field(s, MSTATUS_MPP, state.prv);
    s = set_field(s, MSTATUS_MIE, 0);
    set_csr(CSR_MSTATUS, s);
    set_privilege(PRV_M);
  }
}

void processor_t::disasm(insn_t insn)
{
  uint64_t bits = insn.bits() & ((1ULL << (8 * insn_length(insn.bits()))) - 1);
  if (last_pc != state.pc || last_bits != bits) {
    if (executions != 1) {
      fprintf(stderr, "core %3d: Executed %" PRIx64 " times\n", id, executions);
    }

    fprintf(stderr, "core %3d: 0x%016" PRIx64 " (0x%08" PRIx64 ") %s\n",
            id, state.pc, bits, disassembler->disassemble(insn).c_str());
    last_pc = state.pc;
    last_bits = bits;
    executions = 1;
  } else {
    executions++;
  }
}

int processor_t::paddr_bits()
{
  assert(xlen == max_xlen);
  return max_xlen == 64 ? 50 : 34;
}

void processor_t::set_csr(int which, reg_t val)
{
  val = zext_xlen(val);
  reg_t delegable_ints = MIP_SSIP | MIP_STIP | MIP_SEIP
                       | ((ext != NULL) << IRQ_COP);
  reg_t all_ints = delegable_ints | MIP_MSIP | MIP_MTIP;

  if (which >= CSR_PMPADDR0 && which < CSR_PMPADDR0 + state.n_pmp) {
    size_t i = which - CSR_PMPADDR0;
    bool locked = state.pmpcfg[i] & PMP_L;
    bool next_locked = i+1 < state.n_pmp && (state.pmpcfg[i+1] & PMP_L);
    bool next_tor = i+1 < state.n_pmp && (state.pmpcfg[i+1] & PMP_A) == PMP_TOR;
    if (!locked && !(next_locked && next_tor))
      state.pmpaddr[i] = val;

    mmu->flush_tlb();
  }

  if (which >= CSR_PMPCFG0 && which < CSR_PMPCFG0 + state.n_pmp / 4) {
    for (size_t i0 = (which - CSR_PMPCFG0) * 4, i = i0; i < i0 + xlen / 8; i++) {
      if (!(state.pmpcfg[i] & PMP_L)) {
        uint8_t cfg = (val >> (8 * (i - i0))) & (PMP_R | PMP_W | PMP_X | PMP_A | PMP_L);
        cfg &= ~PMP_W | ((cfg & PMP_R) ? PMP_W : 0); // Disallow R=0 W=1
        state.pmpcfg[i] = cfg;
      }
    }
    mmu->flush_tlb();
  }

  switch (which)
  {
    case CSR_FFLAGS:
      dirty_fp_state;
      state.fflags = val & (FSR_AEXC >> FSR_AEXC_SHIFT);
      break;
    case CSR_FRM:
      dirty_fp_state;
      state.frm = val & (FSR_RD >> FSR_RD_SHIFT);
      break;
    case CSR_FCSR:
      dirty_fp_state;
      state.fflags = (val & FSR_AEXC) >> FSR_AEXC_SHIFT;
      state.frm = (val & FSR_RD) >> FSR_RD_SHIFT;
      break;
    case CSR_MSTATUS: {
      if ((val ^ state.mstatus) &
          (MSTATUS_MPP | MSTATUS_MPRV | MSTATUS_SUM | MSTATUS_MXR))
        mmu->flush_tlb();

      reg_t mask = MSTATUS_SIE | MSTATUS_SPIE | MSTATUS_MIE | MSTATUS_MPIE
                 | MSTATUS_FS | MSTATUS_MPRV | MSTATUS_SUM
                 | MSTATUS_MXR | MSTATUS_TW | MSTATUS_TVM
                 | MSTATUS_TSR | MSTATUS_UXL | MSTATUS_SXL |
                 (ext ? MSTATUS_XS : 0);

      reg_t requested_mpp = legalize_privilege(get_field(val, MSTATUS_MPP));
      state.mstatus = set_field(state.mstatus, MSTATUS_MPP, requested_mpp);
      if (supports_extension('S'))
        mask |= MSTATUS_SPP;

      state.mstatus = (state.mstatus & ~mask) | (val & mask);

      bool dirty = (state.mstatus & MSTATUS_FS) == MSTATUS_FS;
      dirty |= (state.mstatus & MSTATUS_XS) == MSTATUS_XS;
      if (max_xlen == 32)
        state.mstatus = set_field(state.mstatus, MSTATUS32_SD, dirty);
      else
        state.mstatus = set_field(state.mstatus, MSTATUS64_SD, dirty);

      state.mstatus = set_field(state.mstatus, MSTATUS_UXL, xlen_to_uxl(max_xlen));
      state.mstatus = set_field(state.mstatus, MSTATUS_SXL, xlen_to_uxl(max_xlen));
      // U-XLEN == S-XLEN == M-XLEN
      xlen = max_xlen;
      break;
    }
    case CSR_MIP: {
      reg_t mask = MIP_SSIP | MIP_STIP;
      state.mip = (state.mip & ~mask) | (val & mask);
      break;
    }
    case CSR_MIE:
      state.mie = (state.mie & ~all_ints) | (val & all_ints);
      break;
    case CSR_MIDELEG:
      state.mideleg = (state.mideleg & ~delegable_ints) | (val & delegable_ints);
      break;
    case CSR_MEDELEG: {
      reg_t mask =
        (1 << CAUSE_MISALIGNED_FETCH) |
        (1 << CAUSE_BREAKPOINT) |
        (1 << CAUSE_USER_ECALL) |
        (1 << CAUSE_FETCH_PAGE_FAULT) |
        (1 << CAUSE_LOAD_PAGE_FAULT) |
        (1 << CAUSE_STORE_PAGE_FAULT);
      state.medeleg = (state.medeleg & ~mask) | (val & mask);
      break;
    }
    case CSR_MINSTRET:
    case CSR_MCYCLE:
      if (xlen == 32)
        state.minstret = (state.minstret >> 32 << 32) | (val & 0xffffffffU);
      else
        state.minstret = val;
      // The ISA mandates that if an instruction writes instret, the write
      // takes precedence over the increment to instret.  However, Spike
      // unconditionally increments instret after executing an instruction.
      // Correct for this artifact by decrementing instret here.
      state.minstret--;
      break;
    case CSR_MINSTRETH:
    case CSR_MCYCLEH:
      state.minstret = (val << 32) | (state.minstret << 32 >> 32);
      state.minstret--; // See comment above.
      break;
    case CSR_SCOUNTEREN:
      state.scounteren = val;
      break;
    case CSR_MCOUNTEREN:
      state.mcounteren = val;
      break;
    case CSR_SSTATUS: {
      reg_t mask = SSTATUS_SIE | SSTATUS_SPIE | SSTATUS_SPP | SSTATUS_FS
                 | SSTATUS_XS | SSTATUS_SUM | SSTATUS_MXR;
      return set_csr(CSR_MSTATUS, (state.mstatus & ~mask) | (val & mask));
    }
    case CSR_SIP: {
      reg_t mask = MIP_SSIP & state.mideleg;
      return set_csr(CSR_MIP, (state.mip & ~mask) | (val & mask));
    }
    case CSR_SIE:
      return set_csr(CSR_MIE,
                     (state.mie & ~state.mideleg) | (val & state.mideleg));
    case CSR_SATP: {
      mmu->flush_tlb();
      if (max_xlen == 32)
        state.satp = val & (SATP32_PPN | SATP32_MODE);
      if (max_xlen == 64 && (get_field(val, SATP64_MODE) == SATP_MODE_OFF ||
                             get_field(val, SATP64_MODE) == SATP_MODE_SV39 ||
                             get_field(val, SATP64_MODE) == SATP_MODE_SV48))
        state.satp = val & (SATP64_PPN | SATP64_MODE);
      break;
    }
    case CSR_SEPC: state.sepc = val & ~(reg_t)1; break;
    case CSR_STVEC: state.stvec = val & ~(reg_t)2; break;
    case CSR_SSCRATCH: state.sscratch = val; break;
    case CSR_SCAUSE: state.scause = val; break;
    case CSR_STVAL: state.stval = val; break;
    case CSR_MEPC: state.mepc = val & ~(reg_t)1; break;
    case CSR_MTVEC: state.mtvec = val & ~(reg_t)2; break;
    case CSR_MSCRATCH: state.mscratch = val; break;
    case CSR_MCAUSE: state.mcause = val; break;
    case CSR_MTVAL: state.mtval = val; break;
    case CSR_MISA: {
      // the write is ignored if increasing IALIGN would misalign the PC
      if (!(val & (1L << ('C' - 'A'))) && (state.pc & 2))
        break;

      if (!(val & (1L << ('F' - 'A'))))
        val &= ~(1L << ('D' - 'A'));

      // allow MAFDC bits in MISA to be modified
      reg_t mask = 0;
      mask |= 1L << ('M' - 'A');
      mask |= 1L << ('A' - 'A');
      mask |= 1L << ('F' - 'A');
      mask |= 1L << ('D' - 'A');
      mask |= 1L << ('C' - 'A');
      mask &= max_isa;

      state.misa = (val & mask) | (state.misa & ~mask);
      break;
    }
    case CSR_TSELECT:
      if (val < state.num_triggers) {
        state.tselect = val;
      }
      break;
    case CSR_TDATA1:
      {
        mcontrol_t *mc = &state.mcontrol[state.tselect];
        if (mc->dmode && !state.debug_mode) {
          break;
        }
        mc->dmode = get_field(val, MCONTROL_DMODE(xlen));
        mc->select = get_field(val, MCONTROL_SELECT);
        mc->timing = get_field(val, MCONTROL_TIMING);
        mc->action = (mcontrol_action_t) get_field(val, MCONTROL_ACTION);
        mc->chain = get_field(val, MCONTROL_CHAIN);
        mc->match = (mcontrol_match_t) get_field(val, MCONTROL_MATCH);
        mc->m = get_field(val, MCONTROL_M);
        mc->h = get_field(val, MCONTROL_H);
        mc->s = get_field(val, MCONTROL_S);
        mc->u = get_field(val, MCONTROL_U);
        mc->execute = get_field(val, MCONTROL_EXECUTE);
        mc->store = get_field(val, MCONTROL_STORE);
        mc->load = get_field(val, MCONTROL_LOAD);
        // Assume we're here because of csrw.
        if (mc->execute)
          mc->timing = 0;
        trigger_updated();
      }
      break;
    case CSR_TDATA2:
      if (state.mcontrol[state.tselect].dmode && !state.debug_mode) {
        break;
      }
      if (state.tselect < state.num_triggers) {
        state.tdata2[state.tselect] = val;
      }
      break;
    case CSR_DCSR:
      state.dcsr.prv = get_field(val, DCSR_PRV);
      state.dcsr.step = get_field(val, DCSR_STEP);
      // TODO: ndreset and fullreset
      state.dcsr.ebreakm = get_field(val, DCSR_EBREAKM);
      state.dcsr.ebreakh = get_field(val, DCSR_EBREAKH);
      state.dcsr.ebreaks = get_field(val, DCSR_EBREAKS);
      state.dcsr.ebreaku = get_field(val, DCSR_EBREAKU);
      state.dcsr.halt = get_field(val, DCSR_HALT);
      break;
    case CSR_DPC:
      state.dpc = val & ~(reg_t)1;
      break;
    case CSR_DSCRATCH:
      state.dscratch0 = val;
      break;
    case CSR_DSCRATCH + 1:
      state.dscratch1 = val;
      break;
    case CSR_VSTART:
      VU.vstart = val;
      break;
    case CSR_VXSAT:
      VU.vxsat = val;
      break;
    case CSR_VXRM:
      VU.vxrm = val;
      break;
  }
}

// Note that get_csr is sometimes called when read side-effects should not
// be actioned.  In other words, Spike cannot currently support CSRs with
// side effects on reads.
reg_t processor_t::get_csr(int which)
{
  uint32_t ctr_en = -1;
  if (state.prv < PRV_M)
    ctr_en &= state.mcounteren;
  if (state.prv < PRV_S)
    ctr_en &= state.scounteren;
  bool ctr_ok = (ctr_en >> (which & 31)) & 1;

  // hack for ibda lane counts
  //dlq
  if(which == CSR_MHPMCOUNTER5 || which == CSR_HPMCOUNTER5){
    return state.a_cnt;
  }
  // iq
  if(which == CSR_MHPMCOUNTER6 || which == CSR_HPMCOUNTER6) {
    return state.b_cnt;
  }
  if(which == CSR_MHPMCOUNTER7 || which == CSR_HPMCOUNTER7) {
    // Print out IST size
    fprintf(stdout, "%lu false-positives\n%lu false-negatives\n", state.false_positives, state.false_negatives);
    
    return 0;
  }
  /*
  if(which == CSR_MHPMCOUNTER8 || which == CSR_HPMCOUNTER8) {
    // Print out the number of lookups on each
    #ifndef IST_LRU
    unsigned long i = 0;
    for (auto it = state.ist->cbegin(); it != state.ist->end(); ++it) {
      fprintf(stderr, "%lu IST_lookups-%lu\n", it->second, i);
      ++i;
    }
    #endif 
    
    return 0;
  }
  if(which == CSR_MHPMCOUNTER9 || which == CSR_HPMCOUNTER9) {
    // Print the number of evictions per set
    #ifdef IST_SET_ASSOCIATIVE
    for (int i = 0; i<IST_SETS; ++i) {
      fprintf(stderr, "%lu IST_evictions-%d\n", state.ist_evictions[i], i);
    }

    #else
    #ifdef IST_FULLY_ASSOCIATIVE
    fprintf(stderr, "%lu IST_evictions\n", state.ist_evictions);
    #endif
    #endif

    return 0;
  }
    */
//  if(which == CSR_MHPMCOUNTER10 || which == CSR_HPMCOUNTER10)
//    return state.load_store_cnt;

  if (ctr_ok) {
    if (which >= CSR_HPMCOUNTER3 && which <= CSR_HPMCOUNTER31)
      return 0;
    if (xlen == 32 && which >= CSR_HPMCOUNTER3H && which <= CSR_HPMCOUNTER31H)
      return 0;
  }
  if (which >= CSR_MHPMCOUNTER3 && which <= CSR_MHPMCOUNTER31)
    return 0;
  if (xlen == 32 && which >= CSR_MHPMCOUNTER3H && which <= CSR_MHPMCOUNTER31H)
    return 0;
  if (which >= CSR_MHPMEVENT3 && which <= CSR_MHPMEVENT31)
    return 0;

  if (which >= CSR_PMPADDR0 && which < CSR_PMPADDR0 + state.n_pmp)
    return state.pmpaddr[which - CSR_PMPADDR0];

  if (which >= CSR_PMPCFG0 && which < CSR_PMPCFG0 + state.n_pmp / 4) {
    require((which & ((xlen / 32) - 1)) == 0);

    reg_t res = 0;
    for (size_t i0 = (which - CSR_PMPCFG0) * 4, i = i0; i < i0 + xlen / 8 && i < state.n_pmp; i++)
      res |= reg_t(state.pmpcfg[i]) << (8 * (i - i0));
    return res;
  }

  switch (which)
  {
    case CSR_FFLAGS:
      require_fp;
      if (!supports_extension('F'))
        break;
      return state.fflags;
    case CSR_FRM:
      require_fp;
      if (!supports_extension('F'))
        break;
      return state.frm;
    case CSR_FCSR:
      require_fp;
      if (!supports_extension('F'))
        break;
      return (state.fflags << FSR_AEXC_SHIFT) | (state.frm << FSR_RD_SHIFT);
    case CSR_INSTRET:
    case CSR_CYCLE:
      if (ctr_ok)
        return state.minstret;
      break;
    case CSR_MINSTRET:
    case CSR_MCYCLE:
      return state.minstret;
    case CSR_INSTRETH:
    case CSR_CYCLEH:
      if (ctr_ok && xlen == 32)
        return state.minstret >> 32;
      break;
    case CSR_MINSTRETH:
    case CSR_MCYCLEH:
      if (xlen == 32)
        return state.minstret >> 32;
      break;
    case CSR_SCOUNTEREN: return state.scounteren;
    case CSR_MCOUNTEREN: return state.mcounteren;
    case CSR_SSTATUS: {
      reg_t mask = SSTATUS_SIE | SSTATUS_SPIE | SSTATUS_SPP | SSTATUS_FS
                 | SSTATUS_XS | SSTATUS_SUM | SSTATUS_MXR | SSTATUS_UXL;
      reg_t sstatus = state.mstatus & mask;
      if ((sstatus & SSTATUS_FS) == SSTATUS_FS ||
          (sstatus & SSTATUS_XS) == SSTATUS_XS)
        sstatus |= (xlen == 32 ? SSTATUS32_SD : SSTATUS64_SD);
      return sstatus;
    }
    case CSR_SIP: return state.mip & state.mideleg;
    case CSR_SIE: return state.mie & state.mideleg;
    case CSR_SEPC: return state.sepc & pc_alignment_mask();
    case CSR_STVAL: return state.stval;
    case CSR_STVEC: return state.stvec;
    case CSR_SCAUSE:
      if (max_xlen > xlen)
        return state.scause | ((state.scause >> (max_xlen-1)) << (xlen-1));
      return state.scause;
    case CSR_SATP:
      if (get_field(state.mstatus, MSTATUS_TVM))
        require_privilege(PRV_M);
      return state.satp;
    case CSR_SSCRATCH: return state.sscratch;
    case CSR_MSTATUS: return state.mstatus;
    case CSR_MIP: return state.mip;
    case CSR_MIE: return state.mie;
    case CSR_MEPC: return state.mepc & pc_alignment_mask();
    case CSR_MSCRATCH: return state.mscratch;
    case CSR_MCAUSE: return state.mcause;
    case CSR_MTVAL: return state.mtval;
    case CSR_MISA: return state.misa;
    case CSR_MARCHID: return 5;
    case CSR_MIMPID: return 0;
    case CSR_MVENDORID: return 0;
    case CSR_MHARTID: return id;
    case CSR_MTVEC: return state.mtvec;
    case CSR_MEDELEG: return state.medeleg;
    case CSR_MIDELEG: return state.mideleg;
    case CSR_TSELECT: return state.tselect;
    case CSR_TDATA1:
      if (state.tselect < state.num_triggers) {
        reg_t v = 0;
        mcontrol_t *mc = &state.mcontrol[state.tselect];
        v = set_field(v, MCONTROL_TYPE(xlen), mc->type);
        v = set_field(v, MCONTROL_DMODE(xlen), mc->dmode);
        v = set_field(v, MCONTROL_MASKMAX(xlen), mc->maskmax);
        v = set_field(v, MCONTROL_SELECT, mc->select);
        v = set_field(v, MCONTROL_TIMING, mc->timing);
        v = set_field(v, MCONTROL_ACTION, mc->action);
        v = set_field(v, MCONTROL_CHAIN, mc->chain);
        v = set_field(v, MCONTROL_MATCH, mc->match);
        v = set_field(v, MCONTROL_M, mc->m);
        v = set_field(v, MCONTROL_H, mc->h);
        v = set_field(v, MCONTROL_S, mc->s);
        v = set_field(v, MCONTROL_U, mc->u);
        v = set_field(v, MCONTROL_EXECUTE, mc->execute);
        v = set_field(v, MCONTROL_STORE, mc->store);
        v = set_field(v, MCONTROL_LOAD, mc->load);
        return v;
      } else {
        return 0;
      }
      break;
    case CSR_TDATA2:
      if (state.tselect < state.num_triggers) {
        return state.tdata2[state.tselect];
      } else {
        return 0;
      }
      break;
    case CSR_TDATA3: return 0;
    case CSR_DCSR:
      {
        uint32_t v = 0;
        v = set_field(v, DCSR_XDEBUGVER, 1);
        v = set_field(v, DCSR_EBREAKM, state.dcsr.ebreakm);
        v = set_field(v, DCSR_EBREAKH, state.dcsr.ebreakh);
        v = set_field(v, DCSR_EBREAKS, state.dcsr.ebreaks);
        v = set_field(v, DCSR_EBREAKU, state.dcsr.ebreaku);
        v = set_field(v, DCSR_STOPCYCLE, 0);
        v = set_field(v, DCSR_STOPTIME, 0);
        v = set_field(v, DCSR_CAUSE, state.dcsr.cause);
        v = set_field(v, DCSR_STEP, state.dcsr.step);
        v = set_field(v, DCSR_PRV, state.dcsr.prv);
        return v;
      }
    case CSR_DPC:
      return state.dpc & pc_alignment_mask();
    case CSR_DSCRATCH:
      return state.dscratch0;
    case CSR_DSCRATCH + 1:
      return state.dscratch1;
    case CSR_VSTART:
      require_vector_vs;
      if (!supports_extension('V'))
        break;
      return VU.vstart;
    case CSR_VXSAT:
      require_vector_vs;
      if (!supports_extension('V'))
        break;
      return VU.vxsat;
    case CSR_VXRM:
      require_vector_vs;
      if (!supports_extension('V'))
        break;
      return VU.vxrm;
    case CSR_VL:
      require_vector_vs;
      if (!supports_extension('V'))
        break;
      return VU.vl;
    case CSR_VTYPE:
      require_vector_vs;
      if (!supports_extension('V'))
        break;
      return VU.vtype;
  }
  throw trap_illegal_instruction(0);
}

reg_t illegal_instruction(processor_t* p, insn_t insn, reg_t pc)
{
  throw trap_illegal_instruction(0);
}

insn_func_t processor_t::decode_insn(insn_t insn)
{
  // look up opcode in hash table
  size_t idx = insn.bits() % OPCODE_CACHE_SIZE;
  insn_desc_t desc = opcode_cache[idx];

  if (unlikely(insn.bits() != desc.match)) {
    // fall back to linear search
    insn_desc_t* p = &instructions[0];
    while ((insn.bits() & p->mask) != p->match)
      p++;
    desc = *p;

    if (p->mask != 0 && p > &instructions[0]) {
      if (p->match != (p-1)->match && p->match != (p+1)->match) {
        // move to front of opcode list to reduce miss penalty
        while (--p >= &instructions[0])
          *(p+1) = *p;
        instructions[0] = desc;
      }
    }

    opcode_cache[idx] = desc;
    opcode_cache[idx].match = insn.bits();
  }

  return xlen == 64 ? desc.rv64 : desc.rv32;
}

void processor_t::register_insn(insn_desc_t desc)
{
  instructions.push_back(desc);
}

void processor_t::build_opcode_map()
{
  struct cmp {
    bool operator()(const insn_desc_t& lhs, const insn_desc_t& rhs) {
      if (lhs.match == rhs.match)
        return lhs.mask > rhs.mask;
      return lhs.match > rhs.match;
    }
  };
  std::sort(instructions.begin(), instructions.end(), cmp());

  for (size_t i = 0; i < OPCODE_CACHE_SIZE; i++)
    opcode_cache[i] = {0, 0, &illegal_instruction, &illegal_instruction};
}

void processor_t::register_extension(extension_t* x)
{
  for (auto insn : x->get_instructions())
    register_insn(insn);
  build_opcode_map();
  for (auto disasm_insn : x->get_disasms())
    disassembler->add_insn(disasm_insn);
  if (ext != NULL)
    throw std::logic_error("only one extension may be registered");
  ext = x;
  x->set_processor(this);
}

void processor_t::register_base_instructions()
{
  #define DECLARE_INSN(name, match, mask) \
    insn_bits_t name##_match = (match), name##_mask = (mask);
  #include "encoding.h"
  #undef DECLARE_INSN

  #define DEFINE_INSN(name) \
    REGISTER_INSN(this, name, name##_match, name##_mask)
  #include "insn_list.h"
  #undef DEFINE_INSN

  register_insn({0, 0, &illegal_instruction, &illegal_instruction});
  build_opcode_map();
}

bool processor_t::load(reg_t addr, size_t len, uint8_t* bytes)
{
  switch (addr)
  {
    case 0:
      if (len <= 4) {
        memset(bytes, 0, len);
        bytes[0] = get_field(state.mip, MIP_MSIP);
        return true;
      }
      break;
  }

  return false;
}

bool processor_t::store(reg_t addr, size_t len, const uint8_t* bytes)
{
  switch (addr)
  {
    case 0:
      if (len <= 4) {
        state.mip = set_field(state.mip, MIP_MSIP, bytes[0]);
        return true;
      }
      break;
  }

  return false;
}

void processor_t::trigger_updated()
{
  mmu->flush_tlb();
  mmu->check_triggers_fetch = false;
  mmu->check_triggers_load = false;
  mmu->check_triggers_store = false;

  for (unsigned i = 0; i < state.num_triggers; i++) {
    if (state.mcontrol[i].execute) {
      mmu->check_triggers_fetch = true;
    }
    if (state.mcontrol[i].load) {
      mmu->check_triggers_load = true;
    }
    if (state.mcontrol[i].store) {
      mmu->check_triggers_store = true;
    }
  }
}
