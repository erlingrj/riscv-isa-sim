// See LICENSE for license details.

#include "sim.h"
#include "mmu.h"
#include "remote_bitbang.h"
#include "cachesim.h"
#include "extension.h"
#include <dlfcn.h>
#include <fesvr/option_parser.h>
#include <stdio.h>
#include <stdlib.h>
#include <vector>
#include <string>
#include <memory>
#include "../VERSION"
#include "ibda.h"
#include "ibda_hash.h"

static void help(int exit_code = 1)
{
  fprintf(stderr, "Spike RISC-V ISA Simulator " SPIKE_VERSION "\n\n");
  fprintf(stderr, "usage: spike [host options] <target program> [target options]\n");
  fprintf(stderr, "Host Options:\n");
  fprintf(stderr, "  -p<n>                 Simulate <n> processors [default 1]\n");
  fprintf(stderr, "  -m<n>                 Provide <n> MiB of target memory [default 2048]\n");
  fprintf(stderr, "  -m<a:m,b:n,...>       Provide memory regions of size m and n bytes\n");
  fprintf(stderr, "                          at base addresses a and b (with 4 KiB alignment)\n");
  fprintf(stderr, "  -d                    Interactive debug mode\n");
  fprintf(stderr, "  -g                    Track histogram of PCs\n");
  fprintf(stderr, "  -l                    Generate a log of execution\n");
  fprintf(stderr, "  -h, --help            Print this help message\n");
  fprintf(stderr, "  -H                    Start halted, allowing a debugger to connect\n");
  fprintf(stderr, "  --isa=<name>          RISC-V ISA string [default %s]\n", DEFAULT_ISA);
  fprintf(stderr, "  --varch=<name>        RISC-V Vector uArch string [default %s]\n", DEFAULT_VARCH);
  fprintf(stderr, "  --pc=<address>        Override ELF entry point\n");
  fprintf(stderr, "  --hartids=<a,b,...>   Explicitly specify hartids, default is 0,1,...\n");
  fprintf(stderr, "  --ic=<S>:<W>:<B>      Instantiate a cache model with S sets,\n");
  fprintf(stderr, "  --dc=<S>:<W>:<B>        W ways, and B-byte blocks (with S and\n");
  fprintf(stderr, "  --l2=<S>:<W>:<B>        B both powers of 2).\n");
  fprintf(stderr, "  --device=<P,B,A>      Attach MMIO plugin device from an --extlib library\n");
  fprintf(stderr, "                          P -- Name of the MMIO plugin\n");
  fprintf(stderr, "                          B -- Base memory address of the device\n");
  fprintf(stderr, "                          A -- String arguments to pass to the plugin\n");
  fprintf(stderr, "                          This flag can be used multiple times.\n");
  fprintf(stderr, "                          The extlib flag for the library must come first.\n");
  fprintf(stderr, "  --log-cache-miss      Generate a log of cache miss\n");
  fprintf(stderr, "  --extension=<name>    Specify RoCC Extension\n");
  fprintf(stderr, "  --extlib=<name>       Shared library to load\n");
  fprintf(stderr, "                        This flag can be used multiple times.\n");
  fprintf(stderr, "  --rbb-port=<port>     Listen on <port> for remote bitbang connection\n");
  fprintf(stderr, "  --dump-dts            Print device tree string and exit\n");
  fprintf(stderr, "  --disable-dtb         Don't write the device tree blob into memory\n");
  fprintf(stderr, "  --dm-progsize=<words> Progsize for the debug module [default 2]\n");
  fprintf(stderr, "  --dm-sba=<bits>       Debug bus master supports up to "
      "<bits> wide accesses [default 0]\n");
  fprintf(stderr, "  --dm-auth             Debug module requires debugger to authenticate\n");
  fprintf(stderr, "  --dmi-rti=<n>         Number of Run-Test/Idle cycles "
      "required for a DMI access [default 0]\n");
  fprintf(stderr, "  --dm-abstract-rti=<n> Number of Run-Test/Idle cycles "
      "required for an abstract command to execute [default 0]\n");
  fprintf(stderr, "  --dm-no-hasel         Debug module supports hasel\n");
  fprintf(stderr, "  --dm-no-abstract-csr  Debug module won't support abstract to authenticate\n");
  fprintf(stderr, "  --dm-no-halt-groups   Debug module won't support halt groups\n");

  exit(exit_code);
}

static void suggest_help()
{
  fprintf(stderr, "Try 'spike --help' for more information.\n");
  exit(1);
}

static std::vector<std::pair<reg_t, mem_t*>> make_mems(const char* arg)
{
  // handle legacy mem argument
  char* p;
  auto mb = strtoull(arg, &p, 0);
  if (*p == 0) {
    reg_t size = reg_t(mb) << 20;
    if (size != (size_t)size)
      throw std::runtime_error("Size would overflow size_t");
    return std::vector<std::pair<reg_t, mem_t*>>(1, std::make_pair(reg_t(DRAM_BASE), new mem_t(size)));
  }

  // handle base/size tuples
  std::vector<std::pair<reg_t, mem_t*>> res;
  while (true) {
    auto base = strtoull(arg, &p, 0);
    if (!*p || *p != ':')
      help();
    auto size = strtoull(p + 1, &p, 0);
    if ((size | base) % PGSIZE != 0)
      help();
    res.push_back(std::make_pair(reg_t(base), new mem_t(size)));
    if (!*p)
      break;
    if (*p != ',')
      help();
    arg = p + 1;
  }
  return res;
}

// IBDA simulation tuff

 

int main(int argc, char** argv)
{
  
  bool debug = false;
  bool halted = false;
  bool histogram = false;
  bool log = false;
  bool dump_dts = false;
  bool dtb_enabled = true;
  size_t nprocs = 1;
  reg_t start_pc = reg_t(-1);
  std::vector<std::pair<reg_t, mem_t*>> mems;
  std::vector<std::pair<reg_t, abstract_device_t*>> plugin_devices;
  std::unique_ptr<icache_sim_t> ic;
  std::unique_ptr<dcache_sim_t> dc;
  std::unique_ptr<cache_sim_t> l2;
  bool log_cache = false;
  bool log_commits = false;
  std::function<extension_t*()> extension;
  const char* isa = DEFAULT_ISA;
  const char* varch = DEFAULT_VARCH;
  uint16_t rbb_port = 0;
  bool use_rbb = false;
  unsigned dmi_rti = 0;
  debug_module_config_t dm_config = {
    .progbufsize = 2,
    .max_bus_master_bits = 0,
    .require_authentication = false,
    .abstract_rti = 0,
    .support_hasel = true,
    .support_abstract_csr_access = true,
    .support_haltgroups = true
  };
  std::vector<int> hartids;

  struct ibda_params ibda;
  ibda.ist_fully_associative = false;
  ibda.ist_set_associative = false;
  ibda.ist_sz = 0;
  ibda.ist_ways = 0;
  ibda.ist_wp= 0;
  ibda.tag_sz= 0;
  ibda.ist_vb_sz =0;
  ibda.ist_sets=0;
  ibda.ist_vb=false;
  ibda.ibda_compare_perfect = false;
  ibda.ibda_ist_hash_xor_david = false;
  ibda.ibda_tag_bits = 32;
  ibda.ist_perfect = false;
  ibda.trace_level = 0;
  ibda.calculate_instruction_entropy = false;
  ibda.calculate_ist_instruction_entropy = false;
  ibda.ibda_hash_pc_mask = 0xFFFFFFFF;
  ibda.ibda_hash_insn_mask = 0xFFFFFFFF;
  ibda.ibda_simple_hash = false;
  ibda.ibda_binary_matrix_hash = false;
  ibda.ibda_no_hash = false;
  ibda.ibda_xor_hash = false;
  ibda.seed = 0;
  ibda.count_wp_usage = false;

  ibda.ibda_hash_bloom = false;
  ibda.bloom_m =0;
  ibda.bloom_k = 0;
  ibda.bloom_fp_rate = 0.0;

  auto const hartids_parser = [&](const char *s) {
    std::string const str(s);
    std::stringstream stream(str);

    int n;
    while (stream >> n)
    {
      hartids.push_back(n);
      if (stream.peek() == ',') stream.ignore();
    }
  };

  auto const device_parser = [&plugin_devices](const char *s) {
    const std::string str(s);
    std::istringstream stream(str);

    // We are parsing a string like name,base,args.

    // Parse the name, which is simply all of the characters leading up to the
    // first comma. The validity of the plugin name will be checked later.
    std::string name;
    std::getline(stream, name, ',');
    if (name.empty()) {
      throw std::runtime_error("Plugin name is empty.");
    }

    // Parse the base address. First, get all of the characters up to the next
    // comma (or up to the end of the string if there is no comma). Then try to
    // parse that string as an integer according to the rules of strtoull. It
    // could be in decimal, hex, or octal. Fail if we were able to parse a
    // number but there were garbage characters after the valid number. We must
    // consume the entire string between the commas.
    std::string base_str;
    std::getline(stream, base_str, ',');
    if (base_str.empty()) {
      throw std::runtime_error("Device base address is empty.");
    }
    char* end;
    reg_t base = static_cast<reg_t>(strtoull(base_str.c_str(), &end, 0));
    if (end != &*base_str.cend()) {
      throw std::runtime_error("Error parsing device base address.");
    }

    // The remainder of the string is the arguments. We could use getline, but
    // that could ignore newline characters in the arguments. That should be
    // rare and discouraged, but handle it here anyway with this weird in_avail
    // technique. The arguments are optional, so if there were no arguments
    // specified we could end up with an empty string here. That's okay.
    auto avail = stream.rdbuf()->in_avail();
    std::string args(avail, '\0');
    stream.readsome(&args[0], avail);

    plugin_devices.emplace_back(base, new mmio_plugin_device_t(name, args));
  };

  option_parser_t parser;
  parser.help(&suggest_help);
  parser.option('h', "help", 0, [&](const char* s){help(0);});
  parser.option('d', 0, 0, [&](const char* s){debug = true;});
  parser.option('g', 0, 0, [&](const char* s){histogram = true;});
  parser.option('l', 0, 0, [&](const char* s){log = true;});
  parser.option('p', 0, 1, [&](const char* s){nprocs = atoi(s);});
  parser.option('m', 0, 1, [&](const char* s){mems = make_mems(s);});
  // I wanted to use --halted, but for some reason that doesn't work.
  parser.option('H', 0, 0, [&](const char* s){halted = true;});
  parser.option(0, "rbb-port", 1, [&](const char* s){use_rbb = true; rbb_port = atoi(s);});
  parser.option(0, "pc", 1, [&](const char* s){start_pc = strtoull(s, 0, 0);});
  parser.option(0, "hartids", 1, hartids_parser);
  parser.option(0, "ic", 1, [&](const char* s){ic.reset(new icache_sim_t(s));});
  parser.option(0, "dc", 1, [&](const char* s){dc.reset(new dcache_sim_t(s));});
  parser.option(0, "l2", 1, [&](const char* s){l2.reset(cache_sim_t::construct(s, "L2$"));});
  parser.option(0, "log-cache-miss", 0, [&](const char* s){log_cache = true;});
  parser.option(0, "isa", 1, [&](const char* s){isa = s;});
  parser.option(0, "varch", 1, [&](const char* s){varch = s;});
  parser.option(0, "device", 1, device_parser);
  parser.option(0, "extension", 1, [&](const char* s){extension = find_extension(s);});
  parser.option(0, "dump-dts", 0, [&](const char *s){dump_dts = true;});
  parser.option(0, "disable-dtb", 0, [&](const char *s){dtb_enabled = false;});
  parser.option(0, "extlib", 1, [&](const char *s){
    void *lib = dlopen(s, RTLD_NOW | RTLD_GLOBAL);
    if (lib == NULL) {
      fprintf(stderr, "Unable to load extlib '%s': %s\n", s, dlerror());
      exit(-1);
    }
  });
  parser.option(0, "dm-progsize", 1,
      [&](const char* s){dm_config.progbufsize = atoi(s);});
  parser.option(0, "dm-sba", 1,
      [&](const char* s){dm_config.max_bus_master_bits = atoi(s);});
  parser.option(0, "dm-auth", 0,
      [&](const char* s){dm_config.require_authentication = true;});
  parser.option(0, "dmi-rti", 1,
      [&](const char* s){dmi_rti = atoi(s);});
  parser.option(0, "dm-abstract-rti", 1,
      [&](const char* s){dm_config.abstract_rti = atoi(s);});
  parser.option(0, "dm-no-hasel", 0,
      [&](const char* s){dm_config.support_hasel = false;});
  parser.option(0, "dm-no-abstract-csr", 0,
      [&](const char* s){dm_config.support_abstract_csr_access = false;});
  parser.option(0, "dm-no-halt-groups", 0,
      [&](const char* s){dm_config.support_haltgroups = false;});
  parser.option(0, "log-commits", 0, [&](const char* s){log_commits = true;});
  
  // IBDA simulation add-ons
  parser.option(0, "ist_sz", 1, [&](const char* s){ibda.ist_sz = atoi(s);});
  parser.option(0, "ist_ways", 1, [&](const char* s){ibda.ist_ways = atoi(s);});
  //parser.option(0, "ist_cw", 1, [&](const char* s){ist_cw = atoi(s);});
  parser.option(0, "ist_wp", 1, [&](const char* s){ibda.ist_wp = atoi(s);});
  parser.option(0, "ibda_ist_hash_xor_david", 0, [&](const char* s){ibda.ibda_ist_hash_xor_david = true;});
  parser.option(0, "ist_fully_associative", 0, [&](const char* s){ibda.ist_fully_associative = true;});
  parser.option(0, "ist_set_associative", 0, [&](const char* s){ibda.ist_set_associative = true;});
  parser.option(0, "ist_vb", 0, [&](const char* s){ibda.ist_vb = true;});
  parser.option(0, "ist_vb_sz", 1, [&](const char* s){ibda.ist_vb_sz = atoi(s);});
  parser.option(0, "ibda_compare_perfect", 0, [&](const char* s){ibda.ibda_compare_perfect = true;});
  parser.option(0, "ist_perfect", 0, [&](const char* s){ibda.ist_perfect = true;});
  parser.option(0, "ibda_tag_bits", 1, [&](const char* s){ibda.ibda_tag_bits = atoi(s);});
  parser.option(0, "trace_level", 1, [&](const char* s){ibda.trace_level = atoi(s);});
  parser.option(0, "calculate_ist_instruction_entropy", 0, [&](const char* s){ibda.calculate_ist_instruction_entropy = true;});
  parser.option(0, "calculate_instruction_entropy", 0, [&](const char* s){ibda.calculate_instruction_entropy = true;});
  parser.option(0, "ibda_hash_pc_mask", 1, [&](const char* s){ibda.ibda_hash_pc_mask = strtoull(s, NULL, 16);});
  parser.option(0, "ibda_hash_insn_mask", 1, [&](const char* s){ibda.ibda_hash_insn_mask = strtoull(s, NULL, 16);});
  parser.option(0, "ibda_simple_hash", 0, [&](const char* s){ibda.ibda_simple_hash = true;});
  parser.option(0, "ibda_binary_matrix_hash", 0, [&](const char* s){ibda.ibda_binary_matrix_hash = true;});
  parser.option(0, "seed", 1, [&](const char* s){ibda.seed = strtoull(s, NULL, 10);});
  parser.option(0, "ibda_no_hash", 0, [&](const char* s){ibda.ibda_no_hash = true;});
  parser.option(0, "ibda_xor_hash", 0, [&](const char* s){ibda.ibda_xor_hash = true;});
  parser.option(0, "count_wp_usage", 0, [&](const char* s){ibda.count_wp_usage = true;});
  parser.option(0, "ibda_bloom_hash", 0, [&](const char* s){ibda.ibda_hash_bloom = true;});
  parser.option(0, "bloom_k", 1, [&](const char* s){ibda.bloom_k = strtoull(s, NULL, 10);});
  parser.option(0, "bloom_m", 1, [&](const char* s){ibda.bloom_m = strtoull(s, NULL, 10);});
  parser.option(0, "bloom_fp_rate", 1, [&](const char* s){ibda.bloom_fp_rate = strtof(s, NULL);});


  auto argv1 = parser.parse(argv);
  std::vector<std::string> htif_args(argv1, (const char*const*)argv + argc);
  if (mems.empty())
    mems = make_mems("2048");

  if (!*argv1)
    help();


  printf("trace_level=%d\nist_sz=%lu\nist_ways=%lu\nist_wp=%lu\nibda_ist_hash_xor_david=%d\nibda_tag_bits=%d\nist_perfect=%d\nist_fully_associative=%d\nist_set_associative=%d\nist_vb=%d\nist_vb_sz=%lu\nibda_compare_perfect=%d\n",
      ibda.trace_level, ibda.ist_sz, ibda.ist_ways, ibda.ist_wp, ibda.ibda_ist_hash_xor_david, ibda.ibda_tag_bits, ibda.ist_perfect, ibda.ist_fully_associative, ibda.ist_set_associative, ibda.ist_vb, ibda.ist_vb_sz, ibda.ibda_compare_perfect);
  
  printf("pc_mask=%llx\ninsn_mask=%llx\n", ibda.ibda_hash_pc_mask, ibda.ibda_hash_insn_mask);
  if (ibda.ist_set_associative) {
    assert(ibda.ist_ways > 0);
    assert(ibda.ist_sz > 0);
    ibda.ist_sets = ibda.ist_sz/ibda.ist_ways;  
  }

  printf("RNG_SEED=%llu\n", ibda.seed);
  
  assert(!(ibda.ibda_simple_hash && ibda.ibda_binary_matrix_hash));

  assert(ibda.ist_wp>0);
  assert(! (ibda.ist_set_associative && ibda.ist_fully_associative));
  assert(! (ibda.ist_perfect &&  (ibda.ist_sz>0)));
  assert(! (ibda.calculate_ist_instruction_entropy && ibda.calculate_instruction_entropy));

  printf("bloom=%d\nbloom_k=%lu\nbloom_m=%lu\nbloom_fp_rate=%f\n",
          ibda.ibda_hash_bloom, ibda.bloom_k, ibda.bloom_m, ibda.bloom_fp_rate);
  if (ibda.ibda_hash_bloom) {
    assert(ibda.bloom_m > 0 && ibda.bloom_m <= 2048);
    assert(ibda.bloom_k > 0);
    assert(ibda.bloom_fp_rate > 0.0);
  }        
 

  sim_t s(isa, varch, nprocs, halted, start_pc, mems, plugin_devices, htif_args,
      std::move(hartids), dm_config,ibda);
  std::unique_ptr<remote_bitbang_t> remote_bitbang((remote_bitbang_t *) NULL);
  std::unique_ptr<jtag_dtm_t> jtag_dtm(
      new jtag_dtm_t(&s.debug_module, dmi_rti));
  if (use_rbb) {
    remote_bitbang.reset(new remote_bitbang_t(rbb_port, &(*jtag_dtm)));
    s.set_remote_bitbang(&(*remote_bitbang));
  }
  s.set_dtb_enabled(dtb_enabled);

  if (dump_dts) {
    printf("%s", s.get_dts());
    return 0;
  }

  if (ic && l2) ic->set_miss_handler(&*l2);
  if (dc && l2) dc->set_miss_handler(&*l2);
  if (ic) ic->set_log(log_cache);
  if (dc) dc->set_log(log_cache);
  for (size_t i = 0; i < nprocs; i++)
  {
    if (ic) s.get_core(i)->get_mmu()->register_memtracer(&*ic);
    if (dc) s.get_core(i)->get_mmu()->register_memtracer(&*dc);
    if (extension) s.get_core(i)->register_extension(extension());
  }

  s.set_debug(debug);
  s.set_log(log);
  s.set_histogram(histogram);
  s.set_log_commits(log_commits);

  auto return_code = s.run();

  for (auto& mem : mems)
    delete mem.second;

  for (auto& plugin_device : plugin_devices)
    delete plugin_device.second;
  return return_code;
}
