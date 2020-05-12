#include <stdio.h>
#include <stdint.h>
#include <random>
typedef uint64_t reg_t;

#include "ibda_hash.h"
#include "bloom.h"

#define CATCH_CONFIG_MAIN
#include "catch.hpp"




TEST_CASE( "XOR Hash", "[xor-hash]") {
    SECTION("do it") {
        IbdaHashXor h1(0xFFFFFFFFFFFFFFFF, 0x00);
        reg_t hash = h1.hash(0xABCDE, 0xFFFFF);
        REQUIRE(h1.get_set_index(hash,6) == 0x16);
        REQUIRE(h1.get_tag(hash,6) == 0x1579); 

        reg_t hash2 = h1.hash(0x803A466, 0xFFFFF);
        REQUIRE(h1.get_set_index(hash2,6) == 0x3B);
        REQUIRE(h1.get_tag(hash2,6) == 0x100748); 

    }
}


TEST_CASE( "BloomFilter", "[bloom-filter]") {


    SECTION("n max") {
        BloomFilter b1(6,2048,0.001,0,true,0,0,true,NULL,NULL,NULL);
    
        REQUIRE(b1.get_nmax() == 778);
    }

    SECTION("Constructor") {
        reg_t fp = 0;
        reg_t np = 0;
        reg_t bf = 0;
        BloomFilter b1(
            10,
            1028,
            0.01,
            0,
            true,
            0xFFFFFFFFFFFFFFFF,
            0x00,
            true,
            &fp,
            &np,
            &bf
        );
        // False positives work
        b1.test_incr_fp();
        b1.test_incr_np();
        b1.test_incr_np();
        REQUIRE(fp == 1);
        REQUIRE(np == 2);

        b1.flush();
        b1.flush();
        REQUIRE(bf == 2);

    }

    SECTION("Add") {
        reg_t fp = 0;
        reg_t np = 0;
        reg_t bf = 0;
        BloomFilter b1(
            6,
            2048,
            0.01,
            0,
            true,
            0xFFFFFFFFFFFFFFFF,
            0x00,
            true,
            &fp,
            &np,
            &bf
        );

        b1.add(0xABCDE, 0x00);
        REQUIRE(!b1.exists(0x63, 0x32));
        REQUIRE(b1.exists(0xABCDE, 0x00));
    }

    SECTION("Flush") {
        reg_t fp = 0;
        reg_t np = 0;
        reg_t bf = 0;
        BloomFilter b1(
            6,
            2048,
            0.001,
            0,
            true,
            0xFFFFFFFFFFFFFFFF,
            0x00,
            true,
            &fp,
            &np,
            &bf
        );



        for (int i = 0; i<779; ++i) {
            b1.add(i,i*i);
        }
        REQUIRE(bf == 1);

        REQUIRE(b1.get_count() == 1);
        std::bitset<2048> ** ist = b1.get_bitset();
        for (int i = 0; i<6; ++i) {
            REQUIRE(ist[i]->count() == 1);
        }
    }

    SECTION("Random exists") {
        /* Random number generator */
        std::default_random_engine g1(0);

        /* Distribution on which to apply the generator */
        std::uniform_int_distribution<reg_t> distribution(0,0xFFFFFFFF);

        reg_t fp = 0;
        reg_t np = 0;
        reg_t bf = 0;
        int k = 6;
        int m = 2048;
        float fp_max = 0.001;
        int seed = 0;
        reg_t pc_mask = 0x3F;
        reg_t insn_mask = 0xFFFFFFFF;

        BloomFilter b1(k,m,fp_max,seed,true,pc_mask,insn_mask,true,&fp,&np, &bf);
        int n_max = b1.get_nmax();
        reg_t pc_in[n_max];
        reg_t insn_in[n_max];

        for (int i = 0; i<n_max; ++i) {
            pc_in[i] = distribution(g1);
            insn_in[i] = distribution(g1);
            b1.add(pc_in[i], insn_in[i]);
        }

        for (int i = 0; i<n_max; ++i) {
            REQUIRE(b1.exists(pc_in[i], insn_in[i]));
        }

        REQUIRE(fp == 0);
        REQUIRE(np == 0);

        for (int i = 0; i<100000; ++i) {
            b1.exists(distribution(g1), distribution(g1));
        }

        REQUIRE(fp > 0);

        b1.add(0,0);
        REQUIRE(bf == 1);

        REQUIRE(b1.get_count() == 1);

        for (int i = 0; i<n_max; ++i) {
            b1.exists(pc_in[i], insn_in[i]);
        }

        REQUIRE(np == n_max);
    }

}




TEST_CASE( "Ibda Simple Hash", "[ibda-simple-hash]" ) {

    IbdaHashSimple h1(6,0xFF,0x0);
    IbdaHashSimple h2(6,0xF,0xF);
    IbdaHashSimple h5(12, 0x3E, 0xFFFF);
    IbdaHashSimple h6(14, 0x7E, 0x8490);

    SECTION("Combine") {
        REQUIRE(h1.combine(0x43, 0x84) == 0x43);
        REQUIRE(h2.combine(0x65, 0x23) == 0x35);
        REQUIRE(h5.combine(0x801E6, 0x23A2) == 0x47453);
        REQUIRE(h6.combine(0x48, 0xa75c0) == 0x1A4);
    } 

    SECTION("Hash") {
        REQUIRE(h1.hash(0x66,0x66) == 0x26);
        REQUIRE(h1.hash(0x2A,0xFF) == 0x2A);
        REQUIRE(h2.hash(0x56,0x32) == 0x26); 
        REQUIRE(h2.hash(0x66,0xA3) == 0x36);
        REQUIRE(h6.hash(0x0076a40b7c, 0x6008a6be5) == h6.combine(0x0076a40b7c, 0x6008a6be5));

    }

    SECTION("Get index") {
        REQUIRE(h1.get_set_index(0x4A3B, 6) == 0x3B);
        REQUIRE(h1.get_set_index(0x64, 8) == 0x64);
    }

    SECTION("Get tag") {
        REQUIRE(h1.get_tag(0x36A2B, 8) == 0x36A);
        REQUIRE(h1.get_tag(0x64, 8) == 0x00);

    }
    SECTION("Distribution") {
        std::random_device rd;

        /* Random number generator */
        std::default_random_engine generator(rd());
        /* Distribution on which to apply the generator */
        std::uniform_int_distribution<reg_t> distribution(0,0xFFFFFFFF);

        int res[256] = {0};
        int runs = 10000000;

        for (int i = 0; i <runs; ++i) {
            reg_t pc = distribution(generator);
            reg_t insn = distribution(generator);

//            ++res[h8.hash(pc,insn)];
        }

        int max = 0;
        int min = runs +1;
        for (int i = 0; i<256; i++) {
            if (res[i] > max) {
                max = res[i];
            }
            if (res[i] < min) {
                min = res[i];
            }
        }

  //      printf("max=%d min=%d min/max = %f\n", max,min, ((float) min) / max);
    }
        
}


TEST_CASE( "IbdaHashNone", "[no-hash]") {
     std::random_device rd;

    /* Random number generator */
    std::default_random_engine g(rd());
    /* Distribution on which to apply the generator */
    std::uniform_int_distribution<reg_t> d(0,0xFFFFFFFFFFFFFFFF);
    std::uniform_int_distribution<reg_t> d2(0,0xFFFFFFFF);


    SECTION("FULL PC") {
        IbdaHashNone h1(0xFFFFFFFFFFFFFFFF, 0x00);

        for (int i = 0; i<10000; ++i) {
            reg_t pc = d(g);
            reg_t hash = h1.hash(pc, d(g));
            REQUIRE(pc==hash);
        }
    }

    SECTION("BOOM") {
        IbdaHashNone h2(0x3E, 0xFFFFFFFF);
        for (int i = 0; i<10000; ++i) {
            reg_t pc = d2(g);
            reg_t insn = d2(g);
            reg_t hash = h2.hash(pc,insn);
            reg_t res = ((insn << 5) | ((pc >> 1) & 0x1F));
            if (hash != res) {
                printf("pc=%lx insn=%lx\n",pc,insn);
            }

            REQUIRE(hash == res);
        }
    }

}


TEST_CASE( "Binary Hash Matrix ", "[binary-hash-matrix]") {
    IbdaHashBinaryMatrix h1(3,0x0,0xF,0,false);
    IbdaHashBinaryMatrix h2(6,0x0,0xFF, 0,true);

    SECTION("Combine") {
        REQUIRE(h1.combine(0xFF, 0xD) == 0xD);
    }

    SECTION("Hash") {
        REQUIRE(h1.hash(0xFF, 0xD) == 2);
        reg_t r2[100];
        for(int i = 0; i<100; ++i) {
            REQUIRE(h2.hash(0x32, 0x32) < 64);
        }
    }

    IbdaHashBinaryMatrix h3(8,0xff, 0xffffffff,0,true);
    
    SECTION("Realistic") {
        for (int i =0; i<100; i++) {
            REQUIRE(h3.hash(0x800010 + i, 0x21bd9300) < 256);
        }
    }

    // Hashing 8 bits from PC and 32 bit from insn and generating total of 
    // 8 bits
    int bits_out = 15;
    IbdaHashBinaryMatrix h8(bits_out,0xff, 0xffffffff,0,true);

    SECTION("Uniform distribution") {
        std::random_device rd;

        /* Random number generator */
        std::default_random_engine generator(rd());
        /* Distribution on which to apply the generator */
        std::uniform_int_distribution<reg_t> distribution(0,0xFF);

        int m = pow(2,bits_out);
        int res[m] = {0};
        int runs = 10000000;

        for (int i = 0; i <runs; ++i) {
            reg_t pc = distribution(generator);
            reg_t insn = distribution(generator);

            ++res[h8.hash(pc,insn)];
        }
        float score= 0.0;
        for (int i = 0; i<m; i++) {
            score += ((float) res[i])*(((float) res[i]+1))/2;
        }

        score = score/((float) (((float) runs)/(m*2))*(runs+(2*m)-1)); 


        printf("entropy score = %f\n", score);
    }
}

TEST_CASE("RNG") {
    SECTION("Seeded RNG") {

        /* Random number generator */
        std::default_random_engine g1(0);
        std::default_random_engine g2(0);
        std::default_random_engine g3(12345);

        /* Distribution on which to apply the generator */
        std::uniform_int_distribution<reg_t> distribution(0,0xFFFFFFFF);

        int res[256] = {0};
        int runs = 100;

        for (int i = 0; i <runs; ++i) {
           // printf("rng=%d\n", distribution(g3));
            if (distribution(g1) != distribution(g2)) {
                REQUIRE(false);
            }
        }

        std::default_random_engine g4(123456);

        REQUIRE(distribution(g3) != distribution(g4));

    }
}




/*

int main(int argc, char ** argv) {
    IbdaHashSimple h1(8,6,0xFF,0x0);
    IbdaHashSimple h2(8,6,0xF,0xF);
    
    // Check that Combine works
    assert(h1.combine(0x43, 0x84) == 0x43);
    assert(h2.combine(0x65, 0x23) == 0x35);

    //IbdaHashBinaryMatrix h3(4,3,false,0,false);
    //IbdaHashBinaryMatrix h4(8,6,false,0,true);


    //IbdaHashSimple h5(63,62,true);

    //assert(h5.hash(0x81723718236) == (0x81723718236 >> 1) );

    printf("h2.hash(0x66) = %lu\n",h2.hash(0x66,0x66));
    printf("h1.hash(0x66) = %lu\n",h1.hash(0x66,0x66));

    assert(h1.hash(0x66,0x66) == 0x33);
    assert(h2.hash(0x66,0x66) == 0x26);
    assert(h1.hash(0x56,0x56) == 0x2B);
    assert(h2.hash(0x56,0x56) == 0x16);

    //printf("h3.hash(0xD) = %lu\n", h3.hash(0xD));
    //printf("h4.hash(0xD) = %lu\n", h4.hash(0xD));

}

*/