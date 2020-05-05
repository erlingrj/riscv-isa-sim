#include <stdio.h>
#include <stdint.h>
typedef uint64_t reg_t;

#include "ibda_hash.h"

#define CATCH_CONFIG_MAIN
#include "catch.hpp"




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