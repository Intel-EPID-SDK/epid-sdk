/*############################################################################
  # Copyright 2017-2019 Intel Corporation
  #
  # Licensed under the Apache License, Version 2.0 (the "License");
  # you may not use this file except in compliance with the License.
  # You may obtain a copy of the License at
  #
  #     http://www.apache.org/licenses/LICENSE-2.0
  #
  # Unless required by applicable law or agreed to in writing, software
  # distributed under the License is distributed on an "AS IS" BASIS,
  # WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
  # See the License for the specific language governing permissions and
  # limitations under the License.
  ############################################################################*/
/// Unit tests for OneTimePad.
/*! \file */

#include <gtest/gtest.h>

#include "testhelper/onetimepad.h"

namespace {
uint32_t be32toh(uint32_t big_endian_32bits) {
  return ((uint32_t)(((((unsigned char*)&(big_endian_32bits))[0]) << 24) +
                     ((((unsigned char*)&(big_endian_32bits))[1]) << 16) +
                     ((((unsigned char*)&(big_endian_32bits))[2]) << 8) +
                     (((unsigned char*)&(big_endian_32bits))[3])));
}

TEST(OneTimePadTest, GenerateFailsWhenDefaultConstructedWithoutInit) {
  OneTimePad otp;
  EXPECT_EQ(0u, otp.BitsConsumed());
  std::vector<unsigned int> actual({0, 0});
  EXPECT_NE(0, OneTimePad::Generate(actual.data(), 8, &otp));
}

TEST(OneTimePadTest, GeneratesCorrectDataWhenConstructedWithUint8s) {
  std::vector<unsigned int> actual1({0, 0});
  std::vector<unsigned int> actual2({0, 0});
  const std::vector<unsigned int> expected1({0x07050301, 0});
  const std::vector<unsigned int> expected2({0x0e0c0a09, 0});
  OneTimePad otp({0x01, 0x03, 0x05, 0x07, 0x09, 0x0a, 0x0c, 0x0e});
  EXPECT_EQ(0u, otp.BitsConsumed());
  EXPECT_EQ(0, OneTimePad::Generate(actual1.data(), 32, &otp));
  EXPECT_EQ(expected1, actual1);
  EXPECT_EQ(32u, otp.BitsConsumed());
  EXPECT_EQ(0, OneTimePad::Generate(actual2.data(), 32, &otp));
  EXPECT_EQ(expected2, actual2);
  EXPECT_EQ(64u, otp.BitsConsumed());
}

TEST(OneTimePadTest, GeneratesCorrectDataWhenInitializedWithUint8s) {
  std::vector<unsigned int> actual1({0, 0});
  std::vector<unsigned int> actual2({0, 0});
  const std::vector<unsigned int> expected1({0x07050301, 0});
  const std::vector<unsigned int> expected2({0x0e0c0a09, 0});
  OneTimePad otp;
  otp.InitUint8({0x01, 0x03, 0x05, 0x07, 0x09, 0x0a, 0x0c, 0x0e});
  EXPECT_EQ(0u, otp.BitsConsumed());
  EXPECT_EQ(0, OneTimePad::Generate(actual1.data(), 32, &otp));
  EXPECT_EQ(expected1, actual1);
  EXPECT_EQ(32u, otp.BitsConsumed());
  EXPECT_EQ(0, OneTimePad::Generate(actual2.data(), 32, &otp));
  EXPECT_EQ(expected2, actual2);
  EXPECT_EQ(64u, otp.BitsConsumed());
}
TEST(OneTimePadTest, GeneratesCorrectDataWhenInitializedWithUint32s) {
  std::vector<uint32_t> actual({0x00});
  const std::vector<uint32_t> expected({0x01});
  std::vector<uint32_t> actual2({0x00});
  const std::vector<uint32_t> expected2({0x01020304});
  OneTimePad otp({0x01, 0x03, 0x05, 0x07, 0x09, 0x0a, 0x0c, 0x0e});
  otp.InitUint32({0x01, 0x01020304});
  EXPECT_EQ(0u, otp.BitsConsumed());
  EXPECT_EQ(0, OneTimePad::Generate(actual.data(), 32, &otp));
  EXPECT_EQ(32u, otp.BitsConsumed());
  EXPECT_EQ(expected, actual);
  EXPECT_EQ(0, OneTimePad::Generate(actual2.data(), 32, &otp));
  EXPECT_EQ(expected2, actual2);
  EXPECT_EQ(64u, otp.BitsConsumed());
}
TEST(OneTimePadTest, GeneratesSingleBytesCorrectly) {
  OneTimePad otp({0x01, 0x03, 0x05, 0x07, 0x09, 0x0a, 0x0c, 0x0e});
  std::vector<uint8_t> expected1({0x01, 0x00, 0x00, 0x00});
  std::vector<uint8_t> expected2({0x03, 0x00, 0x00, 0x00});
  std::vector<uint8_t> expected3({0x05, 0x00, 0x00, 0x00});
  std::vector<uint8_t> actual({0, 0, 0, 0});
  EXPECT_EQ(0, OneTimePad::Generate((uint32_t*)actual.data(), 8, &otp));
  EXPECT_EQ(8u, otp.BitsConsumed());
  EXPECT_EQ(expected1, actual);
  EXPECT_EQ(0, OneTimePad::Generate((uint32_t*)actual.data(), 8, &otp));
  EXPECT_EQ(16u, otp.BitsConsumed());
  EXPECT_EQ(expected2, actual);
  EXPECT_EQ(0, OneTimePad::Generate((uint32_t*)actual.data(), 8, &otp));
  EXPECT_EQ(24u, otp.BitsConsumed());
  EXPECT_EQ(expected3, actual);
}

TEST(OneTimePadTest, GenerateRejectsNullPtr) {
  OneTimePad otp(8);
  EXPECT_NE(0, OneTimePad::Generate(nullptr, 32, &otp));
}
TEST(OneTimePadTest, GenerateRejectsNegativeBits) {
  OneTimePad otp(8);
  std::vector<unsigned int> actual({0, 0});
  EXPECT_NE(0, OneTimePad::Generate(actual.data(), -32, &otp));
}
TEST(OneTimePadTest, GenerateRejectsZeroBits) {
  OneTimePad otp(8);
  std::vector<unsigned int> actual({0, 0});
  EXPECT_NE(0, OneTimePad::Generate(actual.data(), 0, &otp));
}
TEST(OneTimePadTest, GenerateRejectsTooLargeRequest) {
  OneTimePad otp(8);
  std::vector<unsigned int> actual({0, 0});
  EXPECT_EQ(0, OneTimePad::Generate(actual.data(), 32, &otp));
  EXPECT_EQ(0, OneTimePad::Generate(actual.data(), 32, &otp));
  EXPECT_NE(0, OneTimePad::Generate(actual.data(), 32, &otp));
}

TEST(OneTimePadTest, GenerateHandlesBitRequestsThatAreNotByteMultiples) {
  OneTimePad otp({0xf1, 0xe2, 0xd3, 0xc4, 0xb5, 0xa6, 0x97, 0x88});
  std::vector<unsigned int> actual_buffer({0, 0});
  std::vector<unsigned int> expected_buffer({0, 0});
  unsigned int* actual = actual_buffer.data();
  unsigned int* expected = expected_buffer.data();

  void* user_data = &otp;

  // check pulling off a single bit (1)
  // (1)111000111100010110100111100010010110101101001101001011110001000
  actual[0] = 0xffffffff;
  actual[1] = 0xffffffff;
  int num_bits = 1;

  expected[0] = 1;
  expected[1] = 0xffffffff;

  size_t start_bits = otp.BitsConsumed();
  int sts = OneTimePad::Generate(actual, num_bits, user_data);
  size_t bits_consumed = otp.BitsConsumed() - start_bits;

  EXPECT_EQ(0, sts);
  EXPECT_EQ((size_t)num_bits, bits_consumed);
  EXPECT_EQ(expected_buffer, actual_buffer);

  // check pulling off the next 3 bits (111)
  // 1(111)000111100010110100111100010010110101101001101001011110001000
  actual[0] = 0xffffffff;
  actual[1] = 0xffffffff;
  num_bits = 3;
  expected[0] = 7;
  expected[1] = 0xffffffff;

  start_bits = otp.BitsConsumed();
  sts = OneTimePad::Generate(actual, num_bits, user_data);
  bits_consumed = otp.BitsConsumed() - start_bits;

  EXPECT_EQ(0, sts);
  EXPECT_EQ((size_t)num_bits, bits_consumed);
  EXPECT_EQ(expected_buffer, actual_buffer);

  // check pulling off the next bit (0)
  // 1111(0)00111100010110100111100010010110101101001101001011110001000
  actual[0] = 0xffffffff;
  actual[1] = 0xffffffff;
  num_bits = 1;
  expected[0] = 0;
  expected[1] = 0xffffffff;

  start_bits = otp.BitsConsumed();
  sts = OneTimePad::Generate(actual, num_bits, user_data);
  bits_consumed = otp.BitsConsumed() - start_bits;

  EXPECT_EQ(0, sts);
  EXPECT_EQ((size_t)num_bits, bits_consumed);
  EXPECT_EQ(expected_buffer, actual_buffer);

  // check pulling off the next 3 bits (001)
  // 11110(001)11100010110100111100010010110101101001101001011110001000
  actual[0] = 0xffffffff;
  actual[1] = 0xffffffff;
  num_bits = 3;
  expected[0] = 1;
  expected[1] = 0xffffffff;

  start_bits = otp.BitsConsumed();
  sts = OneTimePad::Generate(actual, num_bits, user_data);
  bits_consumed = otp.BitsConsumed() - start_bits;

  EXPECT_EQ(0, sts);
  EXPECT_EQ((size_t)num_bits, bits_consumed);
  EXPECT_EQ(expected_buffer, actual_buffer);

  // check pulling off the next 2 bits (11)
  // 11110001(11)100010110100111100010010110101101001101001011110001000
  actual[0] = 0xffffffff;
  actual[1] = 0xffffffff;
  num_bits = 2;
  expected[0] = 3;
  expected[1] = 0xffffffff;

  start_bits = otp.BitsConsumed();
  sts = OneTimePad::Generate(actual, num_bits, user_data);
  bits_consumed = otp.BitsConsumed() - start_bits;

  EXPECT_EQ(0, sts);
  EXPECT_EQ((size_t)num_bits, bits_consumed);
  EXPECT_EQ(expected_buffer, actual_buffer);

  // check pulling off the next 3 bits (100)
  // 1111000111(100)010110100111100010010110101101001101001011110001000
  actual[0] = 0xffffffff;
  actual[1] = 0xffffffff;
  num_bits = 3;
  expected[0] = 4;
  expected[1] = 0xffffffff;

  start_bits = otp.BitsConsumed();
  sts = OneTimePad::Generate(actual, num_bits, user_data);
  bits_consumed = otp.BitsConsumed() - start_bits;

  EXPECT_EQ(0, sts);
  EXPECT_EQ((size_t)num_bits, bits_consumed);
  EXPECT_EQ(expected_buffer, actual_buffer);

  // 0xf1, 0xe2, 0xd3, 0xc4, 0xb5, 0xa6, 0x97, 0x88
  // check pulling off the next 32 bits ()
  // 1111000111100(01011010011110001001011010110100)1101001011110001000
  actual[0] = 0xffffffff;
  actual[1] = 0xffffffff;
  num_bits = 32;
  expected[0] = be32toh(0x5a7896b4);  // 0b01011010011110001001011010110100
  expected[1] = 0xffffffff;

  start_bits = otp.BitsConsumed();
  sts = OneTimePad::Generate(actual, num_bits, user_data);
  bits_consumed = otp.BitsConsumed() - start_bits;

  EXPECT_EQ(0, sts);
  EXPECT_EQ((size_t)num_bits, bits_consumed);
  EXPECT_EQ(expected_buffer, actual_buffer);

  // check pulling off 33 bits (after reinitialization)
  otp.InitUint8({0xf1, 0xe2, 0xd3, 0xc4, 0xb5, 0xa6, 0x97, 0x88});
  // (111100011110001011010011110001001)0110101101001101001011110001000
  actual[0] = 0xffffffff;
  actual[1] = 0xffffffff;
  num_bits = 33;
  expected[0] = be32toh(0xf1e2d3c4);
  expected[1] = 0x1;

  start_bits = otp.BitsConsumed();
  sts = OneTimePad::Generate(actual, num_bits, user_data);
  bits_consumed = otp.BitsConsumed() - start_bits;

  EXPECT_EQ(0, sts);
  EXPECT_EQ((size_t)num_bits, bits_consumed);
  EXPECT_EQ(expected_buffer, actual_buffer);
}

TEST(OneTimePadTest, GenerateCoddlesDevelopersWhoDoNotCheckReturnValues) {
  OneTimePad otp(4);
  uint32_t word;
  EXPECT_EQ(0, OneTimePad::Generate(&word, 32, &otp));
  EXPECT_NE(0, OneTimePad::Generate(&word, 32, &otp));
  EXPECT_THROW(OneTimePad::Generate(&word, 32, &otp), std::runtime_error);
}

}  // namespace
