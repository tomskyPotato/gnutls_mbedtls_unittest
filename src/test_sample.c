#include "../inc/unity.h"
#include "../inc/test_sample.h"

void test_Addition(void) {
    TEST_ASSERT_EQUAL_INT(5, 2 + 3);
}

void run_all_tests(void) {
    RUN_TEST(test_Addition);
    RUN_TEST(TEST_PACKET_GOOD, 1);
    RUN_TEST(TEST_PACKET_FAilure, 2);
}

void TEST_PACKET_GOOD(void)
{
    TEST_ASSERT_EQUAL(1, 1); //hier ist alles in Ordnung
}

void TEST_PACKET_FAilure(void)
{
    TEST_ASSERT_EQUAL(1, 2); //hier habe ich einen Fehler eingebaut
}
