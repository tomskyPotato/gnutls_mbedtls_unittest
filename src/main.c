#include <stdio.h>
#include <stdlib.h>

#include "../inc/unity.h"
#include "../inc/test_sample.h"

int main(void)
{
    UNITY_BEGIN();
    run_all_tests();
    return UNITY_END();
}

void
setUp(void)
{
}

void
tearDown(void)
{
}
