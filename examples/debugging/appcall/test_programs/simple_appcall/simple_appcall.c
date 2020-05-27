#include <stdio.h>

typedef int int32;
int ref4(int32 *a)
{
  if (a == NULL)
  {
    printf("ref4: no number passed!");
    return -1;
  }
  printf("ref4: entered with %d\n", *a);
  (*a)++;
  return 1;
}

typedef long long int int64;
int ref8(int64 *a)
{
  if (a == NULL)
  {
    printf("ref8: no number passed!");
    return -1;
  }
  printf("ref8: entered with %lld\n", *a);
  (*a)++;
  return 1;
}

int main()
{
  int32 x;
  int res = ref4(&x);
  int64 y;
  return res + ref8(&y);
}
