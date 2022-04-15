#include <stdio.h>

void vuln() {
    puts("Come get me");

    char buffer[20];
    gets(buffer);
}

int main() {
    vuln();

    return 0;
}
