#include <iostream>
#include <string>

extern "C" {
bool verify_jwt(const char *jwt);
bool check_property(const char *jwt, const char *property,
                    const uint8_t *exp_value, size_t expValSize);
}

// g++ main.cpp -L./target/debug -ltless_jwt
// ./a.out
// $ Verified!
// $ Not verified :-(
int main() {
    std::string goodJwt =
        "eyJhbGciOiJSUzI1NiIsImprdSI6Imh0dHBzOi8vZmFhc21hdHRwcm92LmV1czIuYXR0ZX"
        "N0LmF6dXJlLm5ldC9jZXJ0cyIsImtpZCI6IkowcEFQZGZYWEhxV1dpbWdySDg1M3dNSWRo"
        "NS9mTGUxejZ1U1hZUFhDYTA9IiwidHlwIjoiSldUIn0."
        "eyJleHAiOjE3MjgwOTAxMTMsImlhdCI6MTcyODA2MTMxMywiaXMtZGVidWdnYWJsZSI6dH"
        "J1ZSwiaXNzIjoiaHR0cHM6Ly9mYWFzbWF0dHByb3YuZXVzMi5hdHRlc3QuYXp1cmUubmV0"
        "IiwianRpIjoiNmQyNWIyMjNlMmJhMTFkNmExMWY4NWE2Y2RiYzE1NzcwNjE2ODJkMDczM2"
        "NmNGM2NWZiYjU4ZWJlODg4YTMzOSIsIm1hYS1hdHRlc3RhdGlvbmNvbGxhdGVyYWwiOnsi"
        "cWVpZGNlcnRzaGFzaCI6ImE2NGQ2NDkxOTg1MDdkOGI1N2UzM2Y2M2FiMjY2ODM4ZjQzZj"
        "MyN2JkNGFhY2M3ODUxMGI2OTc2ZWQwNDZlMTAiLCJxZWlkY3JsaGFzaCI6ImFkZmExOTQy"
        "NDIwZTY5ZGY1MTE4ZmYwMDZiNTNhZTFlNWRmZDkxZTVhNTcxMjQyOTczMTI2Yjg2MGFkNW"
        "ViMTMiLCJxZWlkaGFzaCI6Ijc3MDFmNjQ3MDBiN2Y1MDVkN2I0YjdhOTNlNDVkNWNkZThj"
        "ZmM4NjViNjBmMWRkNDllY2JlZTk3OTBjMzM3MmUiLCJxdW90ZWhhc2giOiI0NDNmN2JmY2"
        "QxN2U0YjI3NmQ1ODI1Nzk0MTJiZmE2YjNjMWI5YTU2N2FlZjE1YmE1ZDJiNDdiZTRhMGVl"
        "OWVhIiwidGNiaW5mb2NlcnRzaGFzaCI6ImE2NGQ2NDkxOTg1MDdkOGI1N2UzM2Y2M2FiMj"
        "Y2ODM4ZjQzZjMyN2JkNGFhY2M3ODUxMGI2OTc2ZWQwNDZlMTAiLCJ0Y2JpbmZvY3JsaGFz"
        "aCI6ImFkZmExOTQyNDIwZTY5ZGY1MTE4ZmYwMDZiNTNhZTFlNWRmZDkxZTVhNTcxMjQyOT"
        "czMTI2Yjg2MGFkNWViMTMiLCJ0Y2JpbmZvaGFzaCI6IjY4NjRjNjg3NGMyZWYzNmJjOTJl"
        "NTg3ZTAwOTMwYmYzZWEwYmM0ODYyZDA2YjBmYmU2YWY4NjMyN2UwNGMzNTcifSwibmJmIj"
        "oxNzI4MDYxMzEzLCJwcm9kdWN0LWlkIjowLCJzZ3gtbXJlbmNsYXZlIjoiNjUwNmIzYmI2"
        "NmFlMTQ0MWYyYzIwODZlMjM0MGYzNzY2M2YyZDU4ZmJhYTViZDYwMWE3MTFiMDRiNDk3ZT"
        "E0NSIsInNneC1tcnNpZ25lciI6IjgzZDcxOWU3N2RlYWNhMTQ3MGY2YmFmNjJhNGQ3NzQz"
        "MDNjODk5ZGI2OTAyMGY5YzcwZWUxZGZjMDhjN2NlOWUiLCJzdm4iOjAsInRlZSI6InNneC"
        "IsIngtbXMtYXR0ZXN0YXRpb24tdHlwZSI6InNneCIsIngtbXMtcG9saWN5Ijp7ImlzLWRl"
        "YnVnZ2FibGUiOnRydWUsInByb2R1Y3QtaWQiOjAsInNneC1tcmVuY2xhdmUiOiI2NTA2Yj"
        "NiYjY2YWUxNDQxZjJjMjA4NmUyMzQwZjM3NjYzZjJkNThmYmFhNWJkNjAxYTcxMWIwNGI0"
        "OTdlMTQ1Iiwic2d4LW1yc2lnbmVyIjoiODNkNzE5ZTc3ZGVhY2ExNDcwZjZiYWY2MmE0ZD"
        "c3NDMwM2M4OTlkYjY5MDIwZjljNzBlZTFkZmMwOGM3Y2U5ZSIsInN2biI6MCwidGVlIjoi"
        "c2d4In0sIngtbXMtcG9saWN5LWhhc2giOiJPd0V2cFNWRVdBNWVpc0NFbmNCdDhOU1pGTF"
        "lEUktvTGFvT05Qclpnb2VZIiwieC1tcy1zZ3gtY29sbGF0ZXJhbCI6eyJxZWlkY2VydHNo"
        "YXNoIjoiYTY0ZDY0OTE5ODUwN2Q4YjU3ZTMzZjYzYWIyNjY4MzhmNDNmMzI3YmQ0YWFjYz"
        "c4NTEwYjY5NzZlZDA0NmUxMCIsInFlaWRjcmxoYXNoIjoiYWRmYTE5NDI0MjBlNjlkZjUx"
        "MThmZjAwNmI1M2FlMWU1ZGZkOTFlNWE1NzEyNDI5NzMxMjZiODYwYWQ1ZWIxMyIsInFlaW"
        "RoYXNoIjoiNzcwMWY2NDcwMGI3ZjUwNWQ3YjRiN2E5M2U0NWQ1Y2RlOGNmYzg2NWI2MGYx"
        "ZGQ0OWVjYmVlOTc5MGMzMzcyZSIsInF1b3RlaGFzaCI6IjQ0M2Y3YmZjZDE3ZTRiMjc2ZD"
        "U4MjU3OTQxMmJmYTZiM2MxYjlhNTY3YWVmMTViYTVkMmI0N2JlNGEwZWU5ZWEiLCJ0Y2Jp"
        "bmZvY2VydHNoYXNoIjoiYTY0ZDY0OTE5ODUwN2Q4YjU3ZTMzZjYzYWIyNjY4MzhmNDNmMz"
        "I3YmQ0YWFjYzc4NTEwYjY5NzZlZDA0NmUxMCIsInRjYmluZm9jcmxoYXNoIjoiYWRmYTE5"
        "NDI0MjBlNjlkZjUxMThmZjAwNmI1M2FlMWU1ZGZkOTFlNWE1NzEyNDI5NzMxMjZiODYwYW"
        "Q1ZWIxMyIsInRjYmluZm9oYXNoIjoiNjg2NGM2ODc0YzJlZjM2YmM5MmU1ODdlMDA5MzBi"
        "ZjNlYTBiYzQ4NjJkMDZiMGZiZTZhZjg2MzI3ZTA0YzM1NyJ9LCJ4LW1zLXNneC1pcy1kZW"
        "J1Z2dhYmxlIjp0cnVlLCJ4LW1zLXNneC1tcmVuY2xhdmUiOiI2NTA2YjNiYjY2YWUxNDQx"
        "ZjJjMjA4NmUyMzQwZjM3NjYzZjJkNThmYmFhNWJkNjAxYTcxMWIwNGI0OTdlMTQ1IiwieC"
        "1tcy1zZ3gtbXJzaWduZXIiOiI4M2Q3MTllNzdkZWFjYTE0NzBmNmJhZjYyYTRkNzc0MzAz"
        "Yzg5OWRiNjkwMjBmOWM3MGVlMWRmYzA4YzdjZTllIiwieC1tcy1zZ3gtcHJvZHVjdC1pZC"
        "I6MCwieC1tcy1zZ3gtcmVwb3J0LWRhdGEiOiI1MmM0YmJjZWViNTkxMjRkNTg0NzQzZTc1"
        "MGQ0NmNhN2FiOTU2YzlkZDAzMmU4ODcyYjM3MjcwNWZhOWRlNGUzYTliZTVkZGVkNzM0Yz"
        "g1Nzg1NDM0NTNiOWE5OGFjYjQxOTUxNDYzYjUxZGUzNjIzYzRiNjc5NWM1MjYyZmE1MyIs"
        "IngtbXMtc2d4LXN2biI6MCwieC1tcy1zZ3gtdGNiaWRlbnRpZmllciI6IjEwIiwieC1tcy"
        "12ZXIiOiIxLjAifQ.2MHmljiFFxQzlU3qLHoEGx2wcyvXXOyLUdaMzekYiuG2ZiEh4H-"
        "g1PI-TymWpdUFkT-0a2zw06tdP0IOWmbvqF-"
        "uSta3wlINN1LmsBapZiLBwxYH2otTvr1z9oy1iRMhe44x_"
        "fOplLLmL4buaw4xjm1zqzKtHHpwQUQCWVAyZF9BQ3-yi6ssf-4HYBr-"
        "8bvwbxHR8HbAgAdC8meAjkV8Z15V0BF3cnC8hkjbq-OlAAzgFORL6nNpQy_"
        "CXp6LgPknInubBECxMU6ybRk-_MI1jqy6Ko-rTHYbAC0bmZiM3VwILDEQDLnT-"
        "3EcMfELaYHmRTH7I8LKHbQxDbSOw-ydKA";
    std::string badJwt =
        "eyJmbmciOiJSUzI1NiIsImprdSI6Imh0dHBzOi8vZmFhc21hdHRwcm92LmV1czIuYXR0ZX"
        "N0LmF6dXJlLm5ldC9jZXJ0cyIsImtpZCI6IkowcEFQZGZYWEhxV1dpbWdySDg1M3dNSWRo"
        "NS9mTGUxejZ1U1hZUFhDYTA9IiwidHlwIjoiSldUIn0."
        "eyJleHAiOjE3MjgwOTAxMTMsImlhdCI6MTcyODA2MTMxMywiaXMtZGVidWdnYWJsZSI6dH"
        "J1ZSwiaXNzIjoiaHR0cHM6Ly9mYWFzbWF0dHByb3YuZXVzMi5hdHRlc3QuYXp1cmUubmV0"
        "IiwianRpIjoiNmQyNWIyMjNlMmJhMTFkNmExMWY4NWE2Y2RiYzE1NzcwNjE2ODJkMDczM2"
        "NmNGM2NWZiYjU4ZWJlODg4YTMzOSIsIm1hYS1hdHRlc3RhdGlvbmNvbGxhdGVyYWwiOnsi"
        "cWVpZGNlcnRzaGFzaCI6ImE2NGQ2NDkxOTg1MDdkOGI1N2UzM2Y2M2FiMjY2ODM4ZjQzZj"
        "MyN2JkNGFhY2M3ODUxMGI2OTc2ZWQwNDZlMTAiLCJxZWlkY3JsaGFzaCI6ImFkZmExOTQy"
        "NDIwZTY5ZGY1MTE4ZmYwMDZiNTNhZTFlNWRmZDkxZTVhNTcxMjQyOTczMTI2Yjg2MGFkNW"
        "ViMTMiLCJxZWlkaGFzaCI6Ijc3MDFmNjQ3MDBiN2Y1MDVkN2I0YjdhOTNlNDVkNWNkZThj"
        "ZmM4NjViNjBmMWRkNDllY2JlZTk3OTBjMzM3MmUiLCJxdW90ZWhhc2giOiI0NDNmN2JmY2"
        "QxN2U0YjI3NmQ1ODI1Nzk0MTJiZmE2YjNjMWI5YTU2N2FlZjE1YmE1ZDJiNDdiZTRhMGVl"
        "OWVhIiwidGNiaW5mb2NlcnRzaGFzaCI6ImE2NGQ2NDkxOTg1MDdkOGI1N2UzM2Y2M2FiMj"
        "Y2ODM4ZjQzZjMyN2JkNGFhY2M3ODUxMGI2OTc2ZWQwNDZlMTAiLCJ0Y2JpbmZvY3JsaGFz"
        "aCI6ImFkZmExOTQyNDIwZTY5ZGY1MTE4ZmYwMDZiNTNhZTFlNWRmZDkxZTVhNTcxMjQyOT"
        "czMTI2Yjg2MGFkNWViMTMiLCJ0Y2JpbmZvaGFzaCI6IjY4NjRjNjg3NGMyZWYzNmJjOTJl"
        "NTg3ZTAwOTMwYmYzZWEwYmM0ODYyZDA2YjBmYmU2YWY4NjMyN2UwNGMzNTcifSwibmJmIj"
        "oxNzI4MDYxMzEzLCJwcm9kdWN0LWlkIjowLCJzZ3gtbXJlbmNsYXZlIjoiNjUwNmIzYmI2"
        "NmFlMTQ0MWYyYzIwODZlMjM0MGYzNzY2M2YyZDU4ZmJhYTViZDYwMWE3MTFiMDRiNDk3ZT"
        "E0NSIsInNneC1tcnNpZ25lciI6IjgzZDcxOWU3N2RlYWNhMTQ3MGY2YmFmNjJhNGQ3NzQz"
        "MDNjODk5ZGI2OTAyMGY5YzcwZWUxZGZjMDhjN2NlOWUiLCJzdm4iOjAsInRlZSI6InNneC"
        "IsIngtbXMtYXR0ZXN0YXRpb24tdHlwZSI6InNneCIsIngtbXMtcG9saWN5Ijp7ImlzLWRl"
        "YnVnZ2FibGUiOnRydWUsInByb2R1Y3QtaWQiOjAsInNneC1tcmVuY2xhdmUiOiI2NTA2Yj"
        "NiYjY2YWUxNDQxZjJjMjA4NmUyMzQwZjM3NjYzZjJkNThmYmFhNWJkNjAxYTcxMWIwNGI0"
        "OTdlMTQ1Iiwic2d4LW1yc2lnbmVyIjoiODNkNzE5ZTc3ZGVhY2ExNDcwZjZiYWY2MmE0ZD"
        "c3NDMwM2M4OTlkYjY5MDIwZjljNzBlZTFkZmMwOGM3Y2U5ZSIsInN2biI6MCwidGVlIjoi"
        "c2d4In0sIngtbXMtcG9saWN5LWhhc2giOiJPd0V2cFNWRVdBNWVpc0NFbmNCdDhOU1pGTF"
        "lEUktvTGFvT05Qclpnb2VZIiwieC1tcy1zZ3gtY29sbGF0ZXJhbCI6eyJxZWlkY2VydHNo"
        "YXNoIjoiYTY0ZDY0OTE5ODUwN2Q4YjU3ZTMzZjYzYWIyNjY4MzhmNDNmMzI3YmQ0YWFjYz"
        "c4NTEwYjY5NzZlZDA0NmUxMCIsInFlaWRjcmxoYXNoIjoiYWRmYTE5NDI0MjBlNjlkZjUx"
        "MThmZjAwNmI1M2FlMWU1ZGZkOTFlNWE1NzEyNDI5NzMxMjZiODYwYWQ1ZWIxMyIsInFlaW"
        "RoYXNoIjoiNzcwMWY2NDcwMGI3ZjUwNWQ3YjRiN2E5M2U0NWQ1Y2RlOGNmYzg2NWI2MGYx"
        "ZGQ0OWVjYmVlOTc5MGMzMzcyZSIsInF1b3RlaGFzaCI6IjQ0M2Y3YmZjZDE3ZTRiMjc2ZD"
        "U4MjU3OTQxMmJmYTZiM2MxYjlhNTY3YWVmMTViYTVkMmI0N2JlNGEwZWU5ZWEiLCJ0Y2Jp"
        "bmZvY2VydHNoYXNoIjoiYTY0ZDY0OTE5ODUwN2Q4YjU3ZTMzZjYzYWIyNjY4MzhmNDNmMz"
        "I3YmQ0YWFjYzc4NTEwYjY5NzZlZDA0NmUxMCIsInRjYmluZm9jcmxoYXNoIjoiYWRmYTE5"
        "NDI0MjBlNjlkZjUxMThmZjAwNmI1M2FlMWU1ZGZkOTFlNWE1NzEyNDI5NzMxMjZiODYwYW"
        "Q1ZWIxMyIsInRjYmluZm9oYXNoIjoiNjg2NGM2ODc0YzJlZjM2YmM5MmU1ODdlMDA5MzBi"
        "ZjNlYTBiYzQ4NjJkMDZiMGZiZTZhZjg2MzI3ZTA0YzM1NyJ9LCJ4LW1zLXNneC1pcy1kZW"
        "J1Z2dhYmxlIjp0cnVlLCJ4LW1zLXNneC1tcmVuY2xhdmUiOiI2NTA2YjNiYjY2YWUxNDQx"
        "ZjJjMjA4NmUyMzQwZjM3NjYzZjJkNThmYmFhNWJkNjAxYTcxMWIwNGI0OTdlMTQ1IiwieC"
        "1tcy1zZ3gtbXJzaWduZXIiOiI4M2Q3MTllNzdkZWFjYTE0NzBmNmJhZjYyYTRkNzc0MzAz"
        "Yzg5OWRiNjkwMjBmOWM3MGVlMWRmYzA4YzdjZTllIiwieC1tcy1zZ3gtcHJvZHVjdC1pZC"
        "I6MCwieC1tcy1zZ3gtcmVwb3J0LWRhdGEiOiI1MmM0YmJjZWViNTkxMjRkNTg0NzQzZTc1"
        "MGQ0NmNhN2FiOTU2YzlkZDAzMmU4ODcyYjM3MjcwNWZhOWRlNGUzYTliZTVkZGVkNzM0Yz"
        "g1Nzg1NDM0NTNiOWE5OGFjYjQxOTUxNDYzYjUxZGUzNjIzYzRiNjc5NWM1MjYyZmE1MyIs"
        "IngtbXMtc2d4LXN2biI6MCwieC1tcy1zZ3gtdGNiaWRlbnRpZmllciI6IjEwIiwieC1tcy"
        "12ZXIiOiIxLjAifQ.2MHmljiFFxQzlU3qLHoEGx2wcyvXXOyLUdaMzekYiuG2ZiEh4H-"
        "g1PI-TymWpdUFkT-0a2zw06tdP0IOWmbvqF-"
        "uSta3wlINN1LmsBapZiLBwxYH2otTvr1z9oy1iRMhe44x_"
        "fOplLLmL4buaw4xjm1zqzKtHHpwQUQCWVAyZF9BQ3-yi6ssf-4HYBr-"
        "8bvwbxHR8HbAgAdC8meAjkV8Z15V0BF3cnC8hkjbq-OlAAzgFORL6nNpQy_"
        "CXp6LgPknInubBECxMU6ybRk-_MI1jqy6Ko-rTHYbAC0bmZiM3VwILDEQDLnT-"
        "3EcMfELaYHmRTH7I8LKHbQxDbSOw-ydKA";

    if (verify_jwt(goodJwt.c_str())) {
        std::cout << "Verified!" << std::endl;
    } else {
        std::cerr << "Not verified :-(" << std::endl;
    }

    if (verify_jwt(badJwt.c_str())) {
        std::cout << "Verified!" << std::endl;
    } else {
        std::cerr << "Not verified :-(" << std::endl;
    }

    std::string expJku = "https://faasmattprov.eus2.attest.azure.net/certs";
    if (check_property(goodJwt.c_str(), "jku", expJku)) {
        std::cout << "Has property!" << std::endl;
    }

    /*
    if (!check_property(goodJwt.c_str(), "jku",
    "https://lolz.eus2.attest.azure.net/certs")) { std::cout << "Has not got
    property :-(" << std::endl;
    }
    */

    return 0;
}
