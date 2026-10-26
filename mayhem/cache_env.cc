// Points the library's fixed-base table cache at the one build.sh pre-generated; building the 255 MB
// table at fuzzer start takes 100+ s under ASan. Only sets the variable if the caller did not.
#include <cstdlib>
__attribute__((constructor)) static void mayhem_cache_env() {
    setenv("XDG_CACHE_HOME", "/mayhem/mayhem/build-fuzz/xdg", 0);
}
