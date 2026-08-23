cmake_minimum_required(VERSION 3.16)
project(SkySecretVault C)

set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED ON)
set(CMAKE_C_EXTENSIONS OFF)

find_package(OpenSSL REQUIRED COMPONENTS Crypto)

add_compile_options(-Wall -Wextra -Wpedantic -Werror -Wconversion -Wshadow -Wformat=2)

add_library(skyvault STATIC
    src/crypto.c
    src/audit.c
    src/vault.c
)
target_include_directories(skyvault PUBLIC src)
target_link_libraries(skyvault PUBLIC OpenSSL::Crypto)

target_compile_definitions(skyvault PRIVATE _POSIX_C_SOURCE=200809L)

add_executable(sky-secret-vault src/main.c)
target_link_libraries(sky-secret-vault PRIVATE skyvault)

include(CTest)
if(BUILD_TESTING)
    add_executable(test_vault tests/test_main.c)
    target_link_libraries(test_vault PRIVATE skyvault)
    add_test(NAME vault_unit COMMAND test_vault)
endif()
