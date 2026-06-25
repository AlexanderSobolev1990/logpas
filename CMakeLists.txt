cmake_minimum_required(VERSION 3.7)

project(logpas VERSION 1.2.3)

include(GNUInstallDirs)

set(CMAKE_CXX_STANDARD 14)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

if(NOT CMAKE_BUILD_TYPE) # Если не указан тип сборки, собрать в режиме Release
  set(CMAKE_BUILD_TYPE Release)
endif()
message(STATUS "Build mode: ${CMAKE_BUILD_TYPE}")

set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${CMAKE_SOURCE_DIR}/bin/${CMAKE_BUILD_TYPE})

find_package(OpenSSL REQUIRED)
find_package(Boost REQUIRED COMPONENTS program_options)
find_package(Threads REQUIRED)

find_path(SODIUM_INCLUDE_DIR sodium.h)
find_library(SODIUM_LIB NAMES sodium)

if(NOT SODIUM_INCLUDE_DIR OR NOT SODIUM_LIB)
    message(FATAL_ERROR "libsodium development files were not found")
endif()

add_executable(logpas
    src/main.cpp
    src/cli.hpp
    src/cli.cpp
    src/clipboard.hpp
    src/clipboard.cpp
    src/crypto.hpp
    src/crypto.cpp
    src/entry.hpp
    src/fs.hpp
    src/fs.cpp
    src/generator.hpp
    src/generator.cpp
    src/secure_input.hpp
    src/secure_input.cpp
    src/secure_memory.hpp
    src/vault.hpp
    src/vault.cpp
)

target_include_directories(logpas PRIVATE src)
target_include_directories(logpas PRIVATE ${SODIUM_INCLUDE_DIR})

target_compile_definitions(logpas PRIVATE
    BOOST_BIND_GLOBAL_PLACEHOLDERS
    LOGPAS_VERSION="${PROJECT_VERSION}"
)

if(TARGET OpenSSL::Crypto)
    set(LOGPAS_OPENSSL_CRYPTO OpenSSL::Crypto)
else()
    set(LOGPAS_OPENSSL_CRYPTO ${OPENSSL_CRYPTO_LIBRARY})
endif()

if(TARGET Boost::program_options)
    set(LOGPAS_BOOST_PROGRAM_OPTIONS Boost::program_options)
else()
    target_include_directories(logpas PRIVATE ${Boost_INCLUDE_DIRS})
    set(LOGPAS_BOOST_PROGRAM_OPTIONS ${Boost_PROGRAM_OPTIONS_LIBRARY})
endif()

target_link_libraries(logpas PRIVATE
    Threads::Threads
    ${LOGPAS_OPENSSL_CRYPTO}
    ${LOGPAS_BOOST_PROGRAM_OPTIONS}
    ${SODIUM_LIB}
)

install(TARGETS logpas DESTINATION ${CMAKE_INSTALL_BINDIR})

set(CPACK_GENERATOR "DEB")
set(CPACK_PACKAGE_NAME "logpas")
set(CPACK_PACKAGE_VERSION ${PROJECT_VERSION})
set(CPACK_DEBIAN_PACKAGE_MAINTAINER "alexandersobolev1990@gmail.com")
set(CPACK_DEBIAN_PACKAGE_DEPENDS "xclip | xsel | wl-clipboard")
set(CPACK_STRIP_FILES ON)
set(CPACK_DEBIAN_PACKAGE_SHLIBDEPS ON)
set(CPACK_DEBIAN_FILE_NAME logpas_v${PROJECT_VERSION}.deb)
set(CPACK_PACKAGING_INSTALL_PREFIX "/usr")
include(CPack)
