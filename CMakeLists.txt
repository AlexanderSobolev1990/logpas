cmake_minimum_required(VERSION 3.7)

project(logpas VERSION 1.0.0)

set(CMAKE_CXX_STANDARD 14)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

if(NOT CMAKE_BUILD_TYPE) # Если не указан тип сборки, собрать в режиме Release
  set(CMAKE_BUILD_TYPE Release)
endif()
message(STATUS "Build mode: ${CMAKE_BUILD_TYPE}")

set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${CMAKE_SOURCE_DIR}/bin/${CMAKE_BUILD_TYPE})

find_package(OpenSSL REQUIRED)
find_package(Boost REQUIRED COMPONENTS program_options)
find_library(SODIUM_LIB sodium REQUIRED)

add_executable(logpas
    src/main.cpp
    src/cli.h
    src/cli.cpp
    src/clipboard.h
    src/clipboard.cpp
    src/crypto.h
    src/crypto.cpp
    src/entry.h
    src/fs.h
    src/fs.cpp
    src/generator.h
    src/generator.cpp
    src/secure_input.h
    src/secure_input.cpp
    src/vault.h
    src/vault.cpp
)

target_include_directories(logpas PRIVATE src)

target_link_libraries(logpas
    OpenSSL::Crypto
    Boost::program_options
    ${SODIUM_LIB}
)

install(TARGETS logpas DESTINATION /usr/local/bin)

set(CPACK_GENERATOR "DEB")
set(CPACK_PACKAGE_NAME "logpas")
set(CPACK_PACKAGE_VERSION ${PROJECT_VERSION})
set(CPACK_DEBIAN_PACKAGE_MAINTAINER "alexandersobolev1990@gmail.com")
set(CPACK_STRIP_FILES ON)
set(CPACK_DEBIAN_PACKAGE_SHLIBDEPS ON)
set(CPACK_DEBIAN_FILE_NAME logpas_v${PROJECT_VERSION}.deb)
include(CPack)