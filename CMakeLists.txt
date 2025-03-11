cmake_minimum_required(VERSION 3.30)


project(plato)


set(CMAKE_CXX_STANDARD 23)
list(APPEND CMAKE_MODULE_PATH "${CMAKE_CURRENT_LIST_DIR}/cmake")
find_package(WDK REQUIRED)

wdk_add_driver(plato KMDF 1.15 source/main.cpp)


add_subdirectory(source)
add_subdirectory(extlibs/code_virtualizer)

target_link_libraries(plato WDK::NETIO cv-sdk)
