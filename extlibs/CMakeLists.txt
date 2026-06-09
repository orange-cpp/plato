set(KSOCKET_SOURCE_DIR "${CMAKE_CURRENT_SOURCE_DIR}/ksocket/src/ksocket")

wdk_add_library(ksocket STATIC
        "${KSOCKET_SOURCE_DIR}/berkeley.c"
        "${KSOCKET_SOURCE_DIR}/ksocket.c"
)

target_include_directories(ksocket PUBLIC
        "${CMAKE_CURRENT_SOURCE_DIR}/ksocket/src"
)

target_link_libraries(ksocket PUBLIC WDK::NETIO)
