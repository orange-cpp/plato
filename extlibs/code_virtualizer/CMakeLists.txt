add_library(cv-sdk INTERFACE include/VirtualizerSDK.h)

target_include_directories(cv-sdk INTERFACE include)
target_link_directories(cv-sdk INTERFACE lib)
target_link_libraries(cv-sdk INTERFACE VirtualizerDDK)