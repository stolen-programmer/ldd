
add_rules("mode.debug", "mode.release")

add_requires("catch2", {system=false})
add_requires("iconvpp", {system=false, debug=true})
add_requires("spdlog", {system=false , debug=true})

target("main")
    add_files("src/main.cpp")
    

includes("tests")