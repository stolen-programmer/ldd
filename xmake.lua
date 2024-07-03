
add_rules("mode.debug", "mode.release")

add_requires("catch2", {system=false})
add_requires("iconvpp", {system=false, debug=true})
add_requires("fmt", {system=false , debug=true})

includes("tests")