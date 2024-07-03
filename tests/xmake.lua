

for _, file in ipairs(os.files("test_*.cpp")) do
     local name = path.basename(file)
     target(name)
        set_kind("binary")
        set_languages("c++20")
    
        set_default(false)
        add_files(name .. ".cpp")
        add_files("../src/" ..  string.gsub(name, "^test_", "") ..".cpp")
        add_files(name .. ".rc")
        add_tests("default")
        add_includedirs("../include")
        add_packages("catch2", "fmt")
         
end