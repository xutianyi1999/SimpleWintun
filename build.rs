fn main() {
    cc::Build::new()
        .cpp(true)
        .include("src/cpp")
        .file("src/cpp/simple_wintun.cpp")
        .compile("SimpleWintunAPI");
}