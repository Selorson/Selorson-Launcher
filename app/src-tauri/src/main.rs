// Chặn cửa sổ dòng lệnh đen trên Windows ở bản Release
#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

fn main() {
    selorson_launcher_lib::run();
}
