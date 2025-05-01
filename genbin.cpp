#include <iostream>
#include <fstream>
#include <cstdlib>  // для rand() и srand()
#include <ctime>    // для time()

void generateBinaryFile(const std::string& filename, size_t n) {
    // Открываем файл в бинарном режиме для записи
    std::ofstream outFile(filename, std::ios::binary);
    if (!outFile) {
        std::cerr << "Ошибка открытия файла для записи!" << std::endl;
        return;
    }

    // Инициализация генератора случайных чисел
    std::srand(std::time(nullptr));

    // Записываем n случайных байт в файл
    for (size_t i = 0; i < n; ++i) {
        char randomByte = static_cast<char>(std::rand() % 256);
        outFile.write(&randomByte, sizeof(randomByte));
    }

    // Закрываем файл
    outFile.close();

    std::cout << "Файл " << filename << " успешно создан и заполнен " << n << " байтами." << std::endl;
}

int main() {
    std::string filename = "data.bin";
    size_t n = 32;  // Размер файла в байтах
    // size_t n = 1048576;  // Размер файла в байтах 1 мб
    // size_t n = 10485760;  // Размер файла в байтах 10 мб

    generateBinaryFile(filename, n);

    return 0;
}