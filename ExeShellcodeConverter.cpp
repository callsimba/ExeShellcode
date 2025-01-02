#include <iostream>
#include <fstream>
#include <vector>
#include <cstring>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <zlib.h>
#include <stdexcept>
#include <iomanip>
#include <cstdint>

const std::string MAGIC_HEADER = "EXE2SC";
const std::string AES_KEY = "super_secret_key_1234567890123456";
const size_t IV_SIZE = 16;

struct Metadata {
    char magicHeader[6];
    uint8_t encryptFlag;
    uint8_t compressFlag;
    uint8_t obfuscateFlag;
    uint64_t originalSize;
    unsigned char iv[IV_SIZE];
};

std::vector<unsigned char> ReadFile(const std::string &path);
void WriteFile(const std::string &path, const std::vector<unsigned char> &data);
void WriteMetadata(std::ofstream &outFile, const Metadata &meta);
Metadata ReadMetadata(std::ifstream &inFile);
void CompressData(std::vector<unsigned char> &data);
void DecompressData(std::vector<unsigned char> &data, uint64_t originalSize);
void ObfuscateData(std::vector<unsigned char> &data);
void DeobfuscateData(std::vector<unsigned char> &data);
void EncryptAES256(std::vector<unsigned char> &data, const std::string &key, std::vector<unsigned char> &iv);
void DecryptAES256(std::vector<unsigned char> &data, const std::string &key, const unsigned char *iv);
void GeneratePowerShellArray(const std::string &outputPath, const std::vector<unsigned char> &data);

void ConvertExeToShellcode(const std::string &exePath, const std::string &outputPath, bool encrypt, bool compress, bool obfuscate, bool outputAsPowerShell);
void ConvertShellcodeToExe(const std::string &shellcodePath, const std::string &outputExePath);

int main(int argc, char *argv[]) {
    if (argc < 4) {
        std::cerr << "Usage:\n";
        std::cerr << "  Convert EXE to Shellcode: ./ExeShellcodeConverter -e2s input.exe shellcode.bin -encrypt -compress -obfuscate -format=ps\n";
        std::cerr << "  Convert Shellcode to EXE: ./ExeShellcodeConverter -s2e shellcode.bin output.exe\n";
        return 1;
    }

    try {
        std::string mode = argv[1];
        std::string inputPath = argv[2];
        std::string outputPath = argv[3];

        bool encrypt = (argc >= 5 && std::string(argv[4]) == "-encrypt");
        bool compress = (argc >= 6 && std::string(argv[5]) == "-compress");
        bool obfuscate = (argc >= 7 && std::string(argv[6]) == "-obfuscate");
        bool outputAsPowerShell = (argc >= 8 && std::string(argv[7]) == "-format=ps");

        if (mode == "-e2s") {
            ConvertExeToShellcode(inputPath, outputPath, encrypt, compress, obfuscate, outputAsPowerShell);
        } else if (mode == "-s2e") {
            ConvertShellcodeToExe(inputPath, outputPath);
        } else {
            throw std::runtime_error("Invalid mode specified.");
        }
    } catch (const std::exception &e) {
        std::cerr << "Error: " << e.what() << "\n";
        return 1;
    }

    return 0;
}
