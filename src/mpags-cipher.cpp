#include "CipherFactory.hpp"
#include "CipherMode.hpp"
#include "CipherType.hpp"
#include "ProcessCommandLine.hpp"
#include "TransformChar.hpp"
#include "VigenereCipher.hpp"
#include <algorithm>
#include <chrono>
#include <fstream>
#include <future>
#include <iostream>
#include <stdexcept>
#include <string>
#include <thread>
#include <vector>

int main(int argc, char* argv[])
{
    // Convert the command-line arguments into a more easily usable form
    const std::vector<std::string> cmdLineArgs{argv, argv + argc};

    // Options that might be set by the command-line arguments
    ProgramSettings settings{false, false, "", "", {}, {}, CipherMode::Encrypt};

    // Process command line arguments
    try {
        processCommandLine(cmdLineArgs, settings);
    } catch (const MissingArgument& e) {
        std::cerr << "[error] Missing argument: " << e.what() << std::endl;
        return 1;
    } catch (const UnknownArgument& e) {
        std::cerr << "[error] Unknown argument: " << e.what() << std::endl;
        return 1;
    }

    // Any failure in the argument processing means we can't continue
    // Use a non-zero return value to indicate failure

    // Handle help, if requested
    if (settings.helpRequested) {
        // Line splitting for readability
        std::cout
            << "Usage: mpags-cipher [-h/--help] [--version] [-i <file>] [-o <file>] [-c <cipher>] [-k <key>] [--encrypt/--decrypt]\n\n"
            << "Encrypts/Decrypts input alphanumeric text using classical ciphers\n\n"
            << "Available options:\n\n"
            << "  -h|--help        Print this help message and exit\n\n"
            << "  --version        Print version information\n\n"
            << "  -i FILE          Read text to be processed from FILE\n"
            << "                   Stdin will be used if not supplied\n\n"
            << "  -o FILE          Write processed text to FILE\n"
            << "                   Stdout will be used if not supplied\n\n"
            << "                   Stdout will be used if not supplied\n\n"
            << "  --multi-cipher N Specify the number of ciphers to be used in sequence\n"
            << "                   N should be a positive integer - defaults to 1"
            << "  -c CIPHER        Specify the cipher to be used to perform the encryption/decryption\n"
            << "                   CIPHER can be caesar, playfair, or vigenere - caesar is the default\n\n"
            << "  -k KEY           Specify the cipher KEY\n"
            << "                   A null key, i.e. no encryption, is used if not supplied\n\n"
            << "  --encrypt        Will use the cipher to encrypt the input text (default behaviour)\n\n"
            << "  --decrypt        Will use the cipher to decrypt the input text\n\n"
            << std::endl;
        // Help requires no further action, so return from main
        // with 0 used to indicate success
        return 0;
    }

    // Handle version, if requested
    // Like help, requires no further action,
    // so return from main with zero to indicate success
    if (settings.versionRequested) {
        std::cout << "0.5.0" << std::endl;
        return 0;
    }

    // Initialise variables
    char inputChar{'x'};
    std::string cipherText;

    // Read in user input from stdin/file
    if (!settings.inputFile.empty()) {
        // Open the file and check that we can read from it
        std::ifstream inputStream{settings.inputFile};
        if (!inputStream.good()) {
            std::cerr << "[error] failed to create istream on file '"
                      << settings.inputFile << "'" << std::endl;
            return 1;
        }

        // Loop over each character from the file
        while (inputStream >> inputChar) {
            cipherText += transformChar(inputChar);
        }

    } else {
        // Loop over each character from user input
        // (until Return then CTRL-D (EOF) pressed)
        while (std::cin >> inputChar) {
            cipherText += transformChar(inputChar);
        }
    }

    // Request construction of the appropriate cipher(s)
    std::vector<std::unique_ptr<Cipher>> ciphers;
    std::size_t nCiphers{settings.cipherType.size()};
    ciphers.reserve(nCiphers);

    for (std::size_t iCipher{0}; iCipher < nCiphers; ++iCipher) {
        try {
            ciphers.push_back(CipherFactory::makeCipher(
                settings.cipherType[iCipher], settings.cipherKey[iCipher]));

        } catch (const InvalidKey& e) {
            std::cerr << "[error] Invalid Key: " << e.what() << std::endl;
            return 1;
        }

        // Check that the cipher was constructed successfully
        if (!ciphers.back()) {
            std::cerr << "[error] problem constructing requested cipher"
                      << std::endl;
            return 1;
        }
    }

    // If we are decrypting, we need to reverse the order of application of the ciphers
    if (settings.cipherMode == CipherMode::Decrypt) {
        std::reverse(ciphers.begin(), ciphers.end());
    }

    // Run the cipher(s) on the input text, specifying whether to encrypt/decrypt
    for (const auto& cipher : ciphers) {
        if (std::find(settings.cipherType.begin(), settings.cipherType.end(),
                      CipherType::Caesar) != settings.cipherType.end()) {
            // numThreads can be set to any value here
            const std::size_t numThreads{4};

            const std::size_t chunkSize = cipherText.size() / numThreads;

            std::vector<std::future<std::string>> futures;

            for (std::size_t i = 0; i < numThreads; ++i) {
                std::size_t start = i * chunkSize;
                std::size_t end = (i == numThreads - 1) ? cipherText.size()
                                                        : (i + 1) * chunkSize;

                futures.push_back(
                    std::async(std::launch::async, [&ciphers, &cipherText,
                                                    &settings, start, end]() {
                        std::string chunk =
                            cipherText.substr(start, end - start);
                        // Send each chunk of caesar to applyCipher
                        chunk = ciphers.front()->applyCipher(
                            chunk, settings.cipherMode);
                        return chunk;
                    }));
            }
            // Wait for futures to finish using chrono module for timings
            for (auto& future : futures) {
                auto status = future.wait_for(std::chrono::seconds(1));
                while (status != std::future_status::ready) {
                    status = future.wait_for(std::chrono::seconds(2));
                }
            }

            cipherText = "";

            for (auto& future : futures) {
                cipherText += future.get();
            }
        } else {
            // For Vigenere and Playfair
            cipherText = cipher->applyCipher(cipherText, settings.cipherMode);
        }
    }

    // Output the encrypted/decrypted text to stdout/file
    if (!settings.outputFile.empty()) {
        // Open the file and check that we can write to it
        std::ofstream outputStream{settings.outputFile};
        if (!outputStream.good()) {
            std::cerr << "[error] failed to create ostream on file '"
                      << settings.outputFile << "'" << std::endl;
            return 1;
        }

        // Print the encrypted/decrypted text to the file
        outputStream << cipherText << std::endl;

    } else {
        // Print the encrypted/decrypted text to the screen
        std::cout << cipherText << std::endl;
    }

    // No requirement to return from main, but we do so for clarity
    // and for consistency with other functions
    return 0;
}
