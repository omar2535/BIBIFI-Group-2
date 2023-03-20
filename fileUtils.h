#ifndef FILEUTILS_H
#define FILEUTILS_H
#include <vector>
#include <string>
#include <map>
#include <vector>
#include <sstream>
#include <iostream>
#include <algorithm> 
#include <filesystem>
#include "crypto_funcs.h"
#include "stringUtils.h"

const std::string METADATA_LOC = "filesystem/metadata/";
std::string adminName;

// return relativePath starts with filesystem/
std::filesystem::path getRelativePath(std::filesystem::path& absolutePath, int startIndex)
{
    return absolutePath.generic_string().substr(startIndex);
}

/*
Check path boundary. If a child path is under the root path, it is under the boundary. False otherwise.
*/
bool checkPathBoundary(const std::filesystem::path &root, const std::filesystem::path &child)
{
    //TODO..
    auto const canonicalRootPath = std::filesystem::canonical(root);
    auto const canonicalChildPath = std::filesystem::canonical(child);
    
    auto itr = std::search(canonicalChildPath.begin(), canonicalChildPath.end(), 
                           canonicalRootPath.begin(), canonicalRootPath.end());
    
    return itr == canonicalChildPath.begin();
}

//check if string is a valid filename
bool isValidFilename(const std::string &str) 
{
    if (str.empty()) 
        return false; 
    for (const char c : str) 
    {
        if (!isalnum(c) && c != '_' && c != '-' && c != '.' && c != '=')
        return false;
    }
    return true;
}

std::string convertPath(std::string pathstr, std::string username, bool isenc) {
    std::string res = "";
    std::vector<std::string> strs = split(pathstr, '/');
    try {
        for(int i = 0; i < strs.size(); i++) {
            if(isenc)
                strs[i] = encrypt_b64(strs[i], username).substr(0, 12);
            else
                res;// = get_decrypted_path from metadata
        }
    }
    catch (const std::exception& e) {
        std::cout << "Exception in filename encrypt/decrypt: " << e.what() << " Terminating." << std::endl;
        exit(1);
    }
    res = joinStrings(strs, "/");
    return res;
}

//encrypt file name. If it is encrypted before, it returns the previous ciphertext
std::string encryptFilename(const std::string &filename, const std::string &username)
{
    //search for existing mapping
    std::ifstream ifile(METADATA_LOC + "fileNameMapping.txt");

    if (!ifile.is_open()) {
        std::cerr << "Error: could not open fileNameMapping " << std::endl;
        return NULL;
    }

    std::string line;
    while (std::getline(ifile, line)) {
        std::istringstream iss(line);
        std::string usernameCol, plaintextNameCol, ciphertextNameCol;

        if (std::getline(iss, usernameCol, ',') && std::getline(iss, plaintextNameCol, ',') && std::getline(iss, ciphertextNameCol, ',')) {
            if (usernameCol == username && plaintextNameCol == filename) {
                return ciphertextNameCol;
            }
        }
    }

    //encrypt new plaintextname 
    std::string cipherName = encrypt_b64(filename, username).substr(0, 12);     //TODO: we should use a separate key (i.e. "filesystem") to encrypt file name
    //cipherName = filename;           //Uncomment this line to turn off filename encryption

    std::ofstream ofile;
    ofile.open(METADATA_LOC + "fileNameMapping.txt", std::ios_base::app);

    if (!ofile.is_open()) {
        std::cerr << "Error: could not open file fileNameMapping.txt for appending" << std::endl;
        return NULL;
    }

    ofile << username << "," << filename << "," << cipherName << std::endl;
    ofile.close();

    return cipherName;
}

std::string decryptFilename(const std::string &cipher, const std::string &username)
{
    std::ifstream file(METADATA_LOC + "fileNameMapping.txt");

    if (!file.is_open()) {
        std::cerr << "Error: could not open fileNameMapping " << std::endl;
        return "";
    }

    std::string line;
    while (std::getline(file, line)) {
        std::istringstream iss(line);
        std::string usernameCol, plaintextNameCol, ciphertextNameCol;

        if (std::getline(iss, usernameCol, ',') && std::getline(iss, plaintextNameCol, ',') && std::getline(iss, ciphertextNameCol, ',')) {
            if (usernameCol == username && ciphertextNameCol == cipher) {
                return plaintextNameCol;
            }
        }
    }

    return "";
}

/*
Determine which user own the current path:
    If the path is /sysetm/path/here/filesystem, 
        the function will return 'admin'
    If the path is /sysetm/path/here/filesystem/UEFH8FNVMD/...., 
        the function will return 'decryptFilename(UEFH8FNVMD, "admin") which is the user who owns the folder' 
*/
std::string userOfPath(const std::string path){
    // get the owner of the path
    auto pathTokens = split(path,"filesystem/");
    if(pathTokens.size() == 1){ //the path ends with 'filesystem', only admin can reach this folder
        return adminName;
    }
    auto pathTokensInFilesystem = split(pathTokens[1],'/');
    std::string userCipher = pathTokensInFilesystem[0];
    return decryptFilename(userCipher, adminName);
}

std::string extractFilename(const std::string &path) {
    std::string filename = split(path,'/').back();
    return filename;
}

#endif // FILEUTILS_H