#include <iostream>
#include <filesystem>
#include <fstream>
#include <string>
#include <map>
#include <vector>
#include <sstream>
#include "fileUtils.h"
#include "fileShareUtils.h"
 
#define FILENAME_MAX_LEN 20
#define USERNAME_MAX_LEN 20


/*** constants ***/
// Serve for stripping / display purpose
const std::filesystem::path REAL_ROOT_PATH = std::filesystem::current_path();
const auto REAL_ROOT_PATH_LENGTH = REAL_ROOT_PATH.generic_string().length();


// current path
auto currentPath = std::filesystem::current_path() / "filesystem/";
// init() should update it to user root directory
auto userRootPath = std::filesystem::current_path() / "filesystem/";

// how many char to hide for current path
unsigned long currentPathPrefixLength = currentPath.generic_string().length();

bool isAdmin = false;
std::string currentUser;
std::string userPublicKey;
std::string userPrivateKey;


/* 
login

Check user keyfile. Update paths and global variables
*/
void login(const std::string& path)
{
    std::string teststr = "123";
    std::string processed = "";
    // check if provided keyfile name follow constraint
    if(path.length() <= 5 or path.compare(path.length() - 5, 5, "_priv"))
    {
        std::cout << "keyfile name should be: <user>_priv" << std::endl;
        exit(1);
    }
    std::string username = path.substr(0, path.length() - 5);
    if(std::filesystem::exists(pub_key_loc + username + "_pub")) // if user key file exists
    {
        try {  // key vefification     
            processed = decrypt(encrypt(teststr, username), path);
        }
        catch (const std::exception& e) {
            std::cout << "Exception in encrypt/decrypt: " << e.what() << " Terminating." << std::endl;
            exit(1);
        }
        if(processed == teststr)
        {
            currentUser = username;
            // read admin metadata file to decide if current user is admin
            std::ifstream admin_keyfile(METADATA_LOC + "admin.txt");
            admin_keyfile >> adminName;
            admin_keyfile.close();
            std::cout << "Login as: " << username << std::endl;

            if(adminName == username)
            {
                isAdmin = true;
                std::cout << "You have admin privilege" << std::endl;
            }
            else
            {
                //Non user move to user home directory
                std::string userHomeDir = encryptFilename(username, adminName);
                
                currentPath = currentPath / userHomeDir;
                userRootPath = currentPath;

                currentPathPrefixLength = currentPath.generic_string().length();
            }
        }
        else
        {
            std::cout << "Login failed" << std::endl;
            exit(1);
        }
    }
    else
    {
        std::cout << "User not exist" << std::endl;
        exit(1);
    }
}

/**** File system functions ****/
/*
cd

Traverse to target directory with given path
*/
void cd(const std::string& toDirectory)
{
    std::string workingPath = toDirectory;
    std::filesystem::path tmpPath;

    //handle the case of path starts with "/"
    if (workingPath.rfind("/", 0) == 0 ){
        workingPath = workingPath.substr(1, workingPath.length() -1);
        tmpPath = userRootPath;
    }else{
        tmpPath = currentPath;
    }

    auto folderTokens = split(workingPath, "/");
    for (std::vector<std::string>::iterator it = folderTokens.begin() ; it != folderTokens.end(); ++it) {

        std::string token = *it;
        std::string dirName;
        std::string username = userOfPath(tmpPath);

        if(token == ""){  // path with multiple '/' is considered as single '/' with empty folder in between. Therefore it does nothing
            continue;
        }else if(token != ".." && token != "."){
            dirName = encryptFilename(token, username);
        }else{
            dirName = token;
        }

        std::filesystem::path newPath;

        try{
            newPath = std::filesystem::canonical(tmpPath / dirName);
        }catch(const std::exception& ex){
            std::cout << "Invalid path" << std::endl;
            return;
        }

        if(!checkPathBoundary(userRootPath, newPath)) {
            std::cout << "Directory " << toDirectory << " is overbound" << std::endl;
            return;
        }
        if(!std::filesystem::exists(newPath)) {
            std::cout << "Directory " << toDirectory << " doesn't exist" << std::endl;
            return;
        }
        if(!std::filesystem::is_directory(newPath)) {
            std::cout << "Target path " << toDirectory << " is not a directory" << std::endl;
            return;
        }

        tmpPath = newPath;
    }

    currentPath = tmpPath / "";      //currentPath always ends with "/"
}

/* 
pwd

print current path
*/
void pwd()
{
    std::cout << "/";
    if(currentPath != userRootPath) {
        // remove path before filesystem
        auto pathTokens = (isAdmin) 
                            ? split(currentPath,"filesystem") 
                            : split(currentPath,"filesystem/" + encryptFilename(currentUser, adminName));
        std::string pathToBePrinted = pathTokens[1];

        std::string userOfFolder = userOfPath(currentPath);

        // tokenize path, decrypt and print it
        auto pathToBePrintedTokens = split(pathToBePrinted, '/');
        for (std::vector<std::string>::iterator it = pathToBePrintedTokens.begin() ; it != pathToBePrintedTokens.end(); ++it) {
            if(isAdmin && it ==  pathToBePrintedTokens.begin()){  //Assume the folder in admin's root is user folder, those names are encrypted with admin
                std::cout << decryptFilename(*it, adminName) + "/";  
            }else{
                std::cout << decryptFilename(*it, userOfFolder) + "/";
            }
        }
    }
    
    std::cout << std::endl;
}

/* 
ls

list all files and folders on current path
*/
void ls()
{
    std::cout << "d -> ." << std::endl;

    if(currentPath != userRootPath) {
        std::cout << "d -> .." << std::endl;
    }

    for (const auto& entry : std::filesystem::directory_iterator(currentPath))
    {
        std::string user = userOfPath(currentPath);
        std::string filename = entry.path().filename();
        std::string orgName = decryptFilename(filename, user);
        if(!orgName.empty())
            std::cout << (entry.is_directory() ? "d" : "f") << " -> " << orgName << std::endl;
        else
            std::cout << "\033[1;31m(unencrypted)\033[0m" << (entry.is_directory() ? "d" : "f") << " -> " << filename << std::endl;
    }
}

/* 
cat

show a file content
*/
void cat(const std::string& filename)
{

    // get the current paths and append on filename
    auto pathTokens = split(currentPath,"filesystem/");
    // decide which key to use for decryption. 
    auto decryptKeyName = decryptFilename(split(pathTokens[1],'/')[0], adminName);
    std::string finalPath = "filesystem/" + pathTokens[1] + "/" + encryptFilename(filename, userOfPath(currentPath));      //TODO: pass file owner to encryptFilename
    std::ifstream file(finalPath);
    if (file.is_open())
    {
        try {
            std::stringstream buffer;
            file >> buffer.rdbuf();
            std::cout << decryptByMetadataPrivateKey(buffer.str(), decryptKeyName) << std::endl;
        }
        catch (const std::exception& e) {
            std::cout << "cat failed. Exception in decrypt: " << e.what() << std::endl;
        }
        file.close();
    }
    else
    {
        std::cout << filename << " doesn't exist" << std::endl;
    }
}

/* 
share

share a file to target user
*/
void share(const std::string& filename, const std::string& username)
{

    auto pathTokens = split(currentPath, "filesystem/");
    if(pathTokens.size() < 2) {  // can't share file under filesystem or user dir
        std::cout << "Can't share file here" << std::endl;
        return;
    }
    auto relpath = split(pathTokens[1],'/');
    auto user = decryptFilename(relpath[0], adminName);
    if(user.empty()) {
        std::cout << "Unexpected path" << std::endl;
        return;
    }
    if(relpath.size() < 2) {
        std::cout << "Can't share file here" << std::endl;
        return;
    }
    auto folderName = decryptFilename(relpath[1], user);
    if(folderName.empty() || folderName == "shared") {
        std::cout << "Can't share file here" << std::endl;
        return;
    }

    auto full_source_path = currentPath / encryptFilename(filename, userOfPath(currentPath));                           //TODO: pass correct user name to encryptFilename()

    // validate if full_source_path exists
    if (!std::filesystem::exists(full_source_path) || std::filesystem::is_directory(full_source_path))
    {
        std::cout << "File " << filename << " doesn't exist." << std::endl;
        return;
    }
    
    // validate if username exists
    if (!std::filesystem::exists(REAL_ROOT_PATH / "filesystem" / encryptFilename(username, adminName)))   //TODO: pass correct user name to encryptFilename()
    {
        std::cout << "User " << username << " doesn't exist." << std::endl;
        return;
    }

    // try to read in the decrypt file
    std::ifstream source_file(full_source_path.generic_string());
    if (!source_file.is_open()) {
        std::cerr << "Failed to open file: " << filename << std::endl;
        return;
    }
    std::stringstream buffer;
    buffer << source_file.rdbuf();
    std::string content = buffer.str();

    auto currentUser = userOfPath(currentPath);
    auto plaintext = decryptByMetadataPrivateKey(content, currentUser);
    auto cyphertext = encrypt(plaintext, username);

    auto full_target_path = REAL_ROOT_PATH / "filesystem" / encryptFilename(username, adminName) / encryptFilename("shared", username) / encryptFilename(currentUser + "_" + filename, username);        //TODO: pass correct user name to encryptFilename()

    // write cyphertext to destination
    std::ofstream file(full_target_path.generic_string());
    std::ofstream ofs(full_target_path.generic_string(), std::ios::trunc);
    ofs << cyphertext;

    // update fileShareMapping
    addFileShareMapping(userOfPath(currentPath), getRelativePath(full_source_path, currentPathPrefixLength + 1), username);
}

/* 
mkdir

Create a directory on current folder
*/
void mkdir(const std::string& dirname)
{
    auto pathTokens = split(currentPath, "filesystem/");
    if(pathTokens.size() < 2) {  // can't create directly under filesystem or user dir
        std::cout << "Can't create dir here" << std::endl;
        return;
    }
    auto relpath = split(pathTokens[1],'/');
    auto user = decryptFilename(relpath[0], adminName);
    if(user.empty()) {
        std::cout << "Unexpected path" << std::endl;
        return;
    }
    if(relpath.size() < 2) {
        std::cout << "Can't create dir here" << std::endl;
        return;
    }
    auto share = decryptFilename(relpath[1], user);
    if(share.empty() or share == "shared") {
        std::cout << "Can't create dir here" << std::endl;
        return;
    }

    std::string dirname_enc, user_enc, share_enc;
    try {
        dirname_enc = encryptFilename(dirname, user);
    }
    catch (const std::exception& e) {
        std::cout << "mkdir failed. Exception in encrypt: " << e.what() << std::endl;
        return;
    }

    if(std::filesystem::exists(currentPath / dirname_enc)) {
        std::cout << "Name already exists" << std::endl; 
    } else {
        try {
            auto new_dir = currentPath / dirname_enc;
            std::filesystem::create_directory(new_dir);
        }
        catch (const std::exception& e) {
            std::cout << "mkdir failed. Exception: " << e.what() << std::endl;
            return;
        }
    }
}

/* 
mkfile

Create a file in current folder and write contents to the new file
*/
void mkfile(const std::string& filename, std::string contents)
{
    auto pathTokens = split(currentPath, "filesystem/");
    if(pathTokens.size() < 2) {  // can't create directly under filesystem or user dir
        std::cout << "Can't create file here" << std::endl;
        return;
    }
    auto relpath = split(pathTokens[1],'/');
    auto user = decryptFilename(relpath[0], adminName);  // to do: add null handling
    if(user.empty()) {
        std::cout << "Unexpected path" << std::endl;
        return;
    }
    if(relpath.size() < 2) {
        std::cout << "Can't create file here" << std::endl;
        return;
    }
    auto folderName = decryptFilename(relpath[1], user);
    if(folderName.empty() || folderName == "shared") {
        std::cout << "Can't create file here" << std::endl;
        return;
    }

    std::string filename_enc, user_enc, share_enc;
    try {
        filename_enc = encryptFilename(filename, user);
        //user_enc = encryptFilename(currentUser, currentUser),
        share_enc = encryptFilename("shared", user);
        contents = encrypt(contents, user);
    }
    catch (const std::exception& e) {
        std::cout << "mkfile failed. Exception in encrypt: " << e.what() << std::endl;
        return;
    }

    if(std::filesystem::is_directory(currentPath / filename_enc)) {
        std::cout << "Name already exists" << std::endl; 
        return;
    }
    std::ofstream file(currentPath / filename_enc, std::ofstream::trunc);
    if (file.is_open()) {        
        file << contents;
        file.close();
        
        //get receivers and reshare
        std::filesystem::path new_dir = currentPath / filename_enc;
        std::vector<std::string> receivers;
        if (isAdmin) {
            receivers = getReceivers(userOfPath(currentPath), getRelativePath(new_dir, encryptFilename(userOfPath(currentPath), adminName).length() + currentPathPrefixLength + 1));
        } else {
            receivers = getReceivers(userOfPath(currentPath), getRelativePath(new_dir, currentPathPrefixLength + 1));
        }
        for (auto receiver : receivers) {
            share(filename, receiver);
        }
        
        std::cout << "Successfully created file" << std::endl;
    } else {
        std::cout << "Failed to create file" << std::endl;
    }
}

/**** Privilege functions ****/
/* 
adduser

Add a user to the filesystem. 
If user is succesfully created, generate new user's keyfile under private_keys folder.

** Admin privilege is required.
*/
void adduser(const std::string& username, bool addAdmin = false)
{
    if(!isAdmin && !addAdmin)
        std::cout << "Log in as admin to use admin functions" << std::endl;
    //if(users.find(username) != users.end())
    else if(std::filesystem::exists(pub_key_loc + username + "_pub"))
    {
        std::cout << "User " << username << " already exists" << std::endl;
    }
    else
    {
        std::string uname_enc, personal_enc, shared_enc;
        create_keys(username);   

        try {
            uname_enc = encryptFilename(username, adminName);
            personal_enc = encryptFilename("personal", username);
            shared_enc = encryptFilename("shared", username);
        }
        catch (const std::exception& e) {
            std::cout << "Adduser Failed. Exception in encrypt: " << e.what() << std::endl;
            if(!addAdmin) {
                std::filesystem::remove(priv_key_loc + username + "_priv");
                std::filesystem::remove(pub_key_loc + username + "_pub");
            }
            return;
        }

        //create a keyfile called username_keyfile on the host
        auto user_dir_full = REAL_ROOT_PATH / "filesystem" / uname_enc / personal_enc;
        auto share_dir_full = REAL_ROOT_PATH / "filesystem" / uname_enc / shared_enc;
        if(!std::filesystem::exists(user_dir_full))
            std::filesystem::create_directories(user_dir_full);
        if(!std::filesystem::exists(share_dir_full))
            std::filesystem::create_directories(share_dir_full);
        std::cout << "Added user: " << username << std::endl;
    }
}

/**** UI function ****/
/* 
prompt

Display current user name and current directory. Wait for user to enter command.
*/
void prompt()
{
    //TODO...
    std::string cmd;
    int numargs;
    while(1)
    {
        std::cout << "Enter your command:> ";
        std::getline(std::cin, cmd);
        cmd = strip(cmd);
        if(cmd == "")
        {
            ;
        }
        else if(cmd == "exit") 
        {
            exit(1);
        }
        else if(cmd == "pwd")
        {
            pwd();
        }
        else if(cmd == "ls")
        {
            ls();
        }
        else
        {
            std::vector<std::string> args = split(cmd, ' ');
            numargs = args.size();
            if(numargs <= 1 || numargs > 3)
                std::cout << "invalid command or argument" << std::endl;
            else if(args[0] == "cat")
            {
                if(numargs != 2)
                    std::cout << "command only takes 1 argument" << std::endl;
                else if(!isValidFilename(args[1]))
                    std::cout << "invalid filename" << std::endl;
                else
                    cat(args[1]);
            }
            else if(args[0] == "cd")
            {
                if(numargs != 2)
                    std::cout << "command only takes 1 argument" << std::endl;
                else
                    cd(args[1]);
            }
            else if(args[0] == "share")
            {
                if(numargs != 3)
                    std::cout << "command takes 2 arguments" << std::endl;
                else if(!isValidFilename(args[1]) || !isValidFilename(args[2]))
                    std::cout << "invalid filename" << std::endl;
                else
                    share(args[1], args[2]);
            }
            else if(args[0] == "mkdir")
            {
                if(numargs != 2)
                    std::cout << "command only takes 1 argument" << std::endl;
                else if(!isValidFilename(args[1]) || args[1].length() > FILENAME_MAX_LEN)
                    std::cout << "invalid path" << std::endl; 
                else
                    mkdir(args[1]);
            }
            else if(args[0] == "mkfile")
            {
                if(numargs != 3)
                    std::cout << "command takes 2 arguments" << std::endl;
                else if(!isValidFilename(args[1]) || args[1].length() > FILENAME_MAX_LEN)
                    std::cout << "invalid filename" << std::endl; 
                else
                    mkfile(args[1], args[2]);
            }
            else if(args[0] == "adduser")
            {
                if(numargs != 2)
                    std::cout << "command only takes 1 argument" << std::endl;
                else if(!isValidFilename(args[1]) || args[1].length() > FILENAME_MAX_LEN)
                    std::cout << "invalid username" << std::endl; 
                else
                {
                    adduser(args[1]);
                }
            }
            else
            {
                std::cout << "invalid command" << std::endl;
            }
        }
    }
}

/* 
initSystemFolder

Initalize filesystem by 
creating a `filesystem` folder, admin's keyfile and metadata folders
*/
void initSystemFolder(const std::string &adminName)
{
    if(!std::filesystem::exists("filesystem"))  // create directory if not exist
        std::filesystem::create_directory("filesystem");
    if(!std::filesystem::exists(METADATA_LOC))
        std::filesystem::create_directory(METADATA_LOC);
    if(!std::filesystem::exists(priv_key_loc))
        std::filesystem::create_directory(priv_key_loc);
    if(!std::filesystem::exists(pub_key_loc))
        std::filesystem::create_directory(pub_key_loc);

    std::ofstream fileShareMappingFile(METADATA_LOC + "fileShareMapping.txt");
    fileShareMappingFile.close();
    std::ofstream fileNameMappingFile(METADATA_LOC + "fileNameMapping.txt");
    fileNameMappingFile.close();
    std::ofstream file(METADATA_LOC + "admin.txt");  // write admin user name to admin metadata file
    if (file.is_open())
    {
        file << adminName;
        file.close();
        isAdmin = true;
        currentUser = adminName;
        std::cout << "Successfully created admin user" << std::endl;
    } else
    {
        std::cout << "Failed to create admin user" << std::endl;
        exit(1);
    }
}

/* 
main
*/
int main(int argc, char* argv[])
{
    std::string info = "Encrypted Filsystem:\n\nAvailable Commands:\ncd <dir>\nls\npwd\nmkfile <file> <contents> \
    \nmkdir <dir>\ncat <file>\nshare <file> <user>\nexit\n\nAdmin can also use:\nadduser <user>\n\nFilename/username constraints: \
    \nMax 20 characters. Can only contain 'A-Z','a-z','0-9','-','_','.','='.\nFile contents max length: 470 bytes.\n\n";
    std::cout << info << std::endl;
    if(argc != 2 || !isValidFilename(argv[1]) || std::string(argv[1]).length() > FILENAME_MAX_LEN + 4)
    {
        std::cout << "Bad argument. Start failed." << std::endl;
        exit(1);
    }
    std::string name_arg = argv[1];
    //check if filesystem folder exists. If it does, retrieve existing user key for login. Otherwise, init `filesystem` folder
    if (std::filesystem::exists(METADATA_LOC + "admin.txt")) {
        login(name_arg);
    } else {
        adminName = name_arg;
        initSystemFolder(name_arg);
        adduser(name_arg, true);
        //create_keys(keyfileName);
    }
    
    prompt();

    return 0;
}
