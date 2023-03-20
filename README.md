# BIBIFI
Create a encrypted filesystem

## How to run
### Initlialize fileserver on first run
Run the fileserver and provide the admin name in the argument

`./fileserver <admin_name>`

### Run fileserver
Put your private key file uder the level as `main`. Run the fileserver and provide the keyfile in the argument

`./fileserver <keyfile_name>`

***Note: Keyfile name format must be in `<username>_priv`.***

## Commands
| Command | Description | Note |
| --- | --- | --- |
| `cd <directory>` | Traverse to target path | |
| `ls` | Display files and folders in current directory. | It supports listing files on current directory only. |
| `pwd` | Display current path. | |
| `cat <filename>` | Display file content in current directory. | It does not support read file outside of current directory. |
| `share <filename> <username>` | Share a file to target user. File will be created under target user's `/shared` folder. | It does not support read file outside of current directory. |
| `mkdir <directory_name>` | Create a directory in current directory. | It does not support creating a new directory outside of current directory. |
| `mkfile <filename> <contents>` | Create a new file and write content into it under current directory. | It does not support creating file outside of current directory.|
| `adduser <username>` | Create user in filesystem and return `<username>_priv` under `private_keys` folder | Admin privilege is required. |
| `exit` | exit program | |
