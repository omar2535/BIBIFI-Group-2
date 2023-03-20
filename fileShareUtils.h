#ifndef FILESHAREUTILS_H
#define FILESHAREUTILS_H

#include <sstream>
#include <iostream>
#include <fstream>
#include <map>
#include <vector>
#include "stringUtils.h"
#include "fileUtils.h"

void addFileShareMapping(const std::string &sender,
                         const std::string &filename,
                         const std::string &receiver)
{
    std::ifstream ifile(METADATA_LOC + "fileShareMapping.txt");
    if (!ifile.is_open())
    {
        std::cerr << "Error: could not open fileShareMapping" << std::endl;
    }

    std::string line;
    while (std::getline(ifile, line))
    {
        std::istringstream iss(line);
        std::string senderCol, filenameCol, receiverCol;
        if (std::getline(iss, senderCol, ',') && std::getline(iss, filenameCol, ',') && std::getline(iss, receiverCol, ','))
        {
            if (sender == senderCol && filename == filenameCol && receiver == receiverCol)
            {
                return;
            }
        }
    }

    std::ofstream ofile;
    ofile.open(METADATA_LOC + "fileShareMapping.txt", std::ios_base::app);
    if (!ofile.is_open())
    {
        std::cerr << "Error: could not open fileShareMapping" << std::endl;
        return;
    }

    ofile << sender << "," << filename << "," << receiver << std::endl;
    ofile.close();

    return;
}

std::vector<std::string> getReceivers(const std::string &sender, const std::string &filename)
{
    std::vector<std::string> receivers;

    std::ifstream ifile(METADATA_LOC + "fileShareMapping.txt");
    if (!ifile.is_open())
    {
        std::cerr << "Error: could not open fileShareMapping" << std::endl;
        return receivers;
    }

    std::string line;
    while (std::getline(ifile, line))
    {
        std::istringstream iss(line);
        std::string senderCol, filenameCol, receiverCol;
        if (std::getline(iss, senderCol, ',') && std::getline(iss, filenameCol, ',') && std::getline(iss, receiverCol, ','))
        {
            if (sender == senderCol && filename == filenameCol)
            {
                receivers.push_back(receiverCol);
            }
        }
    }

    return receivers;
}



#endif // FILESHAREUTILS_H