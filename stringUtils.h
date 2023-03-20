#ifndef STRINGUTILS_H
#define STRINGUTILS_H

#include <vector>
#include <string>
#include <map>
#include <vector>
#include <sstream>
#include <iostream>


//split a string
std::vector<std::string> split(const std::string &s, char delim) 
{
    std::vector<std::string> elems;
    std::stringstream ss;
    ss.str(s);
    std::string item;
    while (std::getline(ss, item, delim)) 
    {
        if(!item.empty())
        {
            elems.push_back(item);
        }
    }
    return elems;
}

std::vector<std::string> split(const std::string &input, const std::string &delim) 
{
    std::vector<std::string> elems;
    std::string s = input;

    size_t pos = 0;
    std::string token;
    while ((pos = s.find(delim)) != std::string::npos) {
        token = s.substr(0, pos);
        elems.push_back(token);
        s.erase(0, pos + delim.length());
    }
    if(!s.empty())
        elems.push_back(s);
    return elems;
}

std::string strip(std::string str) {
    int start = str.find_first_not_of(" \t\r\f\v");
    if (start == std::string::npos) {
        return "";
    }
    int end = str.find_last_not_of(" \t\r\f\v");
    return str.substr(start, end - start + 1);
}

// join strings
std::string joinStrings(std::vector<std::string> strings, std::string delim) {
  std::string result = "";
  int sz = strings.size();
  for (int i = 0; i < sz; i++) {
    result += strings[i];
    if (i != sz - 1) {  // last element
      result += delim;
    }
  }
  return result;
}

#endif // STRINGUTILS_H