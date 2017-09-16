#ifndef SL_COMMON_UTIL_H
#define SL_COMMON_UTIL_H

#include <vector>
#include <string>
#include <sstream>
#include <fstream>


using namespace std;


void Split(const string &s, char delim, vector<string> &elems);
vector<string> Split(const string &s, char delim);
bool IsFilesEqual(const std::string& lFilePath, const std::string& rFilePath);
bool CreateFolderIfNotExists(std::string folderName);
std::string BreakLine(const std::string &data, uint32_t charPerLine);
bool WriteFile(const std::string &fileName, const std::string &content);

#endif // SL_COMMON_UTIL_H
