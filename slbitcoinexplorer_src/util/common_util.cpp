#include <vector>
#include <string>
#include <sstream>
#include <fstream>

#include <boost/filesystem.hpp>

#include "common_util.h"

using namespace std;


void Split(const string &s, char delim, vector<string> &elems)
{
    stringstream ss(s);
    string item;
    while (getline(ss, item, delim))
    {
        elems.push_back(item);
    }
}

vector<string> Split(const string &s, char delim)
{
    vector<string> elems;
    Split(s, delim, elems);
    return elems;
}


bool IsFilesEqual(const std::string& lFilePath, const std::string& rFilePath)
{
    int BUFFER_SIZE = 1024;
    std::ifstream lFile(lFilePath.c_str(), std::ifstream::in | std::ifstream::binary);
    std::ifstream rFile(rFilePath.c_str(), std::ifstream::in | std::ifstream::binary);

    if(!lFile.is_open() || !rFile.is_open())
    {
        return false;
    }

    char *lBuffer = new char[BUFFER_SIZE]();
    char *rBuffer = new char[BUFFER_SIZE]();

    do
    {
        lFile.read(lBuffer, BUFFER_SIZE);
        rFile.read(rBuffer, BUFFER_SIZE);

        if (std::memcmp(lBuffer, rBuffer, BUFFER_SIZE) != 0)
        {
            delete[] lBuffer;
            delete[] rBuffer;
            return false;
        }
    }
    while (lFile.good() || rFile.good());

    delete[] lBuffer;
    delete[] rBuffer;
    return true;
}


bool CreateFolderIfNotExists(std::string dir_path)
{
    boost::filesystem::path dir(dir_path);
    return boost::filesystem::create_directory(dir);
}


std::string BreakLine(const std::string &data, uint32_t charPerLine)
{
    if (charPerLine <= 0)
        return data;

    std::stringstream ss;

    size_t writeSize = 0;
    size_t chunk = charPerLine;
    while (writeSize < data.size())
    {
        if (writeSize + chunk > data.size())
            chunk = data.size() - writeSize;

        ss.write(data.c_str() + writeSize, chunk);

        if (writeSize + chunk < data.size())
            ss << std::endl;

        writeSize += chunk;
    }
    return ss.str();
}

bool WriteFile(const std::string &fileName, const std::string &content)
{
    std::ofstream f;
    f.open(fileName);
    if (f.is_open())
    {
        f.write(content.c_str(), content.size());
        f.close();
        return true;
    }
    return false;
}
