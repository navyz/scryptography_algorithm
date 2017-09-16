#ifndef MY_EXCEPTION_H
#define MY_EXCEPTION_H

#include <exception>
#include <string>

class not_implemented_exception: public std::exception
{
public:
  virtual const char* what() const throw() // my call to the std exception class function (doesn't nessasarily have to be virtual).
  {
  return "You can't divide by zero! Error code number 0, restarting the calculator..."; // my error message
  }

  void noZero();

};  //<-this is just a lazy way to create an object

struct logic_exception : public std::exception
{
   std::string s;
   logic_exception(std::string ss) : s(ss) {}
   ~logic_exception() throw () {} // Updated
   const char* what() const throw() { return s.c_str(); }
};

#endif
