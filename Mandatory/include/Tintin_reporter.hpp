#ifndef TINTIN_REPORTER_HPP
# define TINTIN_REPORTER_HPP

# include "includes.hpp"

class Tintin_reporter
{
    public :
        enum LogType
        {
            INFO,
            ERROR,
            LOG
        };

        Tintin_reporter( const std::string &logFilePath );
        ~Tintin_reporter();

        void    log( LogType type, const std::string &message );
        void    info( const std::string &message );
        void    error( const std::string &message );
        void    userLog( const std::string &message );

    private :
        std::ofstream   _ofs;
        std::mutex      _mutex;

        std::string getTimestamp() const;
        std::string typeToString( LogType type ) const;

        Tintin_reporter( const Tintin_reporter& );
        Tintin_reporter&    operator=( const Tintin_reporter& );
};

#endif