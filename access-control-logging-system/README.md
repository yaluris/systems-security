In the test_aclog.c file, we execute the functions fopen and fwrite (that we have overwritten in logger.c) 
under various conditions, to fill up the file_logging.log file.

In the logger.c file, we re-declare the fopen and fwrite functions, so that every time they are called, 
they register the necessary information for the file access to the log file. These versions of fopen and 
fwrite were used to overwrite their standard declarations, using LD_preload. 

In the acmonitor.c, we have developed an Access Control Log Monitoring tool that loads the log file and 
can either print all users that tried to access more than 7 different files without having permissions 
(malicious users), or print a table with the number of times each user has modified a given file.

Program execution example:
make clean  
make all  
make run  
./acmonitor -m  
./acmonitor -i file_0
