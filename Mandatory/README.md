# Matt_daemon

## CREATION PROCESS

### Tintin_reporter class :

This class is responsible of registering logs

So it's constructor will receive the logfile as an argument and will open it.

The log member fonction will register the logs in the file.

Ressources :

https://cplusplus.com/reference/fstream/ofstream/

https://cplusplus.com/reference/fstream/ofstream/ofstream/

https://www.youtube.com/watch?v=Rfe2Jb2JP-Y&t=3s

______

https://gabrielstaples.com/cpp-mutexes-and-locks/#gsc.tab=0

______

https://cplusplus.com/reference/sstream/ostringstream/str/

https://www.geeksforgeeks.org/cpp/stdsetbase-stdsetw-stdsetfill-in-cpp/

https://www.w3schools.com/cpp/cpp_date.asp

______

https://stackoverflow.com/questions/57358730/how-to-create-directory-c-using-mkdir

https://stackoverflow.com/questions/66482526/race-condition-stat-and-mkdir

https://docs.fileformat.com/fr/misc/lock/

______

### Matt_daemon class :

This class will check if the programm is launched in root mode,

it will create the needed directories and files,

it will launch the daemon.

The daemon works with a double fork: one to create the process and the second
to ensure that the first process will not be able to take control of any
terminal (so there will not be any risk of receiving unwanted signs for ex).
This second fork + redirecting the logs to a logfile, instead of showing them on 
the terminal are the necessary 

https://www.geeksforgeeks.org/linux-unix/setsid-command-in-linux-with-examples/

https://www.ibm.com/docs/en/zvm/7.4.0?topic=descriptions-setsid-create-session-set-process-group-id

TO GET PROCESS PID AND KILL IT (First daemon tests)

sudo pkill -TERM -x MattDaemon

https://www.tpointtech.com/flock-function-in-cpp

https://man.developpez.com/Archivage-ancien-man-pas-supprimer/man2/flock.2.php

______

### Signal_handler class :

This class will receive and handle the exit signal.

https://en.cppreference.com/w/c/program/sig_atomic_t

http://shtroumbiniouf.free.fr/CoursInfo/Systeme2/TP/CoursSignaux/Volatile.html

https://www.irif.fr/~carton/Enseignement/ObjetsAvances/Cours/simons.pdf

https://en.cppreference.com/w/cpp/utility/program/signal.html

https://pubs.opengroup.org/onlinepubs/007904875/functions/sigaction.html

https://stackoverflow.com/questions/30799296/what-does-signalsigpipe-sig-ign-do

______

### Server class :

https://www.scaler.com/topics/cpp-explicit/

https://en.cppreference.com/w/cpp/language/explicit.html




## TESTING COMMANDS

### To check logs
sudo tail -f /var/log/matt_daemon/matt_daemon.log

### To send messages from another terminal
nc localhost 4242

quit (to stop the deamon from the other terminal)

### To check if th daemon is running
pgrep MattDaemon

pgrep -fl MattDaemon

ps aux | grep MattDaemon

ps aux | grep '[M]attDaemon'

### To give execution rights to details script
chmod +x status.sh start.sh stop.sh restart.sh

### Lock file tests

ls -l /var/lock/matt_daemon.lock

### Kill the process & remove lock file

sudo kill -15 PID

sudo pkill -f MattDaemon

### Kill process with its name

sudo killall -9 process_name


Double fork :
On cherche a avoir un processus qui continue de tourner sans terminal, 
sans session de login associée et sans interaction directe avec 
l’utilisateur : c’est cette combinaison (détachement + fermeture/redirection des I/O + indépendance de la session) qui fait qu’on dit qu’il tourne “en arrière‑plan"

https://stackoverflow.com/questions/31485204/why-fork-twice-while-daemonizing

https://0xjet.github.io/3OHA/2022/04/11/post.html



SIGTERM
SIGKILL