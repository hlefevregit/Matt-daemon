NAME		= MattDaemon

CXX			= c++
CXXFLAGS	= -Wall -Wextra -Werror -std=c++11

INCLUDES	= -I include

SRC_DIR		= src
SRCS		= $(SRC_DIR)/main.cpp \
			  $(SRC_DIR)/Tintin_reporter.cpp \
			  $(SRC_DIR)/Matt_daemon.cpp \
			  $(SRC_DIR)/Signal_handler.cpp \
			  $(SRC_DIR)/Server.cpp

OBJS		= $(SRCS:.cpp=.o)

all: $(NAME)

$(NAME): $(OBJS)
	$(CXX) $(CXXFLAGS) $(OBJS) -o $(NAME)

%.o: %.cpp
	$(CXX) $(CXXFLAGS) $(INCLUDES) -c $< -o $@

clean:
	rm -f $(OBJS)

fclean: clean
	rm -f $(NAME)

re: fclean all

.PHONY: all clean fclean re