SOURCE_C_FILE += $(shell find . -name "*.c")
SOURCE_CPP_FILE += $(shell find . -name "*.cpp")

TARGET_PATH += .
COMPILE_OPTION := -fPIC -shared -fvisibility=hidden -Wno-deprecated -Wno-parentheses
INCLUDE_PATH :=
MACRO := -D_REENTRANT -DDECLSPEC_DLL_EXPORT

#MYSQL_INCLUDE := -I/opt/homebrew/include/
#MYSQL_LINK := -L/opt/homebrew/lib/ -lmysqlclient
MYSQL_LINK := -L/usr/lib64/mysql -lmysqlclient
ifdef MYSQL_LINK
INCLUDE_PATH += $(MYSQL_INCLUDE)
MACRO += -DDB_ENABLE_MYSQL
endif

LINK := -pthread $(MYSQL_LINK)

COMPILER := gcc
ifeq ($(COMPILER), gcc)
SOURCE_CPP_FILE :=
endif

DEBUG_TARGET := $(TARGET_PATH)/libDBApiDynamicDebug.so
RELEASE_TARGET := $(TARGET_PATH)/libDBApiDynamic.so

all:

debug:
	$(COMPILER) $(MACRO) -D_DEBUG -g $(COMPILE_OPTION) $(INCLUDE_PATH) $(SOURCE_C_FILE) $(SOURCE_CPP_FILE) -o $(DEBUG_TARGET) $(LINK)

release:
	$(COMPILER) $(MACRO) -DNDEBUG -O1 $(COMPILE_OPTION) $(INCLUDE_PATH) $(SOURCE_C_FILE) $(SOURCE_CPP_FILE) -o $(RELEASE_TARGET) $(LINK)
