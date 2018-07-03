
#编译debug或者release
DEBUG = 0
    
#越狱iPhone的ip地址
# 需要添加到环境变量中才能生效,命令： "export THEOS_DEVICE_IP=192.168.8.220"
#THEOS_DEVICE_IP = 192.168.1.122
THEOS_DEVICE_IP = 192.168.2.2
 
#指定支持的处理器架构
ARCHS = arm64
 
#指定需要的SDK版本iphone:Base SDK:Deployment Target
#最新的SDK，程序发布在iOS8.0以上
TARGET = iphone:latest:8.0
	

include /opt/theos/makefiles/common.mk

TWEAK_NAME = DeletePrace
DeletePrace_FILES = Tweak.xm ./fishhook/fishhook.c

include $(THEOS_MAKE_PATH)/tweak.mk


#make clean
clean::
	rm -rf ./packages/*


after-install::
	install.exec "killall -9 AttachDemo"
