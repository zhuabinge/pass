TEMPLATE = app
CONFIG += console
CONFIG -= app_bundle
CONFIG -= qt

SOURCES += \
    spoofer_linux/spo_linux.c \
    spoofer_system/spo_system.c \
    spoofer_kernel/spo_kernel.c \
    spoofer_sniffer/spo_sniffer.c \
    spoofer_sender/spo_sender.c \
    spoofer_pool/spo_pool.c \
    spoofer_config/spo_config.c \
    spoofer_test/spo_test.c \
    spoofer_log/spo_log.c \
    spoofer_linux/spo_file/spo_file.c \
    spoofer_linux/spo_ipc/spo_msg.c \
    spoofer_linux/spo_ipc/spo_signal.c \
    spoofer_sniffer/spo_hp_spoofer.c \
    spoofer_sniffer/spo_dns_spoofer.c \
    spoofer_system/spo_verification.c

OTHER_FILES += \
    spoofer_system/readme.txt \
    spoofer_sniffer/readme.txt \
    spoofer_sender/readme.txt \
    spoofer_pool/readme.txt \
    spoofer_linux/readme.txt \
    spoofer_kernel/readme.txt \
    spoofer_config/readme.txt

HEADERS += \
    spoofer_config/spo_config.h \
    spoofer_kernel/spo_kernel.h \
    spoofer_linux/spo_linux.h \
    spoofer_pool/spo_pool.h \
    spoofer_sender/spo_sender.h \
    spoofer_sniffer/spo_sniffer.h \
    spoofer_system/spo_system.h \
    spoofer_system/spoofer.h \
    spoofer_log/spo_log.h \
    spoofer_test/spo_test.h \
    spoofer_sniffer/spo_spoofer.h \
    spoofer_system/spo_verification.h

unix|win32: LIBS += -lpfring -lpthread -lpcap -lrt -lnuma -lnet -lcrypto -lpcre
