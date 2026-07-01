/*
 * 占位头文件：Android NDK (bionic libc) 不提供 <libintl.h>。
 *
 * arachsys/libelf（从 elfutils 剥离）默认开启 gettext 国际化支持
 * (ENABLE_NLS)，src/eu-config.h 会 #include <libintl.h>。我们不需要
 * 多语言翻译功能，这里提供一份"什么都不做"的替代实现：所有 gettext
 * 系列函数直接把传入的字符串原样返回，行为等价于 GNU gettext.h 在
 * ENABLE_NLS 未定义时的标准回退路径（见 GNU gettext 手册 "lib/gettext.h"
 * 一节）。
 *
 * 通过在交叉编译时把这个文件所在目录加入 -I 搜索路径（且排在 NDK
 * sysroot 之前）实现覆盖，不修改 arachsys/libelf 的任何源文件，
 * 也不依赖对其内部 config.h 具体写法的假设——不管它是否真的检查了
 * ENABLE_NLS 宏，只要它 #include <libintl.h>，就会找到这份实现。
 */
#ifndef ANDROID_NDK_LIBINTL_SHIM_H
#define ANDROID_NDK_LIBINTL_SHIM_H

#include <locale.h>

#ifdef __cplusplus
extern "C" {
#endif

static inline char *gettext(const char *msgid) {
    return (char *)msgid;
}

static inline char *dgettext(const char *domainname, const char *msgid) {
    (void)domainname;
    return (char *)msgid;
}

static inline char *dcgettext(const char *domainname, const char *msgid, int category) {
    (void)domainname;
    (void)category;
    return (char *)msgid;
}

static inline char *ngettext(const char *msgid1, const char *msgid2, unsigned long int n) {
    return (char *)(n == 1 ? msgid1 : msgid2);
}

static inline char *dngettext(const char *domainname, const char *msgid1,
                               const char *msgid2, unsigned long int n) {
    (void)domainname;
    return (char *)(n == 1 ? msgid1 : msgid2);
}

static inline char *dcngettext(const char *domainname, const char *msgid1,
                                const char *msgid2, unsigned long int n, int category) {
    (void)domainname;
    (void)category;
    return (char *)(n == 1 ? msgid1 : msgid2);
}

static inline char *textdomain(const char *domainname) {
    return (char *)domainname;
}

static inline char *bindtextdomain(const char *domainname, const char *dirname) {
    (void)domainname;
    return (char *)dirname;
}

static inline char *bind_textdomain_codeset(const char *domainname, const char *codeset) {
    (void)domainname;
    return (char *)codeset;
}

#ifdef __cplusplus
}
#endif

#endif /* ANDROID_NDK_LIBINTL_SHIM_H */
