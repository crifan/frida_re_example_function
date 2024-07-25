# Frida逆向实例和工具函数

* 最新版本：`v1.2.3`
* 更新时间：`20240725`

## 简介

整理Frida逆向期间涉及到的各种实际案例，以及整理出的各种工具类函数。其中Frida的实际使用案例，包括网上别人的实例案例，包括官网的Cdeshare，以及frida和frida-trace。frida中包括iOS的ObjC的各种例子。包括Object对象的methods和ownMethods，以及用Interceptor去hook函数的，单个类的单个函数、单个类的所有函数、所有类的所有函数等。以及ApiResolver的案例以及Stalker的案例，尤其是___lldb_unnamed_symbol2575$$akd的完整代码；接着是frida-trace的实际例子，包括ObjC的akd中Apple账号验证过程、Preferences中Apple账号登录全过程的详细内容。

## 源码+浏览+下载

本书的各种源码、在线浏览地址、多种格式文件下载如下：

### HonKit源码

* [crifan/frida_re_example_function: Frida逆向实例和工具函数](https://github.com/crifan/frida_re_example_function)

#### 如何使用此HonKit源码去生成发布为电子书

详见：[crifan/honkit_template: demo how to use crifan honkit template and demo](https://github.com/crifan/honkit_template)

### 在线浏览

* [Frida逆向实例和工具函数 book.crifan.org](https://book.crifan.org/books/frida_re_example_function/website/)
* [Frida逆向实例和工具函数 crifan.github.io](https://crifan.github.io/frida_re_example_function/website/)

### 离线下载阅读

* [Frida逆向实例和工具函数 PDF](https://book.crifan.org/books/frida_re_example_function/pdf/frida_re_example_function.pdf)
* [Frida逆向实例和工具函数 ePub](https://book.crifan.org/books/frida_re_example_function/epub/frida_re_example_function.epub)
* [Frida逆向实例和工具函数 Mobi](https://book.crifan.org/books/frida_re_example_function/mobi/frida_re_example_function.mobi)

## 版权和用途说明

此电子书教程的全部内容，如无特别说明，均为本人原创。其中部分内容参考自网络，均已备注了出处。如发现有侵权，请通过邮箱联系我 `admin 艾特 crifan.com`，我会尽快删除。谢谢合作。

各种技术类教程，仅作为学习和研究使用。请勿用于任何非法用途。如有非法用途，均与本人无关。

## 鸣谢

感谢我的老婆**陈雪**的包容理解和悉心照料，才使得我`crifan`有更多精力去专注技术专研和整理归纳出这些电子书和技术教程，特此鸣谢。

## 其他

### 作者的其他电子书

本人`crifan`还写了其他`150+`本电子书教程，感兴趣可移步至：

[crifan/crifan_ebook_readme: Crifan的电子书的使用说明](https://github.com/crifan/crifan_ebook_readme)

### 关于作者

关于作者更多介绍，详见：

[关于CrifanLi李茂 – 在路上](https://www.crifan.org/about/)
