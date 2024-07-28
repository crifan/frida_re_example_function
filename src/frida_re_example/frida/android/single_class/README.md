# 单个类

去用Frida去hook调试Java单个类的写法举例：

对于jadx反编译出的抖音的源码：

* `sources/X/C660690Pru.java`

```java
package X;
...

/* renamed from: X.0Pru, reason: invalid class name and case insensitive filesystem */
/* loaded from: classes9.dex */
public class C660690Pru extends TransmitThread {
    public int LIZ;
    public final /* synthetic */ AbstractC660680Prt LIZIZ;
...
    @Override // com.ss.android.ugc.bytex.async.stack.delegate.TransmitThread, com.ss.android.ugc.bytex.pthread.base.proxy.PthreadThreadV2, java.lang.Thread, java.lang.Runnable
    /*
        Code decompiled incorrectly, please refer to instructions dump.
    */
    public void run() {
...
    }

    public final void LIZ() {
...
    }

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public C660690Pru(AbstractC660680Prt abstractC660680Prt) {
        super("DeviceRegisterThread");
        this.LIZIZ = abstractC660680Prt;
    }

...

    private boolean LIZ(JSONObject jSONObject) {
...
    }

    private boolean LIZ(String str, JSONObject jSONObject) {
...
    }

}
```

想要去打印出，当前类的所有函数和属性，可以用如下（核心）代码：

* hook_douyin.js

```js
  /******************** X.C660690Pru ********************/
  var X0PruClassName = "X.0Pru"
  printClassAllMethodsFields(X0PruClassName)

  var X0PruCls = Java.use(X0PruClassName)
  console.log("X0PruCls=" + X0PruCls)
```

* 说明
  * 关于被hook的类名
    * 注意此处jadx是反编译失败，注释
      * `/* renamed from: X.0Pru`
    * 中的`X.0Pru`，才是真正的类名
    * 而不是，此处被改名后的：`public class C660690Pru extends TransmitThread`中的`C660690Pru`
  * 关于工具类函数：`printClassAllMethodsFields`
    * 详见：[函数和属性](../../../../frida_tool_func/android/java_common/func_property.md)

* 调用=调试运行

```bash
frida -U -f com.ss.android.ugc.aweme -l hook_douyin.js
```

* 输出

```bash
==========Class: X.0Pru ==========
-----All Properties-----
use getDeclaredFields
public int X.0Pru.LIZ
public final X.0Prt X.0Pru.LIZIZ
-----All Methods-----
use getDeclaredMethods
private boolean X.0Pru.LIZ(java.lang.String,org.json.JSONObject)
private boolean X.0Pru.LIZ(org.json.JSONObject)
public final void X.0Pru.LIZ()
public void X.0Pru.run()

X0PruCls=<class: X.0Pru>
```
