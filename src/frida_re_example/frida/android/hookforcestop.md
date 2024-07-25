# hookForceStop

调用：

```bash
frida -U -n system_server -l hook_systemServer.js

frida -U -f com.android.settings -l hook_systemServer.js
```

对应脚本：

* `hook_systemServer.js`

```js
/**
 * Update: 20230920
 * Usage:
 *  frida -U -n system_server -l hook_systemServer.js
 * 
 *  frida -U -f com.android.settings -l hook_systemServer.js
*/

/*******************************************************************************
 * Const & Config
*******************************************************************************/

let CurAppPkgName = "com.wallpaper.hd.funny"

// Enable Not Call Filter
let enableNotCallFilter_Binder_execTransact = false

let enableNotCallFilter_AMS_startService = false
let enableNotCallFilter_AMS_startProcessLocked = false

let enableNotCallFilter_ActiveServices_bringUpServiceLocked = true
// let enableNotCallFilter_ActiveServices_bringUpServiceLocked = false

let enableNotCallFilter_ActiveServices_startServiceLocked = false
let enableNotCallFilter_ActiveServices_startServiceInnerLocked = false

let enableNotCallFilter_ProcessList_startProcessLocked = false
let enableNotCallFilter_ProcessList_handleProcessStartedLocked = false

let enableNotCallFilter_ContentProviderHelper_getContentProviderImpl = true
// let enableNotCallFilter_ContentProviderHelper_getContentProviderImpl = false

// let enableNotCallFilter_BroadcastQueue_processNextBroadcastLocked = false

let enableNotCallFilter_Handler_dispatchMessage = true
// let enableNotCallFilter_Handler_dispatchMessage = false


/*******************************************************************************
 * Common Util
*******************************************************************************/

// convert Object(dict/list/...) to JSON string
function toJsonStr(curObj, singleLine=false, space=2){
  // console.log("toJsonStr: singleLine=" + singleLine)
  // var jsonStr = JSON.stringify(curObj, null, 2)
  var jsonStr = JSON.stringify(curObj, null, space)
  if(singleLine) {
    // jsonStr = jsonStr.replace(/\\n/g, '')
    jsonStr = jsonStr.replace(/\n/g, '')
  }
  return jsonStr
  // return curObj.toString()
}

function describeJavaClass(className) {
  var jClass = Java.use(className);
  console.log(JSON.stringify({
    _name: className,
    _methods: Object.getOwnPropertyNames(jClass.__proto__).filter(m => {
    // _methods: Object.getOwnPropertyDescriptor(jClass.__proto__).filter(m => {
    // _methods: Object.getOwnPropertySymbols(jClass.__proto__).filter(m => {
      return !m.startsWith('$') // filter out Frida related special properties
         || m == 'class' || m == 'constructor' // optional
    }), 
    _fields: jClass.class.getFields().map(f => {
      return f.toString()
    })  
  }, null, 2))
}


// enumerate all methods declared in a Java class
function enumMethods(targetClass)
{
  var hook = Java.use(targetClass);
  var ownMethods = hook.class.getDeclaredMethods();
  console.log("use getDeclaredMethods")

  // var ownMethods = hook.class.getMethods();
  // console.log("use getMethods")

  hook.$dispose;
  return ownMethods;
}

// enumerate all property=field declared in a Java class
function enumProperties(targetClass)
{
  var hook = Java.use(targetClass);
  // var ownMethods = hook.class.getFields();
  // console.log("use getFields")

  var ownFields = hook.class.getDeclaredFields();
  console.log("use getDeclaredFields")

  hook.$dispose;
  return ownFields;
}

// print single java class all Functions=Methods and Fields=Properties
function printClassAllMethodsFields(javaClassName){
  console.log("==========" + "Class: " + javaClassName + " ==========")

  console.log("-----" + "All Properties" + "-----")
  var allProperties = enumProperties(javaClassName)
  allProperties.forEach(function(singleProperty) { 
    console.log(singleProperty)
  })

  console.log("-----" + "All Methods" + "-----")
  // enumerate all methods in a class
  var allMethods = enumMethods(javaClassName)
  allMethods.forEach(function(singleMethod) { 
    console.log(singleMethod)
  })
  console.log("")
}

// generate current stack trace string
function genStackStr(ThrowableCls) {
  let newThrowable = ThrowableCls.$new()
  // console.log("genStackStr: newThrowable=" + newThrowable)
  var stackElements = newThrowable.getStackTrace()
  // console.log("genStackStr: stackElements=" + stackElements)
  var stackStr = "Stack: " + stackElements[0] //method//stackElements[0].getMethodName()
  for (var i = 1; i < stackElements.length; i++) {
    stackStr += "\n    at " + stackElements[i]
  }
  // stackStr = "\n\n" + stackStr
  stackStr = stackStr + "\n"
  // console.log("genStackStr: stackStr=" + stackStr)

  return stackStr
}

// 打印当前调用堆栈信息 print call stack
function PrintStack(ThrowableCls) {
  var stackStr = genStackStr(ThrowableCls)
  console.log(stackStr)

  // let newThrowable = ThrowableCls.$new()
  // let curLog = Java.use("android.util.Log")
  // let stackStr = curLog.getStackTraceString(newThrowable)
  // console.log("stackStr=" + stackStr)
}

// generate Function call string
function genFunctionCallStr(funcName, funcParaDict){
  var logStr = `${funcName}:`
  // var logStr = funcName + ":"
  var isFirst = true

  for(var curParaName in funcParaDict){
    let curParaValue = funcParaDict[curParaName]
    var prevStr = ""
    if (isFirst){
      prevStr = " "
      isFirst = false
    } else {
      prevStr = ", "
    }

    logStr = `${logStr}${prevStr}${curParaName}=` + curParaValue
    // logStr = logStr + prevStr + curParaName + "=" + curParaValue
  }

  return logStr
}

// print Function call and stack trace string
function printFunctionCallAndStack(funcName, funcParaDict, ThrowableCls, filterList=undefined){
  // console.log("filterList=" + filterList)

  var needPrint = true

  var functionCallStr = genFunctionCallStr(funcName, funcParaDict)

  var stackStr = genStackStr(ThrowableCls)

  if (filterList != undefined) {
    needPrint = false

    for (const curFilter of filterList) {
      // console.log("curFilter=" + curFilter)
      if (stackStr.includes(curFilter)) {
        needPrint = true
        // console.log("needPrint=" + needPrint)
        break
      }
    }
  }

  if (needPrint) {
    var functionCallAndStackStr = `${functionCallStr}\n${stackStr}`
    // var functionCallAndStackStr = functionCallStr + "\n" + stackStr
  
    // return functionCallAndStackStr
    console.log(functionCallAndStackStr)  
  }
}

// find loaded classes that match a pattern (async)
function findClass(pattern)
{
	console.log("Finding all classes that match pattern: " + pattern + "\n");

	Java.enumerateLoadedClasses({
		onMatch: function(aClass) {
			if (aClass.match(pattern))
				console.log(aClass)
		},
		onComplete: function() {}
	});
}

/*----------------------------------------
 Android Utils
----------------------------------------*/

function printProcessRecord(curProcessRecord){
  console.log("printProcessRecord: curProcessRecord=" + curProcessRecord)
  console.log("  mService=" + curProcessRecord.mService.value)
  console.log("  mProcLock=" + curProcessRecord.mProcLock.value)
  console.log("  info=" + curProcessRecord.info.value)
  console.log("  processInfo=" + curProcessRecord.processInfo.value)
  console.log("  isolated=" + curProcessRecord.isolated.value)
  console.log("  isSdkSandbox=" + curProcessRecord.isSdkSandbox.value)
  console.log("  appZygote=" + curProcessRecord.appZygote.value)
  console.log("  uid=" + curProcessRecord.uid.value)
  console.log("  userId=" + curProcessRecord.userId.value)
  console.log("  processName=" + curProcessRecord.processName.value)
  console.log("  sdkSandboxClientAppPackage=" + curProcessRecord.sdkSandboxClientAppPackage.value)
  console.log("  sdkSandboxClientAppVolumeUuid=" + curProcessRecord.sdkSandboxClientAppVolumeUuid.value)
}

function getParcelInfo(curParcel){
  var parcelDataSize = curParcel.dataSize()
  var parcelDataCapacity = curParcel.dataCapacity()
  // var parcelDataPosition = curParcel.dataPosition()
  // var parcelInfoStr = "dataSize=" + parcelDataSize + ", dataCapacity=" + parcelDataCapacity + ", dataPositon = " + parcelDataPosition
  var parcelInfoStr = "Parcel: " + curParcel + ", dataSize=" + parcelDataSize + ", dataCapacity=" + parcelDataCapacity
  return parcelInfoStr
}

// try to read Parcel string
function tryReadParcelString(curParcel){
  var parcelDataSize = curParcel.dataSize()
  // console.log("curParcel=" + curParcel + ": parcelDataSize=" + parcelDataSize)
  let StepSize = 4

  var isFoundStr = false
  var strDictList = []

  var curStr = null
  var curStepSize = 0
  // var foundStr = null 
  // var strPos = -1
  var foundStrNum = 0
  for (var curPos = 0; curPos < parcelDataSize; curPos++) {
    curStepSize = StepSize
    curParcel.setDataPosition(curPos)
    curStr = curParcel.readString()
    if (curStr){
      if (curStr === "") {
        // empty string, continue try read other string
      } else {
        isFoundStr = true
        foundStrNum += 1

        // foundStr = curStr
        // strPos = curPos
        // console.log("  [" + curPos + "] string=" + curStr)
        // console.log("  [" + strPos + "] string=" + foundStr)
        var curStrDict = {"str": curStr, "pos": curPos}
        strDictList.push(curStrDict)
        var newPosition = curParcel.dataPosition()
        var posDiff = newPosition - curPos
        curStepSize = posDiff
        // console.log("  [" + foundStrNum + "] strDict=" + toJsonStr(curStrDict, true) + ", pos: " + curPos + " -> " + newPosition +", curStepSize=" + curStepSize)
        // break
      }
    }
    curPos += curStepSize
  }

  // setDataPosition and readString maybe CHANGED position, so need reset position
  curParcel.setDataPosition(0)

  // if(isFoundStr){
  //   // var logStr = toJsonStr(strDictList, true, 1)
  //   var logStr = toJsonStr(strDictList, true, 0)
  //   console.log("  logStr=" + logStr)
  // }

  return {
    "isFoundStr": isFoundStr,
    "strDictList": strDictList
  }
}

// print Intent info
function printIntentInfo(curIntent){
  console.log("printIntentInfo: curIntent=" + curIntent)
  var curComponent = curIntent.getComponent()
  console.log("  Intent component=" + curComponent)
  if (curComponent) {
    var pkgName = curComponent.getPackageName()
    var clsName = curComponent.getClassName()
    var shortClsName = curComponent.getShortClassName()
    var flattenedShortStr = curComponent.flattenToShortString()
    var flattenedStr = curComponent.flattenToString()
    console.log("    Intent Component info: pkgName=" + pkgName + ", clsName=" + clsName + ", shortClsName=" + shortClsName  + ", flattenedStr=" + flattenedStr + ",flattenedShortStr=" + flattenedShortStr)
  }
}


/*******************************************************************************
 * Main Hook
*******************************************************************************/

function hookNativeFunc(){
  // /Users/crifan/dev/dev_src/androidReverse/Android/android.googlesource.com/base-refs_heads_main/core/jni/android_util_Binder.cpp
  // status_t onTransact( uint32_t code, const Parcel& data, Parcel* reply, uint32_t flags = 0) override {
  // var foundOnTransact = Module.findExportByName(null, "onTransact")

  // let transactModuleName = "libBinder.so"
  // let transactModuleName = "libbinder.so"
  let transactModuleName = "libbinder_ndk.so"

  var foundOnTransact = Module.findExportByName(transactModuleName, "onTransact")

  console.log("foundOnTransact=" + foundOnTransact)
  if (foundOnTransact) {
    Interceptor.attach(foundOnTransact, {
      onEnter: function(args) {
        var code = args[0]
        var data = args[1]
        var reply = args[2]
        var flags = args[3]
        console.log("onTransact: code=" + code + ", data=" + data + ", reply=" + reply + ", flags=" + flags)
      },
      onLeave: function(retVal) {
        console.log("onTransact: retval=" + retVal)
      }
    })
  }

  // var foundTransact = Module.findExportByName(null, "transact")
  var foundTransact = Module.findExportByName(transactModuleName, "transact")
  console.log("foundTransact=" + foundTransact)
}

function hookPrintTransactCodeValue(){
    // ---------------------------------------- android.app.IActivityManager$Stub
    var IActivityManagerStubClassName = "android.app.IActivityManager$Stub"
    var IActivityManagerStubCls = Java.use(IActivityManagerStubClassName)
    console.log("IActivityManagerStubCls=" + IActivityManagerStubCls)
    // printClassAllMethodsFields(IActivityManagerStubClassName)

    // console.log("IActivityManager$Stub: code_startService=" + code_startService + ", code_broadcastIntent=" + code_broadcastIntent + ", code_startInstrumentation=" + code_startInstrumentation + ", code_unbindService=" + code_unbindService)
    var TRANSACTION_startService = IActivityManagerStubCls.TRANSACTION_startService.value
    console.log("TRANSACTION_startService=" + TRANSACTION_startService)
    var TRANSACTION_broadcastIntent = IActivityManagerStubCls.TRANSACTION_broadcastIntent.value
    console.log("TRANSACTION_broadcastIntent=" + TRANSACTION_broadcastIntent)
    var TRANSACTION_unbindService = IActivityManagerStubCls.TRANSACTION_unbindService.value
    console.log("TRANSACTION_unbindService=" + TRANSACTION_unbindService)
    var TRANSACTION_publishService = IActivityManagerStubCls.TRANSACTION_publishService.value
    console.log("TRANSACTION_publishService=" + TRANSACTION_publishService)
    var TRANSACTION_startInstrumentation = IActivityManagerStubCls.TRANSACTION_startInstrumentation.value
    console.log("TRANSACTION_startInstrumentation=" + TRANSACTION_startInstrumentation)
    var TRANSACTION_startActivity = IActivityManagerStubCls.TRANSACTION_startActivity.value
    console.log("TRANSACTION_startActivity=" + TRANSACTION_startActivity)
    // var TRANSACTION_startActivityAndWait = IActivityManagerStubCls.TRANSACTION_startActivityAndWait.value
    // console.log("TRANSACTION_startActivityAndWait=" + TRANSACTION_startActivityAndWait)
    // var TRANSACTION_startActivityAsCaller = IActivityManagerStubCls.TRANSACTION_startActivityAsCaller.value
    // console.log("TRANSACTION_startActivityAsCaller=" + TRANSACTION_startActivityAsCaller)
    var TRANSACTION_startActivityAsUser = IActivityManagerStubCls.TRANSACTION_startActivityAsUser.value
    console.log("TRANSACTION_startActivityAsUser=" + TRANSACTION_startActivityAsUser)
    var TRANSACTION_startActivityFromRecents = IActivityManagerStubCls.TRANSACTION_startActivityFromRecents.value
    console.log("TRANSACTION_startActivityFromRecents=" + TRANSACTION_startActivityFromRecents)
    // var TRANSACTION_startActivityIntentSender = IActivityManagerStubCls.TRANSACTION_startActivityIntentSender.value
    // console.log("TRANSACTION_startActivityIntentSender=" + TRANSACTION_startActivityIntentSender)
    // var TRANSACTION_startActivityWithConfig = IActivityManagerStubCls.TRANSACTION_startActivityWithConfig.value
    // console.log("TRANSACTION_startActivityWithConfig=" + TRANSACTION_startActivityWithConfig)

    var TRANSACTION_registerUidObserver = IActivityManagerStubCls.TRANSACTION_registerUidObserver.value
    console.log("TRANSACTION_registerUidObserver=" + TRANSACTION_registerUidObserver)
    var TRANSACTION_unhandledBack = IActivityManagerStubCls.TRANSACTION_unhandledBack.value
    console.log("TRANSACTION_unhandledBack=" + TRANSACTION_unhandledBack)
    var TRANSACTION_registerReceiver = IActivityManagerStubCls.TRANSACTION_registerReceiver.value
    console.log("TRANSACTION_registerReceiver=" + TRANSACTION_registerReceiver)
    var TRANSACTION_attachApplication = IActivityManagerStubCls.TRANSACTION_attachApplication.value
    console.log("TRANSACTION_attachApplication=" + TRANSACTION_attachApplication)
    // var TRANSACTION_activityIdle = IActivityManagerStubCls.TRANSACTION_activityIdle.value
    // console.log("TRANSACTION_activityIdle=" + TRANSACTION_activityIdle)
    var TRANSACTION_stopService = IActivityManagerStubCls.TRANSACTION_stopService.value
    console.log("TRANSACTION_stopService=" + TRANSACTION_stopService)
    var TRANSACTION_bindService = IActivityManagerStubCls.TRANSACTION_bindService.value
    console.log("TRANSACTION_bindService=" + TRANSACTION_bindService)
    var TRANSACTION_noteWakeupAlarm = IActivityManagerStubCls.TRANSACTION_noteWakeupAlarm.value
    console.log("TRANSACTION_noteWakeupAlarm=" + TRANSACTION_noteWakeupAlarm)
    var TRANSACTION_openContentUri = IActivityManagerStubCls.TRANSACTION_openContentUri.value
    console.log("TRANSACTION_openContentUri=" + TRANSACTION_openContentUri)
    var TRANSACTION_finishReceiver = IActivityManagerStubCls.TRANSACTION_finishReceiver.value
    console.log("TRANSACTION_finishReceiver=" + TRANSACTION_finishReceiver)
    // var TRANSACTION_startNextMatchingActivity = IActivityManagerStubCls.TRANSACTION_startNextMatchingActivity.value
    // console.log("TRANSACTION_startNextMatchingActivity=" + TRANSACTION_startNextMatchingActivity)

    var TRANSACTION_finishActivity = IActivityManagerStubCls.TRANSACTION_finishActivity.value
    console.log("TRANSACTION_finishActivity=" + TRANSACTION_finishActivity)
}

function hookForceStop() {
  if(!Java.available){
    console.error("Java is not available")
    return
  }

  console.log("Java is available")
  console.log("Java.androidVersion=" + Java.androidVersion)

  Java.perform(function () {

    const ValidTransactCodeList = [
      // 24,
      // 26,
      // 27,
      // 28,
      // 29,
      // 30,
      // 34,

      3, // f12217h = START_ACTIVITY_TRANSACTION = 2+1 = 3
      8, // TRANSACTION_startActivity= 7+1 = 8

      27, // serviceCode = TRANSACTION_startService = 27
      // 34, // serviceCode = START_SERVICE_TRANSACTION = 33+1 = 34
      
      29, // TRANSACTION_bindService = 29

      15, // broadcastCode = TRANSACTION_broadcastIntent = 14+1 = 15
      // 14, // broadcastCode = BROADCAST_INTENT_TRANSACTION = 13+1 = 14, TRANSACTION_removeAccountExplicitly = 13+1 = 14

      37, // instrumentationCode = TRANSACTION_startInstrumentation = 36+1= 37
      // 44, // instrumentationCode = START_INSTRUMENTATION_TRANSACTION = 43+1= 44
    ]

    hookNativeFunc()

    var ThrowableCls = Java.use("java.lang.Throwable")
    console.log("ThrowableCls=" + ThrowableCls)
    let curLog = Java.use("android.util.Log")
    console.log("curLog=" + curLog)
    let Parcel = Java.use("android.os.Parcel")
    console.log("Parcel=" + Parcel)

    // // com.android.server.wm.ActivityStarter
    // var serverCls = Java.use("com.android.server")
    // console.log("serverCls=" + serverCls)
    // var wmCls = serverCls.wm
    // console.log("wmCls=" + wmCls)
    // var ActivityStarterCls = wmCls.ActivityStarter
    // console.log("ActivityStarterCls=" + ActivityStarterCls)
    // // private int executeRequest(Request request) {

    // hookPrintTransactCodeValue()

    // ---------------------------------------- android.os.Binder
    var BinderCls = Java.use("android.os.Binder")
    console.log("BinderCls=" + BinderCls)

    // private boolean execTransact(int code, long dataObj, long replyObj, int flags)
    var execTransactFunc = BinderCls.execTransact
    console.log("execTransactFunc=" + execTransactFunc)

    if (execTransactFunc) {
      execTransactFunc.implementation = function (code, dataObj, replyObj, flags) {
        var shouldCallOrigFunc = true
        // var logStr = ""

        // if (ValidTransactCodeList.includes(code)) {
          var dataParcel = Parcel.obtain(dataObj)

          // var replyPacel = Parcel.obtain(replyObj)
          // var dataParcelStr = dataParcel.toString()
          // var replyPacelStr = replyPacel.toString()
          // console.log("dataParcelStr=" + dataParcelStr + ", replyPacelStr=" + replyPacelStr)
          var curParcelDataSize = dataParcel.dataSize()
          // console.log("  curParcelDataSize=" + curParcelDataSize)
          if (curParcelDataSize > 0) {
            // let interfaceTokenStartPos = 1
            // let interfaceTokenStartPos = 0
            // let interfaceTokenStartPos = 4
            // let interfaceTokenStartPos = 8
            // dataParcel.setDataPosition(interfaceTokenStartPos)
            // var interfaceTokenStr = dataParcel.readString()
            // console.log("  interfaceTokenStr=" + interfaceTokenStr)

            // var parcelStr = tryReadParcelString(dataParcel)
            // var {parcelStr, strPos} = tryReadParcelString(dataParcel)
            var readResultDict = tryReadParcelString(dataParcel)
            // console.log("parcelStr=" + parcelStr + ", strPos=" + strPos)
            var isFoundStr = readResultDict.isFoundStr
            var strDictList = readResultDict.strDictList
            if (isFoundStr) {
              // var foundStrLog = ""
              var strDictListStr = toJsonStr(strDictList, true, 0)
              // console.log("Binder.execTransact: code=" + code + ", dataObj=" + dataObj + ", replyObj=" + replyObj + ", flags=" + flags)
              var execTransactCallStr = "Binder.execTransact: code=" + code + ", dataObj=" + dataObj + ", replyObj=" + replyObj + ", flags=" + flags
              // console.log(execTransactCallStr)

              var dataParcelInfoStr = getParcelInfo(dataParcel)
              // var replyPacelInfoStr = getParcelInfo(replyPacel)
              // console.log("dataParcelInfoStr=" + dataParcelInfoStr + ", replyPacelInfoStr=" + replyPacelInfoStr)
              // console.log("  dataParcel: strDictListStr=" + strDictListStr + ", infoStr=" + dataParcelInfoStr)
              var dataParcelCurAppStr = "  dataParcel: strDictListStr=" + strDictListStr + ", infoStr=" + dataParcelInfoStr
              // console.log(dataParcelCurAppStr)

              // for debug: found string not empty, then not call origin transact -> try find this function is true core trigger service or not
              // if (parcelStr) {
              // if (parcelStr === CurAppPkgName) {
              var isCurApp = false
              for (var idx = 0; idx < strDictList.length; idx++) {
                var curStrDict = strDictList[idx]
                var curPos = curStrDict["pos"]
                var curStr = curStrDict["str"]
                if (curStr.includes(CurAppPkgName)) {
                  isCurApp = true
                  // console.log("    Found [" + curPos + "] current app: " + curStr)
                  break
                }
              }

              if (enableNotCallFilter_Binder_execTransact){
                if (isCurApp) {
                  shouldCallOrigFunc = false
                  // console.log("  shouldCallOrigFunc=" + shouldCallOrigFunc)
                }
              }

              var shouldLogDetail = false
              if (isCurApp) {
                shouldLogDetail = true
                // console.log("shouldLogDetail=" + shouldLogDetail)
              }

              if (shouldLogDetail){
                // var detailedLogStr = execTransactCallStr + "\n" + dataParcelCurAppStr
                var detailedLogStr = `${execTransactCallStr}\n${dataParcelCurAppStr}`
                // var detailedLogStr = execTransactCallStr + "\n" + dataParcelCurAppStr
                console.log(detailedLogStr)
                // foundStrLog = `${execTransactCallStr}\n${dataParcelCurAppStr}`

                //   // console.log("CurApp Binder.execTransact: code=" + code + ", dataObj=" + dataObj + ", replyObj=" + replyObj + ", flags=" + flags + "\n  dataParcel: strDictListStr=" + strDictListStr + ", infoStr=" + dataParcelInfoStr)
                //   console.log("CurApp Binder.execTransact: code=" + code + ", dataObj=" + dataObj + ", replyObj=" + replyObj + ", flags=" + flags)
                //   console.log("  dataParcel: strDictListStr=" + strDictListStr + ", infoStr=" + dataParcelInfoStr)

                //   // logStr = `Binder.execTransact: code=${code}, dataObj=${dataObj}, replyObj=${replyObj}, flags=${flags}\n  dataParcel: strDictListStr=${strDictListStr}, infoStr=${ dataParcelInfoStr}`
                //   // console.log("DetailLogStr=" + logStr)
              } else {
                //   console.log("Simple Binder.execTransact: code=" + code + ", dataObj=" + dataObj + ", flags=" + flags)
                //   // logStr = `Simple: Binder.execTransact: code=${code}, dataObj=${dataObj}, flags=${flags}`
                //   // console.log("SimpleLogStr=" + logStr)

                // foundStrLog = `Binder.execTransact: code=${code}, dataObj=${dataObj}, flags=${flags}`
                var simpleLog = `Binder.execTransact: code=${code}, dataObj=${dataObj}, flags=${flags}`
                // var simpleLog = "Binder.execTransact: code=" + code + ", dataObj=" + dataObj + ", flags=" + flags
                console.log(simpleLog)
              }

              // console.log(foundStrLog)
            }

            // PrintStack(ThrowableCls)
          } else {
            console.log("Binder execTransact: code=" + code + ", 0 size data Parcel, flags=" + flags)
          }
        // }

        if (shouldCallOrigFunc) {
          // console.log(logStr)
          return this.execTransact(code, dataObj, replyObj, flags)
        } else {
          // console.log(logStr)
          console.log("    Not call Binder.execTransact")
          return false
        }

      }
    }

    var IBinderClassName = "android.os.IBinder"
    var IBinderCls = Java.use(IBinderClassName)
    console.log("IBinderCls=" + IBinderCls)
    // printClassAllMethodsFields(IBinderClassName)
    var firstCallTransacton = IBinderCls.FIRST_CALL_TRANSACTION
    console.log("firstCallTransacton=" + firstCallTransacton)
    var firstCallTransactonValue = firstCallTransacton.value
    console.log("firstCallTransactonValue=" + firstCallTransactonValue)

    // public abstract boolean transact (int code, Parcel data, Parcel reply, int flags)
    // var transactFunc = IBinderCls.transact

    var transactFunc = BinderCls.transact
    if (transactFunc) {
      transactFunc.implementation = function (code, data, reply, flags) {
        var transactOk = this.transact(code, data, reply, flags)
        if (ValidTransactCodeList.includes(code)) {
          console.log("Binder transact: code=" + code + ",data=" + data + ",reply=" + reply + ",flags=" + flags + " -> transactOk=" + transactOk)
          PrintStack(ThrowableCls)
        }
        return transactOk
      }
    }

    // protected boolean onTransact (int code,  Parcel data,  Parcel reply,  int flags)
    var onTransactFunc = BinderCls.onTransact
    if (onTransactFunc) {
      onTransactFunc.implementation = function (code, data, reply, flags) {
        var transactOk = this.onTransact(code, data, reply, flags)
        if (ValidTransactCodeList.includes(code)) {
          console.log("Binder onTransact: code=" + code + ",data=" + data + ",reply=" + reply + ",flags=" + flags + " -> transactOk=" + transactOk)
          PrintStack(ThrowableCls)
        }
        return transactOk
      }
    }

    // ---------------------------------------- android.app.ContextImpl
    var ContextImplClassName = "android.app.ContextImpl"
    var ContextImplCls = Java.use(ContextImplClassName)
    console.log("ContextImplCls=" + ContextImplCls)
    // printClassAllMethodsFields(ContextImplClassName)

    // public boolean bindServiceAsUser(Intent service, ServiceConnection conn, int flags, UserHandle user)
    var bindServiceAsUserFunc4 = ContextImplCls.bindServiceAsUser.overload('android.content.Intent', 'android.content.ServiceConnection', 'int', 'android.os.UserHandle')
    if (bindServiceAsUserFunc4) {
      bindServiceAsUserFunc4.implementation = function (service, conn, flags, user) {
        // console.log("ContextImpl.bindServiceAsUser 4: service=" + service + ", conn=" + conn + ", flags=" + flags + ", user=" + user)
        // PrintStack(ThrowableCls)
        var funcName = "ContextImpl.bindServiceAsUser 4"
        var funcParaDict = {
          "service": service,
          "conn": conn,
          "flags": flags,
          "user": user,
        }
        printFunctionCallAndStack(funcName, funcParaDict, ThrowableCls)

        return this.bindServiceAsUser(service, conn, flags, user)
      }
    }

    // public boolean bindServiceAsUser(Intent service, ServiceConnection conn, int flags, Handler handler, UserHandle user)
    var bindServiceAsUserFunc5 = ContextImplCls.bindServiceAsUser.overload('android.content.Intent', 'android.content.ServiceConnection', 'int', 'android.os.Handler', 'android.os.UserHandle')
    if (bindServiceAsUserFunc5) {
      bindServiceAsUserFunc5.implementation = function (service, conn, flags, handler, user) {
        // console.log("ContextImpl.bindServiceAsUser 5: service=" + service + ", conn=" + conn + ", flags=" + flags + ", handler=" + handler + ", user=" + user)
        // PrintStack(ThrowableCls)
        var funcName = "ContextImpl.bindServiceAsUser 5"
        var funcParaDict = {
          "service": service,
          "conn": conn,
          "flags": flags,
          "handler": handler,
          "user": user,
        }
        printFunctionCallAndStack(funcName, funcParaDict, ThrowableCls)

        return this.bindServiceAsUser(service, conn, flags, handler, user)
      }
    }

    
    // ---------------------------------------- com.android.server.am.ProcessRecord
    var ProcessRecordClassName = "com.android.server.am.ProcessRecord"
    var ProcessRecordCls = Java.use(ProcessRecordClassName)
    console.log("ProcessRecordCls=" + ProcessRecordCls)
    // printClassAllMethodsFields(ProcessRecordClassName)

    // ---------------------------------------- com.android.server.am.ActiveServices
    var ActiveServicesClassName = "com.android.server.am.ActiveServices"
    var ActiveServicesCls = Java.use(ActiveServicesClassName)
    console.log("ActiveServicesCls=" + ActiveServicesCls)

    // private String bringUpServiceLocked(ServiceRecord r, int intentFlags, boolean execInFg, boolean whileRestarting, boolean permissionsReviewRequired, boolean packageFrozen, boolean enqueueOomAdj)
    var bringUpServiceLockedFunc = ActiveServicesCls.bringUpServiceLocked
    if (bringUpServiceLockedFunc) {
      bringUpServiceLockedFunc.implementation = function (r, intentFlags, execInFg, whileRestarting, permissionsReviewRequired, packageFrozen, enqueueOomAdj) {
        var shouldCallOrigFunc = true
        // console.log("ActiveServices.bringUpServiceLocked: r=" + r + ", intentFlags=" + intentFlags + ", execInFg=" + execInFg + ", whileRestarting=" + whileRestarting + ", permissionsReviewRequired=" + permissionsReviewRequired + ", packageFrozen=" + packageFrozen + ", enqueueOomAdj=" + enqueueOomAdj)
        // PrintStack(ThrowableCls)

        var funcName = "ActiveServices.bringUpServiceLocked"
        var funcParaDict = {
          "r": r,
          "intentFlags": intentFlags,
          "execInFg": execInFg,
          "whileRestarting": whileRestarting,
          "permissionsReviewRequired": permissionsReviewRequired,
          "packageFrozen": packageFrozen,
          "enqueueOomAdj": enqueueOomAdj,
        }
        printFunctionCallAndStack(funcName, funcParaDict, ThrowableCls)

        if(enableNotCallFilter_ActiveServices_bringUpServiceLocked){
          var rStr = r.toString()
          if (rStr.includes(CurAppPkgName)){
            shouldCallOrigFunc = false
          }
        }

        if(shouldCallOrigFunc) {
          return this.bringUpServiceLocked(r, intentFlags, execInFg, whileRestarting, permissionsReviewRequired, packageFrozen, enqueueOomAdj)
        } else {
          console.log("  Not call ActiveServices.bringUpServiceLocked")
          return ""
        }
      }
    }

    // ComponentName startServiceLocked(IApplicationThread caller, Intent service, String resolvedType, int callingPid, int callingUid, boolean fgRequired, String callingPackage, @Nullable String callingFeatureId, final int userId)
    var startServiceLockedFunc9 = ActiveServicesCls.startServiceLocked.overload('android.app.IApplicationThread', 'android.content.Intent', 'java.lang.String', 'int', 'int', 'boolean', 'java.lang.String', 'java.lang.String', 'int')
    if (startServiceLockedFunc9) {
      startServiceLockedFunc9.implementation = function (caller, service, resolvedType, callingPid, callingUid, fgRequired, callingPackage, callingFeatureId, userId) {
        var shouldCallOrigFunc = true
        var funcName = "ActiveServices.startServiceLocked 9"
        var funcParaDict = {
          "caller": caller,
          "service": service,
          "resolvedType": resolvedType,
          "callingPid": callingPid,
          "callingUid": callingUid,
          "fgRequired": fgRequired,
          "callingPackage": callingPackage,
          "callingFeatureId": callingFeatureId,
          "userId": userId,
        }
        printFunctionCallAndStack(funcName, funcParaDict, ThrowableCls)

        if(enableNotCallFilter_ActiveServices_startServiceLocked){
          if (callingPackage.includes(CurAppPkgName)){
            shouldCallOrigFunc = false
          }
        }

        if(shouldCallOrigFunc) {
          return this.startServiceLocked(caller, service, resolvedType, callingPid, callingUid, fgRequired, callingPackage, callingFeatureId, userId)
        } else {
          console.log("  Not call ActiveServices.startServiceLocked 9")
          return null
        }
      }
    }

    // ComponentName startServiceLocked(IApplicationThread caller, Intent service, String resolvedType, int callingPid, int callingUid, boolean fgRequired, String callingPackage, @Nullable String callingFeatureId, final int userId, boolean allowBackgroundActivityStarts, @Nullable IBinder backgroundActivityStartsToken)
    var startServiceLockedFunc11 = ActiveServicesCls.startServiceLocked.overload('android.app.IApplicationThread', 'android.content.Intent', 'java.lang.String', 'int', 'int', 'boolean', 'java.lang.String', 'java.lang.String', 'int', 'boolean', 'android.os.IBinder')
    if (startServiceLockedFunc11) {
      startServiceLockedFunc11.implementation = function (caller, service, resolvedType, callingPid, callingUid, fgRequired, callingPackage, callingFeatureId, userId, allowBackgroundActivityStarts, backgroundActivityStartsToken) {
        var shouldCallOrigFunc = true
        var funcName = "ActiveServices.startServiceLocked 11"
        var funcParaDict = {
          "caller": caller,
          "service": service,
          "resolvedType": resolvedType,
          "callingPid": callingPid,
          "callingUid": callingUid,
          "fgRequired": fgRequired,
          "callingPackage": callingPackage,
          "callingFeatureId": callingFeatureId,
          "userId": userId,
          "allowBackgroundActivityStarts": allowBackgroundActivityStarts,
          "backgroundActivityStartsToken": backgroundActivityStartsToken,
        }
        printFunctionCallAndStack(funcName, funcParaDict, ThrowableCls)

        if(enableNotCallFilter_ActiveServices_startServiceLocked){
          if (callingPackage.includes(CurAppPkgName)){
            shouldCallOrigFunc = false
          }
        }

        if(shouldCallOrigFunc) {
          return this.startServiceLocked(caller, service, resolvedType, callingPid, callingUid, fgRequired, callingPackage, callingFeatureId, userId, allowBackgroundActivityStarts, backgroundActivityStartsToken)
        } else {
          console.log("  Not call ActiveServices.startServiceLocked 11")
          return null
        }
      }
    }

    // ComponentName startServiceInnerLocked(ServiceMap smap, Intent service, ServiceRecord r, boolean callerFg, boolean addToStarting, int callingUid, boolean wasStartRequested)
    var startServiceInnerLockedFunc7 = ActiveServicesCls.startServiceInnerLocked.overload('com.android.server.am.ActiveServices$ServiceMap', 'android.content.Intent', 'com.android.server.am.ServiceRecord', 'boolean', 'boolean', 'int', 'boolean')
    if (startServiceInnerLockedFunc7) {
      startServiceInnerLockedFunc7.implementation = function (smap, service, r, callerFg, addToStarting, callingUid, wasStartRequested) {
        var shouldCallOrigFunc = true
        var funcName = "ActiveServices.startServiceInnerLocked 7"
        var funcParaDict = {
          "smap": smap,
          "service": service,
          "r": r,
          "callerFg": callerFg,
          "addToStarting": addToStarting,
          "callingUid": callingUid,
          "wasStartRequested": wasStartRequested,
        }
        printFunctionCallAndStack(funcName, funcParaDict, ThrowableCls)

        if(enableNotCallFilter_ActiveServices_startServiceInnerLocked){
          var rStr = r.toString()
          if (rStr.includes(CurAppPkgName)){
            shouldCallOrigFunc = false
          }
        }

        if(shouldCallOrigFunc) {
          return this.startServiceInnerLocked(smap, service, r, callerFg, addToStarting, callingUid, wasStartRequested)
        } else {
          console.log("  Not call ActiveServices.startServiceInnerLocked 7")
          return null
        }
      }
    }

    // private ComponentName startServiceInnerLocked(ServiceRecord r, Intent service, int callingUid, int callingPid, boolean fgRequired, boolean callerFg, boolean allowBackgroundActivityStarts, @Nullable IBinder backgroundActivityStartsToken)
    var startServiceInnerLockedFunc8 = ActiveServicesCls.startServiceInnerLocked.overload('com.android.server.am.ServiceRecord', 'android.content.Intent', 'int', 'int', 'boolean', 'boolean', 'boolean', 'android.os.IBinder')
    if (startServiceInnerLockedFunc8) {
      startServiceInnerLockedFunc8.implementation = function (r, service, callingUid, callingPid, fgRequired, callerFg, allowBackgroundActivityStarts, backgroundActivityStartsToken) {
        var shouldCallOrigFunc = true
        var funcName = "ActiveServices.startServiceInnerLocked 8"
        var funcParaDict = {
          "r": r,
          "service": service,
          "callingUid": callingUid,
          "callingPid": callingPid,
          "fgRequired": fgRequired,
          "callerFg": callerFg,
          "allowBackgroundActivityStarts": allowBackgroundActivityStarts,
          "backgroundActivityStartsToken": backgroundActivityStartsToken,
        }
        printFunctionCallAndStack(funcName, funcParaDict, ThrowableCls)

        if(enableNotCallFilter_ActiveServices_startServiceInnerLocked){
          var rStr = r.toString()
          if (rStr.includes(CurAppPkgName)){
            shouldCallOrigFunc = false
          }
        }

        if(shouldCallOrigFunc) {
          return this.startServiceInnerLocked(r, service, callingUid, callingPid, fgRequired, callerFg, allowBackgroundActivityStarts, backgroundActivityStartsToken)
        } else {
          console.log("  Not call ActiveServices.startServiceInnerLocked 8")
          return null
        }
      }
    }


    // ---------------------------------------- com.android.server.am.ProcessList
    var ProcessListCls = Java.use("com.android.server.am.ProcessList")
    console.log("ProcessListCls=" + ProcessListCls)
    
    //     boolean startProcessLocked(HostingRecord hostingRecord, String entryPoint, ProcessRecord app, int uid, int[] gids, int runtimeFlags, int zygotePolicyFlags, int mountExternal, String seInfo, String requiredAbi, String instructionSet, String invokeWith, long startUptime, long startElapsedTime)
    var startProcessLockedFunc = ProcessListCls.startProcessLocked.overload('com.android.server.am.HostingRecord', 'java.lang.String', 'com.android.server.am.ProcessRecord', 'int', '[I', 'int', 'int', 'int', 'java.lang.String', 'java.lang.String', 'java.lang.String', 'java.lang.String', 'long', 'long')
    console.log("startProcessLockedFunc=" + startProcessLockedFunc)
    if (startProcessLockedFunc) {
      startProcessLockedFunc.implementation = function (hostingRecord, entryPoint, app, uid, gids, runtimeFlags, zygotePolicyFlags, mountExternal, seInfo, requiredAbi, instructionSet, invokeWith, startUptime, startElapsedTime) {
        var shouldCallOrigFunc = true
        console.log("ProcessList.startProcessLocked: hostingRecord=" + hostingRecord + ", entryPoint=" + entryPoint + ", app=" + app + ", uid=" + uid + ", gids=" + gids + ", runtimeFlags=" + runtimeFlags + ", zygotePolicyFlags=" + zygotePolicyFlags + ", mountExternal=" + mountExternal + ", seInfo=" + seInfo + ", requiredAbi=" + requiredAbi + ", instructionSet=" + instructionSet + ", invokeWith=" + invokeWith + ", startUptime=" + startUptime + ", startElapsedTime=" + startElapsedTime)
        // PrintStack(ThrowableCls)

        if(enableNotCallFilter_ProcessList_startProcessLocked){
          var appStr = app.toString()
          if (appStr.includes(CurAppPkgName)){
            shouldCallOrigFunc = false
          }
        }

        if(shouldCallOrigFunc) {
          return this.startProcessLocked(hostingRecord, entryPoint, app, uid, gids, runtimeFlags, zygotePolicyFlags, mountExternal, seInfo, requiredAbi, instructionSet, invokeWith, startUptime, startElapsedTime)
        } else {
          console.log("  Not call ProcessList.startProcessLocked")
          return false
        }
      }
    }


    // boolean handleProcessStartedLocked(ProcessRecord app, int pid, boolean usingWrapper, long expectedStartSeq, boolean procAttached) {
    var handleProcessStartedLockedFunc = ProcessListCls.handleProcessStartedLocked.overload('com.android.server.am.ProcessRecord', 'int', 'boolean', 'long', 'boolean')
    console.log("handleProcessStartedLockedFunc=" + handleProcessStartedLockedFunc)
    if (handleProcessStartedLockedFunc) {
      handleProcessStartedLockedFunc.implementation = function (app, pid, usingWrapper, expectedStartSeq, procAttached) {
        var shouldCallOrigFunc = true
        console.log("ProcessList.handleProcessStartedLocked: app=" + app + ", pid=" + pid + ", usingWrapper=" + usingWrapper + ", expectedStartSeq=" + expectedStartSeq + ", procAttached=" + procAttached)
        // printProcessRecord(app)

        if(enableNotCallFilter_ProcessList_handleProcessStartedLocked){
          var appStr = app.toString()
          if (appStr.includes(CurAppPkgName)){
            shouldCallOrigFunc = false
          }
        }

        if (shouldCallOrigFunc) {
          PrintStack(ThrowableCls)
          return this.handleProcessStartedLocked(app, pid, usingWrapper, expectedStartSeq, procAttached)  
        } else {
          console.log("  Not call ProcessList.handleProcessStartedLocked")
          // return false
          return true
        }

      }
    }

    // ---------------------------------------- com.android.server.am.ContentProviderHelper
    var ContentProviderHelperClassName = "com.android.server.am.ContentProviderHelper"
    var ContentProviderHelperCls = Java.use(ContentProviderHelperClassName)
    console.log("ContentProviderHelperCls=" + ContentProviderHelperCls)

    // private ContentProviderHolder getContentProviderImpl(IApplicationThread caller, String name, IBinder token, int callingUid, String callingPackage, String callingTag, boolean stable, int userId)
    var getContentProviderImplFunc = ContentProviderHelperCls.getContentProviderImpl
    if (getContentProviderImplFunc) {
      getContentProviderImplFunc.implementation = function (caller, name, token, callingUid, callingPackage, callingTag, stable, userId) {
        var shouldCallOrigFunc = true
        // console.log("ContentProviderHelper.getContentProviderImpl: caller=" + caller + ", name=" + name + ", token=" + token + ", callingUid=" + callingUid + ", callingPackage=" + callingPackage + ", callingTag=" + callingTag + ", stable=" + stable + ", userId=" + userId)
        // PrintStack(ThrowableCls)

        var funcName = "ContentProviderHelper.getContentProviderImpl"
        var funcParaDict = {
          "caller": caller,
          "name": name,
          "token": token,
          "callingUid": callingUid,
          "callingPackage": callingPackage,
          "callingTag": callingTag,
          "stable": stable,
          "userId": userId,
        }
        printFunctionCallAndStack(funcName, funcParaDict, ThrowableCls)

        if(enableNotCallFilter_ContentProviderHelper_getContentProviderImpl){
          // if(callingPackage.includes(CurAppPkgName)){
          if(name.includes(CurAppPkgName)){
            shouldCallOrigFunc = false
          }
        }

        if (shouldCallOrigFunc) {
          return this.getContentProviderImpl(caller, name, token, callingUid, callingPackage, callingTag, stable, userId)
        } else {
          console.log("  Not call ContentProviderHelper.getContentProviderImpl")
          return null
        }
      }
    }

    // ---------------------------------------- android.os.Handler
    var HandlerClassName = "android.os.Handler"
    var HandlerCls = Java.use(HandlerClassName)
    console.log("HandlerCls=" + HandlerCls)

    // public void dispatchMessage(@NonNull Message msg)
    var dispatchMessageFunc = HandlerCls.dispatchMessage
    if (dispatchMessageFunc) {
      dispatchMessageFunc.implementation = function (msg) {
        var shouldCallOrigFunc = true

        var mgsStr = msg.toString()
        if(mgsStr.includes(CurAppPkgName)){
          // console.log("Handler.dispatchMessage: msg=" + msg)
          // PrintStack(ThrowableCls)
          var funcName = "Handler.dispatchMessage"
          var funcParaDict = {
            "msg": msg,
          }
          printFunctionCallAndStack(funcName, funcParaDict, ThrowableCls)

          if(enableNotCallFilter_Handler_dispatchMessage){
            // is not : Handler.dispatchMessage: msg={ when=-927ms what=4104 obj=ApplicationExitInfo(timestamp=2023/9/19 16:55 pid=3953 realUid=10249 packageUid=10249 definingUid=10249 user=0 process=com.wallpaper.hd.funny reason=12 (DEPENDENCY DIED) subreason=0 (UNKNOWN) status=0 importance=400 pss=33MB rss=132MB description=depends on provider com.google.android.gms/.phenotype.provider.ConfigurationProvider in dying proc com.google.android.gms.persistent (adj -10000) state=empty trace=null target=com.android.server.am.AppExitInfoTracker$KillHandler }
            if(!mgsStr.includes("ApplicationExitInfo")){
              shouldCallOrigFunc = false
            }
          }
        }

        if (shouldCallOrigFunc) {
          return this.dispatchMessage(msg)
        } else {
          console.log("  Not call Handler.dispatchMessage")
          // return null
          return
        }
      }
    }

    // ---------------------------------------- com.android.server.am.BroadcastQueue
    var BroadcastQueueClassName = "com.android.server.am.BroadcastQueue"
    var BroadcastQueueCls = Java.use(BroadcastQueueClassName)
    console.log("BroadcastQueueCls=" + BroadcastQueueCls)

    // final void processNextBroadcastLocked(boolean fromMsg, boolean skipOomAdj)
    var processNextBroadcastLockedFunc = BroadcastQueueCls.processNextBroadcastLocked
    if (processNextBroadcastLockedFunc) {
      processNextBroadcastLockedFunc.implementation = function (fromMsg, skipOomAdj) {
        var shouldCallOrigFunc = true
        // console.log("BroadcastQueue.processNextBroadcastLocked: fromMsg=" + fromMsg + ", skipOomAdj=" + skipOomAdj)
        // PrintStack(ThrowableCls)
        var funcName = "BroadcastQueue.processNextBroadcastLocked"
        var funcParaDict = {
          "fromMsg": fromMsg,
          "skipOomAdj": skipOomAdj,
        }
        printFunctionCallAndStack(funcName, funcParaDict, ThrowableCls)

        if (shouldCallOrigFunc) {
          return this.processNextBroadcastLocked(fromMsg, skipOomAdj)
        } else {
          console.log("  Not call BroadcastQueue.processNextBroadcastLocked")
          return null
        }
      }
    }

    // ---------------------------------------- com.android.server.am.ActivityManagerService
    var curJavaClassName = "com.android.server.am.ActivityManagerService"
    // printClassAllMethodsFields(curJavaClassName)
    var ActivityManagerServiceCls = Java.use(curJavaClassName)
    console.log("ActivityManagerServiceCls=" + ActivityManagerServiceCls)

    // final ProcessRecord startProcessLocked(String processName, ApplicationInfo info, boolean knownToBeDead, int intentFlags, HostingRecord hostingRecord, int zygotePolicyFlags, boolean allowWhileBooting, boolean isolated)
    var amsStartProcessLockedFunc = ActivityManagerServiceCls.startProcessLocked
    if (amsStartProcessLockedFunc) {
      amsStartProcessLockedFunc.implementation = function (processName, info, knownToBeDead, intentFlags, hostingRecord, zygotePolicyFlags, allowWhileBooting, isolated) {
        var shouldCallOrigFunc = true
        // console.log("AMS.startProcessLocked: processName=" + processName + ", info=" + info + ", knownToBeDead=" + knownToBeDead + ", intentFlags=" + intentFlags + ", hostingRecord=" + hostingRecord + ", zygotePolicyFlags=" + zygotePolicyFlags + ", allowWhileBooting=" + allowWhileBooting + ", isolated=" + isolated)
        // PrintStack(ThrowableCls)
        var funcName = "AMS.startProcessLocked"
        var funcParaDict = {
          "processName": processName,
          "info": info,
          "knownToBeDead": knownToBeDead,
          "intentFlags": intentFlags,
          "hostingRecord": hostingRecord,
          "zygotePolicyFlags": zygotePolicyFlags,
          "allowWhileBooting": allowWhileBooting,
          "isolated": isolated,
        }
        printFunctionCallAndStack(funcName, funcParaDict, ThrowableCls)

        if(enableNotCallFilter_AMS_startProcessLocked){
          if(processName.includes(CurAppPkgName)){
            shouldCallOrigFunc = false
          }
        }

        if (shouldCallOrigFunc) {
          return this.startProcessLocked(processName, info, knownToBeDead, intentFlags, hostingRecord, zygotePolicyFlags, allowWhileBooting, isolated)
        } else {
          console.log("  Not call AMS.startProcessLocked")
          return null
        }
      }
    }

    // private boolean attachApplicationLocked(@NonNull IApplicationThread thread, int pid, int callingUid, long startSeq)
    var attachApplicationLockedFunc = ActivityManagerServiceCls.attachApplicationLocked
    console.log("attachApplicationLockedFunc=" + attachApplicationLockedFunc)
    if (attachApplicationLockedFunc) {
      attachApplicationLockedFunc.implementation = function (thread, pid, callingUid, startSeq) {
        // console.log("AMS.attachApplicationLocked: thread=" + thread + ", pid=" + pid + ", callingUid=" + callingUid + ", startSeq=" + startSeq)
        // PrintStack(ThrowableCls)
        var funcName = "AMS.attachApplicationLocked"
        var funcParaDict = {
          "thread": thread,
          "pid": pid,
          "callingUid": callingUid,
          "startSeq": startSeq,
        }
        printFunctionCallAndStack(funcName, funcParaDict, ThrowableCls)

        return this.attachApplicationLocked(thread, pid, callingUid, startSeq)
      }
    }

    // public ComponentName startService(IApplicationThread caller, Intent service, String resolvedType, boolean requireForeground, String callingPackage, String callingFeatureId, int userId) throws TransactionTooLargeException {
    var startServiceFunc = ActivityManagerServiceCls.startService
    console.log("startServiceFunc=" + startServiceFunc)
    if (startServiceFunc) {
      startServiceFunc.implementation = function (caller, service, resolvedType, requireForeground, callingPackage, callingFeatureId, userId) {
        var shouldCallOrigFunc = true
        // console.log("AMS.startService: caller=" + caller + ", service=" + service + ", resolvedType=" + resolvedType + ", requireForeground=" + requireForeground + ", callingPackage=" + callingPackage + ", callingFeatureId=" + callingFeatureId + ", userId=" + userId)
        // PrintStack(ThrowableCls)

        var isCurApp = false

        if (service){
          // printIntentInfo(service)
          var serviceStr = service.toString()
          console.log("serviceStr=" + serviceStr)
          // serviceStr=Intent { cmp=com.wallpaper.hd.funny/com.w.thsz.s.Service108 }
          if (serviceStr.includes(CurAppPkgName)) {
            isCurApp = true
          }
        }

        if(isCurApp){
          var funcName = "AMS.startService"
          var funcParaDict = {
            "caller": caller,
            "service": service,
            "resolvedType": resolvedType,
            "requireForeground": requireForeground,
            "callingPackage": callingPackage,
            "callingFeatureId": callingFeatureId,
            "userId": userId,
          }
          // console.log("will call printFunctionCallAndStack: funcName=" + funcName + ", funcParaDict=" + toJsonStr(funcParaDict) + ", ThrowableCls=" + ThrowableCls)
          printFunctionCallAndStack(funcName, funcParaDict, ThrowableCls)

          var serviceHasFileDescriptors = service.hasFileDescriptors()
          console.log("serviceHasFileDescriptors=" + serviceHasFileDescriptors)

          if(enableNotCallFilter_AMS_startService){
            shouldCallOrigFunc = false
          }
        }

        if (shouldCallOrigFunc) {
          // return this.startService(caller, service, resolvedType, requireForeground, callingPackage, callingFeatureId, userId)
          var retComponentName = this.startService(caller, service, resolvedType, requireForeground, callingPackage, callingFeatureId, userId)

          if(isCurApp){
            console.log("retComponentName=" + retComponentName)
          }

          return retComponentName
        } else {
          console.log("  Not call AMS.startService")
          return null
        }

      }
    }

    // // !!! Note: hook ActivityManagerService.onTransact always cause Android CRUSH and REBOOT
    // // public boolean onTransact(int code, Parcel data, Parcel reply, int flags)
    // var amsOnTransactFunc = ActivityManagerServiceCls.onTransact
    // console.log("amsOnTransactFunc=" + amsOnTransactFunc)
    // if (amsOnTransactFunc) {
    //   amsOnTransactFunc.implementation = function (code, dataParcel, replyParcel, flags) {
    //     // if (ValidTransactCodeList.includes(code)) {
    //     //   var datParcelStr = tryReadParcelString(dataParcel)
    //     //   if (datParcelStr) {
    //     //     console.log("AMS onTransact: code=" + code + ", dataParcel=" + dataParcel + ",datParcelStr=" + datParcelStr + ", replyParcel=" + replyParcel + ", flags=" + flags)
    //     //     PrintStack(ThrowableCls)  
    //     //   }
    //     // }

    //     // console.log("AMS.onTransact: code=" + code + ", dataParcel=" + dataParcel + ", replyParcel=" + replyParcel + ", flags=" + flags)
    //     return this.onTransact(code, dataParcel, replyParcel, flags)
    //   }
    // }

    // // Note: will cause crash & reboot, so temp not hook
    // // public boolean startInstrumentation(ComponentName className, String profileFile, int flags, Bundle arguments, IInstrumentationWatcher watcher, IUiAutomationConnection uiAutomationConnection, int userId, String abiOverride)
    // var startInstrumentationFunc = ActivityManagerServiceCls.startInstrumentation
    // console.log("startInstrumentationFunc=" + startInstrumentationFunc)
    // if (startInstrumentationFunc) {
    //   // startInstrumentationFunc.implementation = function (className, profileFile, flags, arguments, watcher, uiAutomationConnection, userId, abiOverride) {
    //   startInstrumentationFunc.implementation = function (className, profileFile, flags, arguments1, watcher, uiAutomationConnection, userId, abiOverride) {
    //     console.log("typeof flags=" + (typeof flags) + ",typeof userId=" + (typeof userId))
    //     // var Integer = Java.use("java.lang.Integer")
    //     // var flagsInt = Integer.valueOf(flags)
    //     // var userIdInt = Integer.valueOf(userId)
    //     // console.log("typeof flagsInt=" + (typeof flagsInt) + ",typeof userIdInt=" + (typeof userIdInt))
  
    //     console.log("className=" + className + ", profileFile=" + profileFile + ", flags=" + flags + ", arguments1=" + arguments1 + ", watcher=" + watcher + ", uiAutomationConnection=" + uiAutomationConnection + ", userId=" + userId + ", abiOverride=" + abiOverride)
    //     PrintStack(ThrowableCls)
    //     // return this.startInstrumentation(className, profileFile, flags, arguments, watcher, uiAutomationConnection, userId, abiOverride)
    //     return this.startInstrumentation(className, profileFile, flags, arguments1, watcher, uiAutomationConnection, userId, abiOverride)
    //     // return this.startInstrumentation(className, profileFile, flagsInt, arguments1, watcher, uiAutomationConnection, userIdInt, abiOverride)
    //   }
    // }

    // // public final void com.android.server.am.ActivityManagerService.finishForceStopPackageLocked(java.lang.String,int)
    // // private void finishForceStopPackageLocked(final String packageName, int uid) {
    // var finishForceStopPackageLockedFunc = ActivityManagerServiceCls.finishForceStopPackageLocked
    // console.log("finishForceStopPackageLockedFunc=" + finishForceStopPackageLockedFunc)
    // if (finishForceStopPackageLockedFunc) {
    //   finishForceStopPackageLockedFunc.implementation = function (packageName, uid) {
    //     PrintStack(ThrowableCls)
    //     return this.finishForceStopPackageLocked(packageName, uid)
    //   }
    // }

    // public void com.android.server.am.ActivityManagerService.forceStopPackage(java.lang.String,int)
    // public void forceStopPackage(final String packageName, int userId) {
    var amsForceStopPackageFunc = ActivityManagerServiceCls.forceStopPackage
    console.log("amsForceStopPackageFunc=" + amsForceStopPackageFunc)
    if (amsForceStopPackageFunc) {
      amsForceStopPackageFunc.implementation = function (packageName, userId) {
        PrintStack(ThrowableCls)
        return this.forceStopPackage(packageName, userId)
      }
    }

    // public final void com.android.server.am.ActivityManagerService.forceStopPackageLocked(java.lang.String,int,java.lang.String)
    // private void forceStopPackageLocked(final String packageName, int uid, String reason) {
    var forceStopPackageLockedFunc3 = ActivityManagerServiceCls.forceStopPackageLocked.overload('java.lang.String', 'int', 'java.lang.String')
    console.log("forceStopPackageLockedFunc3=" + forceStopPackageLockedFunc3)
    if (forceStopPackageLockedFunc3) {
      forceStopPackageLockedFunc3.implementation = function (packageName, uid, reason) {
        PrintStack(ThrowableCls)
        return this.forceStopPackageLocked(packageName, uid, reason)
      }
    }

    // public final boolean com.android.server.am.ActivityManagerService.forceStopPackageLocked(java.lang.String,int,boolean,boolean,boolean,boolean,boolean,int,java.lang.String)
    // final boolean forceStopPackageLocked(String packageName, int appId, boolean callerWillRestart, boolean purgeCache, boolean doit, boolean evenPersistent, boolean uninstalling, int userId, String reason) {
    var forceStopPackageLockedFunc9 = ActivityManagerServiceCls.forceStopPackageLocked.overload('java.lang.String', 'int', 'boolean', 'boolean', 'boolean', 'boolean', 'boolean', 'int', 'java.lang.String')
    console.log("forceStopPackageLockedFunc9=" + forceStopPackageLockedFunc9)
    if (forceStopPackageLockedFunc9) {
      forceStopPackageLockedFunc9.implementation = function (packageName, appId, callerWillRestart, purgeCache, doit, evenPersistent, uninstalling, userId, reason) {
        PrintStack(ThrowableCls)
        return this.forceStopPackageLocked(packageName, appId, callerWillRestart, purgeCache, doit, evenPersistent, uninstalling, userId, reason)
      }
    }


    // ---------------------------------------- android.app.ActivityManager
    var ActivityManagerCls = Java.use("android.app.ActivityManager")
    console.log("ActivityManagerCls=" + ActivityManagerCls)

    // public void android.app.ActivityManager.forceStopPackage(java.lang.String)
    // public void forceStopPackage(String packageName) {
    var amForceStopPackageFunc = ActivityManagerCls.forceStopPackage
    console.log("amForceStopPackageFunc=" + amForceStopPackageFunc)
    if (amForceStopPackageFunc) {
      amForceStopPackageFunc.implementation = function (packageName) {
        PrintStack(ThrowableCls)
        return this.forceStopPackage(packageName)
      }
    }

    // // ---------------------------------------- com.android.server.wm.ActivityStarter
    // var ActivityStarterCls = Java.use("com.android.server.wm.ActivityStarter")
    // console.log("ActivityStarterCls=" + ActivityStarterCls)

    // var executeRequestFunc = ActivityStarterCls.executeRequest
    // // var executeRequestFunc = ActivityStarterCls._executeRequest
    // console.log("executeRequestFunc=" + executeRequestFunc)
    // if (executeRequestFunc) {
    //   executeRequestFunc.implementation = function (request) {
    //     // 打印当前调用堆栈信息
    //     let newThrowable = Throwable.$new()
    //     console.log("newThrowable=" + newThrowable)
    //     let stackStr = curLog.getStackTraceString(newThrowable)
    //     console.log("stackStr=" + stackStr)
    //     return this.executeRequest(request)
    //   }
    // }

    // // public void android.app.ActivityManager.forceStopPackageAsUser(java.lang.String,int)
    // // public void forceStopPackageAsUser(String packageName, int userId) {
    // var forceStopPackageAsUserFunc = ActivityManagerCls.forceStopPackageAsUser
    // console.log("forceStopPackageAsUserFunc=" + forceStopPackageAsUserFunc)
    // if (forceStopPackageAsUserFunc) {
    //   forceStopPackageAsUserFunc.implementation = function (packageName, userId) {
    //     PrintStack(ThrowableCls)
    //     return this.forceStopPackageAsUser(packageName, userId)
    //   }
    // }


    // // ---------------------------------------- com.android.server.pm.Settings
    // var SettingsCls = Java.use("com.android.server.pm.Settings")
    // console.log("SettingsCls=" + SettingsCls)

    // /* static @NonNull PackageSetting createNewSetting(
    //         String pkgName,
    //         PackageSetting originalPkg,
    //         PackageSetting disabledPkg,
    //         String realPkgName,
    //         SharedUserSetting sharedUser,
    //         File codePath,
    //         String legacyNativeLibraryPath,
    //         String primaryCpuAbi,
    //         String secondaryCpuAbi,
    //         long versionCode,
    //         int pkgFlags,
    //         int pkgPrivateFlags,
    //         UserHandle installUser,
    //         boolean allowInstall,
    //         boolean instantApp,
    //         boolean virtualPreload,
    //         UserManagerService userManager,
    //         String[] usesSdkLibraries,
    //         long[] usesSdkLibrariesVersions,
    //         String[] usesStaticLibraries,
    //         long[] usesStaticLibrariesVersions,
    //         Set<String> mimeGroupNames,
    //         @NonNull UUID domainSetId
    //     ) {
    // */

    // var createNewSettingFunc = SettingsCls.createNewSetting
    // console.log("createNewSettingFunc=" + createNewSettingFunc)
    // if (createNewSettingFunc) {
    //   createNewSettingFunc.implementation = function (pkgName, originalPkg, disabledPkg, realPkgName, sharedUser, codePath, legacyNativeLibraryPath, primaryCpuAbi, secondaryCpuAbi, versionCode, pkgFlags, pkgPrivateFlags, installUser, allowInstall, instantApp, virtualPreload, userManager, usesSdkLibraries, usesStaticLibraries, usesStaticLibrariesVersions, mimeGroupNames, domainSetId) {
    //     PrintStack(ThrowableCls)
    //     return this.createNewSetting(pkgName, originalPkg, disabledPkg, realPkgName, sharedUser, codePath, legacyNativeLibraryPath, primaryCpuAbi, secondaryCpuAbi, versionCode, pkgFlags, pkgPrivateFlags, installUser, allowInstall, instantApp, virtualPreload, userManager, usesSdkLibraries, usesStaticLibraries, usesStaticLibrariesVersions, mimeGroupNames, domainSetId)
    //   }
    // }

  })
}

setImmediate(hookForceStop)
```
