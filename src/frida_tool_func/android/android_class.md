# Android类

## ProcessRecord

### printProcessRecord

```js
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
```

调用：

```js
    var handleProcessStartedLockedFunc = ProcessListCls.handleProcessStartedLocked.overload('com.android.server.am.ProcessRecord', 'int', 'boolean', 'long', 'boolean')
    if (handleProcessStartedLockedFunc) {
      handleProcessStartedLockedFunc.implementation = function (app, pid, usingWrapper, expectedStartSeq, procAttached) {
...
        printProcessRecord(app)
```

## Parcel

### getParcelInfo

```js
function getParcelInfo(curParcel){
  var parcelDataSize = curParcel.dataSize()
  var parcelDataCapacity = curParcel.dataCapacity()
  // var parcelDataPosition = curParcel.dataPosition()
  // var parcelInfoStr = "dataSize=" + parcelDataSize + ", dataCapacity=" + parcelDataCapacity + ", dataPositon = " + parcelDataPosition
  var parcelInfoStr = "Parcel: " + curParcel + ", dataSize=" + parcelDataSize + ", dataCapacity=" + parcelDataCapacity
  return parcelInfoStr
}
```

调用：

```js
  var dataParcelInfoStr = getParcelInfo(dataParcel)
```

### tryReadParcelString

```js
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
```

调用：

```js
    var readResultDict = tryReadParcelString(dataParcel)
    console.log("parcelStr=" + parcelStr + ", strPos=" + strPos)
    var isFoundStr = readResultDict.isFoundStr
    var strDictList = readResultDict.strDictList
    if (isFoundStr) {
      // var foundStrLog = ""
      var strDictListStr = toJsonStr(strDictList, true, 0)
```

## Intent

### printIntentInfo

```js
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
```

调用：

```js
printIntentInfo(service)
```

## TransactCode

### hookPrintTransactCodeValue

```js
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
```

调用：

```js
hookPrintTransactCodeValue()
```
