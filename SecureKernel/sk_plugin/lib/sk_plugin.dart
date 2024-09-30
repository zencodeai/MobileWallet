
import 'dart:async';
import 'dart:ffi';
import 'dart:io';
import 'dart:isolate';

import 'sk_plugin_bindings_generated.dart';

/// Sync call to the native function `sk_call`.
void skCallNative(
  Pointer<UnsignedChar> dataIn, 
  int dataInLen, 
  Pointer<UnsignedChar> dataOut, 
  Pointer<Size> dataOutLenP) => _bindings.sk_call(dataIn, dataInLen, dataOut, dataOutLenP);

/// Async call to the native function `sk_call`.
Future<void> skCallNativeAsync(
  Pointer<UnsignedChar> dataIn, 
  int dataInLen, 
  Pointer<UnsignedChar> dataOut, 
  Pointer<Size> dataOutLenP) async {
  final Completer<void> completer = Completer<void>();
  final ReceivePort receivePort = ReceivePort()
    ..listen((dynamic data) {
      completer.complete();
    });
  final SendPort sendPort = receivePort.sendPort;
  await Isolate.spawn((SendPort sendPort) {
    skCallNative(dataIn, dataInLen, dataOut, dataOutLenP);
    sendPort.send(null);
  }, sendPort);
  return completer.future;
}


const String _libName = 'sk_plugin';

/// The dynamic library in which the symbols for [SkPluginBindings] can be found.
final DynamicLibrary _dylib = () {
  if (Platform.isMacOS || Platform.isIOS) {
    return DynamicLibrary.open('$_libName.framework/$_libName');
  }
  if (Platform.isAndroid || Platform.isLinux) {
    return DynamicLibrary.open('lib$_libName.so');
  }
  if (Platform.isWindows) {
    return DynamicLibrary.open('$_libName.dll');
  }
  throw UnsupportedError('Unknown platform: ${Platform.operatingSystem}');
}();

/// The bindings to the native functions in [_dylib].
final SkPluginBindings _bindings = SkPluginBindings(_dylib);
