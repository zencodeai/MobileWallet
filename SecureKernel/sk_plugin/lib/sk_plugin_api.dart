
import 'dart:ffi';
import 'dart:typed_data';

import 'package:ffi/ffi.dart';

import 'sk_plugin_consts.dart';
import 'sk_plugin.dart';


/// SkNativeDataBuffer States enumeration
enum SkNativeDataBufferState {
  /// Not initialized
  uninitialized,
  /// Initialized
  initialized,
  /// Cleared
  cleared,
}

/// Binary data buffer
class SkNativeDataBuffer {

  /// Object state
  SkNativeDataBufferState _state = SkNativeDataBufferState.uninitialized;

  /// Pointer to native heap memory
  Pointer<Uint8> _data;

  /// Native heap memory size
  Size _dataSize;

  /// Constructor (allocates native heap memory)
  SkNativeDataBuffer(this._dataSize, [Pointer<Uint8>? data])
    : _data = data ?? calloc.allocate<Uint8>(_dataSize as int),
      _state = SkNativeDataBufferState.initialized;

  /// Clear native heap memory
  void clear() {
    if (_state == SkNativeDataBufferState.initialized) {
      calloc.free(_data);
      _data = nullptr;
      _dataSize = 0 as Size;
      _state = SkNativeDataBufferState.cleared;
    }
  }
}

/// Input buffer data class
class SkNativeDataBufferIn extends SkNativeDataBuffer {

  /// Constructor (initialize from byte array)
  SkNativeDataBufferIn(SKCommand command, ByteData data) : super((4 + data.lengthInBytes) as Size, nullptr) {
    // Create buffer
    ByteData buffer = ByteData(_dataSize as int);
    // Set command
    buffer.setUint32(0, command.value, Endian.little);
    // Set bytes
    buffer.buffer.asUint8List().setRange(4, buffer.lengthInBytes, data.buffer.asUint8List());
    // Set allocated memory
    _data.asTypedList(_dataSize as int).setAll(0, buffer.buffer.asUint8List());
  }
}

/// Output buffer data class
class SkNativeDataBufferOut extends SkNativeDataBuffer {

  /// Pointer to Size object
  late Pointer<Size> _dataSizeP;

  /// Constructor (allocate ouput buffer)
  SkNativeDataBufferOut(Size size) : super(size, nullptr) {
    
    // Allocate Size object
    _dataSizeP = calloc.allocate<Size>(1);
    // Set Size object
    _dataSizeP.value = size as int;
  }

  /// Get output buffer data
  ByteData get data {

    // Throw exception if not initialized
    if (_state != SkNativeDataBufferState.initialized) {
      throw Exception('SkNativeDataBufferOut not initialized');
    }

    // Create buffer
    ByteData buffer = ByteData(_dataSizeP.value);
    // Set bytes
    buffer.buffer.asUint8List().setRange(0, buffer.lengthInBytes, _data.asTypedList(_dataSizeP.value));
    // Return buffer
    return buffer;
  }

  /// Clear native heap memory
  @override
  void clear() {
    if (_state == SkNativeDataBufferState.initialized) {
      // Free Size object
      calloc.free(_dataSizeP);
      _dataSizeP = nullptr;
      // Free native heap memory
      super.clear();
    }
  }
}

/// Secure kernel plugin API class
class SkAPI {

  /// Constructor
  SkAPI();

  /// Call native function
  ByteData skCall(SKCommand command, ByteData data, int outBufferSize) {

    // Create input buffer
    SkNativeDataBufferIn dataIn = SkNativeDataBufferIn(command, data);
    // Create output buffer
    SkNativeDataBufferOut dataOut = SkNativeDataBufferOut(outBufferSize as Size);

    // Call native function
    skCallNative(dataIn._data as Pointer<UnsignedChar>, dataIn._dataSize as int, dataOut._data as Pointer<UnsignedChar>, dataOut._dataSizeP);

    // Output buffer size
    int outSize = dataOut._dataSizeP.value;

    // Get output buffer data, get only the first outSize bytes
    ByteData dataOutBytes = outSize > 0 ? dataOut.data.buffer.asByteData(0, outSize) : ByteData(0);

    // Check for error
    if (outSize == 8) {
      // Get error code
      int errorCode = dataOutBytes.getUint32(4, Endian.little);
      // Throw exception
      throw Exception('SK error: ${SKError.fromCode(errorCode).description}');
    }

    // Clear input buffer
    dataIn.clear();
    // Clear output buffer
    dataOut.clear();

    // Return output buffer data
    return dataOutBytes;
  }

  /// Get secure kernel state
  SKState skState() {

    // Call native function
    ByteData dataOut = skCall(SKCommand.skCmdStatus, ByteData(0), 256);

    // Check output buffer size
    if (dataOut.lengthInBytes != 4) {
      throw Exception('Invalid output buffer size: ${dataOut.lengthInBytes}');
    }

    // Return status
    return SKState.fromCode(dataOut.getUint32(0, Endian.little));
  }

  /// Secure kernel message exchange
  ByteData skExchange(ByteData dataIn) {

    // Call native function
    ByteData dataOut = skCall(SKCommand.skCmdProcessMsg, dataIn, 1024);

    // Return status
    return dataOut;
  }

  /// Secure Kernel provisioning
  ByteData skProvision(ByteData token) {

    // Throw exception if token is not 32 bytes
    if (token.lengthInBytes != 32) {
      throw Exception('Invalid token size: ${token.lengthInBytes}');
    }

    // Call native function
    ByteData dataOut = skCall(SKCommand.skCmdOnline, token, 1024);

    // Check output buffer size
    if (dataOut.lengthInBytes <= 8) {
      throw Exception('Invalid output buffer size: ${dataOut.lengthInBytes}');
    }

    // Return status
    return dataOut;
  }

  /// Balance initialization
  ByteData skInitBalance(ByteData token) {

    // Throw exception if token is not 32 bytes
    if (token.lengthInBytes != 32) {
      throw Exception('Invalid token size: ${token.lengthInBytes}');
    }

    // Call native function
    ByteData dataOut = skCall(SKCommand.skCmdOnline, token, 1024);

    // Check output buffer size
    if (dataOut.lengthInBytes <= 8) {
      throw Exception('Invalid output buffer size: ${dataOut.lengthInBytes}');
    }

    // Return status
    return dataOut;
  }
}
