package com.example.sk_app

import android.os.Bundle
import android.text.Editable
import android.text.TextWatcher
import android.widget.Button
import android.widget.EditText
import androidx.appcompat.app.AppCompatActivity
import io.swagger.client.apis.DefaultApi
import io.swagger.client.models.BalanceInitData
import io.swagger.client.models.OnlineTransactionData
import io.swagger.client.models.ProcessingData
import io.swagger.client.models.ProvisioningData
import java.nio.ByteBuffer
import java.nio.ByteOrder


class MainActivity : AppCompatActivity() {

    private val sep = "----------------------------------------"
    private val provToken: String = "RVHgVz6pR2PveyDuSym9U8EVpGtygUGqfqq744Fv8Jg="
    private val baseURL: String = "http://192.168.1.110:8000"

    private lateinit var logTextBox: EditText

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_main)

        logTextBox = findViewById(R.id.logTextBox)
        logTextBox.addTextChangedListener(object : TextWatcher {
            override fun afterTextChanged(s: Editable?) {
                logTextBox.setSelection(logTextBox.text.length)
            }

            override fun beforeTextChanged(s: CharSequence?, start: Int, count: Int, after: Int) {}
            override fun onTextChanged(s: CharSequence?, start: Int, before: Int, count: Int) {}
        })

        val provisionButton: Button = findViewById(R.id.provisionButton)
        provisionButton.setOnClickListener {
            addLog(sep)
            addLog("Provision secure kernel.")
            provision()
        }

        val initializeButton: Button = findViewById(R.id.initializeButton)
        initializeButton.setOnClickListener {
            addLog(sep)
            addLog("Initialize secure kernel balance.")
            balanceInit()
        }

        val onlineTXButton: Button = findViewById(R.id.onlineTXButton)
        onlineTXButton.setOnClickListener {
            addLog(sep)
            addLog("Create online session.")
            onlineSession()
        }

        val statusButton: Button = findViewById(R.id.statusButton)
        statusButton.setOnClickListener {
            addLog(sep)
            addLog("Get secure kernel state:")
            // Catch exception in case of error.
            try {
                val state = getSKState()
                addLog("State: ${state.valName} : ${state.valDescription}")

            } catch (e: Exception) {
                addLog("Error: $e")
            }
        }
    }

    // Add log message to logTextBox.
    private fun addLog(message: String) {
        runOnUiThread { logTextBox.append("$message\n") }
    }

    // Dump byte array to log with 16 bytes per line and print ASCII characters.
    private fun dumpByteArray(name: String, data: ByteArray, offset: Int = 0, length: Int = data.size) {
        val sb = StringBuilder()
        sb.append("$name: ")
        for (i in offset until offset + length) {
            if (i % 16 == 0) {
                sb.append("\n")
                sb.append(String.format("%04x: ", i))
            }
            sb.append(String.format("%02x ", data[i]))
        }
        sb.append("\n")
        for (i in offset until offset + length) {
            if (i % 16 == 0) {
                sb.append("\n")
                sb.append(String.format("%04x: ", i))
            }
            val c = data[i].toInt().toChar()
            if (c in ' '..'~') {
                sb.append(c)
            } else {
                sb.append('.')
            }
        }
        addLog(sb.toString())
    }

    // Provision
    private fun provision() {

        Thread(Runnable {
            try {
                provisionInternal()
            } catch (e: Exception) {
                addLog("Error: $e")
            }
        }).start()
    }

    // Provision internal
    private fun provisionInternal() {

        // Call SK API.
        val token = android.util.Base64.decode(provToken, android.util.Base64.URL_SAFE)
        val outData = callSKAPI(SKCommand.SkCmdOnline, token, 1024)

        // Call API.
        val api = DefaultApi(baseURL)
        val dataB64 = android.util.Base64.encodeToString(outData.array(), android.util.Base64.URL_SAFE)
        val result = api.provisionApiV1ProvisionPost(ProvisioningData(token=provToken, data=dataB64))

        // Process loop
        processLoop(api, result as Map<*, *>)

        // Send receipt
        sendReceipt(api, result)

        // Done
        addLog("Provision done.")
    }

    // Balance init
    private fun balanceInit() {

        Thread(Runnable {
            try {
                balanceInitInternal()
            } catch (e: Exception) {
                addLog("Error: $e")
            }
        }).start()
    }

    // Balance init internal
    private fun balanceInitInternal() {

        // Call SK API.
        val outData = callSKAPI(SKCommand.SkCmdOnline, byteArrayOf(), 1024)

        // Call API.
        val api = DefaultApi(baseURL)
        val dataB64 = android.util.Base64.encodeToString(outData.array(), android.util.Base64.URL_SAFE)
        val result = api.initApiV1InitPost(BalanceInitData(token=provToken, data=dataB64))

        // Process loop
        processLoop(api, result as Map<*, *>)

        // Send receipt
        sendReceipt(api, result)

        // Done
        addLog("Balance init done.")
    }

    // Online session
    private fun onlineSession() {

        Thread(Runnable {
            try {
                onlineSessionInternal()
            } catch (e: Exception) {
                addLog("Error: $e")
            }
        }).start()
    }

    // Online session internal
    private fun onlineSessionInternal() {

        // Call SK API.
        val outData = callSKAPI(SKCommand.SkCmdOnline, byteArrayOf(), 1024)

        // Call API.
        val api = DefaultApi(baseURL)
        val dataB64 = android.util.Base64.encodeToString(outData.array(), android.util.Base64.URL_SAFE)
        val result = api.onlineApiV1OnlinePost(OnlineTransactionData(token=provToken, data=dataB64))

        // Process loop
        processLoop(api, result as Map<*, *>)

        // Done
        addLog("Session ID: ${result["session_id"]}")
        addLog("Online session creation done.")
    }

    // Process loop
    private fun processLoop(api: DefaultApi, result: Map<*, *>) {

        // Parse result JSON.
        val sessionId = result["session_id"] as String
        val dataB64 = result["data"] as String
        val dataBytes = android.util.Base64.decode(dataB64, android.util.Base64.URL_SAFE)

        // Call SK API.
        var outData = callSKAPI(SKCommand.SkCmdProcessMsg, dataBytes, 2048)

        // Loop
        while (outData.array().isNotEmpty()) {

            // Call API.
            val dataInB64 = android.util.Base64.encodeToString(outData.array(), android.util.Base64.URL_SAFE)
            val result2 = api.processApiV1ProcessPost(ProcessingData(session_id=sessionId, data=dataInB64)) as Map<*, *>

            // Parse JSON result.
            val dataOutB64 = result2["data"] as String
            val dataOutBytes = android.util.Base64.decode(dataOutB64, android.util.Base64.URL_SAFE)

            // Call SK API.
            outData = callSKAPI(SKCommand.SkCmdProcessMsg, dataOutBytes, 2048)
        }
    }

    // Send receipt
    private fun sendReceipt(api: DefaultApi, result: Map<*, *>) {

        // Get session ID
        val sessionId = result["session_id"] as String

        // Generate base64 encoded 32 bytes random receipt
        val receipt = android.util.Base64.encodeToString(generateRandomBytes(32), android.util.Base64.URL_SAFE)

        // Call API.
        api.processApiV1ProcessPost(ProcessingData(session_id=sessionId, data=receipt))
    }

    // Generate random bytes
    private fun generateRandomBytes(i: Int): ByteArray? {
        val bytes = ByteArray(i)
        val random = java.security.SecureRandom()
        random.nextBytes(bytes)
        return bytes
    }


    // Convert a four bytes little endian int buffer to long
    private fun littleEndianToLong(buffer: ByteArray, offset: Int): Long {

        val value = (buffer[offset + 0].toULong() and 0xFFu) or
                ((buffer[offset + 1].toULong() and 0xFFu) shl 8) or
                ((buffer[offset + 2].toULong() and 0xFFu) shl 16) or
                ((buffer[offset + 3].toULong() and 0xFFu) shl 24)

        return value.toLong()
    }

    // Get secure kernel state
    private fun getSKState(): SKState {
        val outData = callSKAPI(SKCommand.SkCmdStatus, byteArrayOf(), 16)
        dumpByteArray("outData", outData.array(), 0, 4)
        val stateValue = littleEndianToLong(outData.array(), 0)
        return SKState.fromValue(stateValue)!!
    }

    // Process error code
    private fun processError(errorBlob: ByteArray) {

        // Error code
        val errorCode = littleEndianToLong(errorBlob, 4)
        val skError = SKError.fromValue(errorCode)
        val errorMsg = if (skError != null) "SK error: ${skError.valName} : ${skError.valDescription}" else "Unknown error: $errorCode"
        throw Exception(errorMsg)
    }

    // Call skCall() from C++.
    private fun callSKAPI(command: SKCommand, inData: ByteArray, length: Int): ByteBuffer {

        // Allocate and build input buffer from command and inData (if not empty).
        val inLen = 4 + inData.size
        val inBuffer = ByteBuffer.allocate(inLen)
        inBuffer.order(ByteOrder.LITTLE_ENDIAN)
        inBuffer.putInt(command.valValue.toInt())

        // Copy inData to input buffer.
        if (inData.isNotEmpty()) {
            inBuffer.put(inData)
        }

        // Allocate output buffer.
        val outBuffer = ByteBuffer.allocate(length)
        outBuffer.order(ByteOrder.LITTLE_ENDIAN)
        val outLen = intArrayOf(length)

        // Call skCall() from C++.
        skCall(inBuffer.array(), inLen, outBuffer.array(), outLen)

        // Ger out data length
        val outDataLen = outLen[0]

        // Check for error.
        if (outDataLen == 8) {

            // Process error code.
            processError(outBuffer.array())
        }

        // Get out data.
        val outData = ByteBuffer.allocate(outDataLen)
        outData.order(ByteOrder.LITTLE_ENDIAN)
        outData.put(outBuffer.array(), 0, outDataLen)

        return outData
    }

    private external fun skCall(inData: ByteArray, inLen: Int, outData: ByteArray, outLen: IntArray): Unit

    // Load the native library on application startup
    companion object {
        init {
            System.loadLibrary("sk_app")
        }
    }
}
