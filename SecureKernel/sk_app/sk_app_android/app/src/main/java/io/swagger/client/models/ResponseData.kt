package io.swagger.client.models

import com.squareup.moshi.Json

// Response data class
class ResponseData {

    @Json(name = "session_id") val sessionId: String? = null
    @Json(name = "data") val responseData: String? = null
}
