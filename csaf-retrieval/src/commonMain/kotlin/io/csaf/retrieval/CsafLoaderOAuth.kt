/*
 * Copyright (c) 2024, The Authors. All rights reserved.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 */
package io.csaf.retrieval

import io.csaf.retrieval.CsafLoader.*
import io.ktor.client.*
import io.ktor.client.call.*
import io.ktor.client.engine.*
import io.ktor.client.plugins.HttpRequestRetry
import io.ktor.client.plugins.auth.*
import io.ktor.client.plugins.auth.providers.*
import io.ktor.client.plugins.contentnegotiation.*
import io.ktor.client.request.forms.*
import io.ktor.client.statement.*
import io.ktor.http.*
import io.ktor.serialization.kotlinx.json.*
import kotlin.time.*
import kotlin.time.Duration.Companion.seconds
import kotlinx.serialization.*

@Serializable
data class TokenData(
    @SerialName("access_token") val accessToken: String,
    @SerialName("expires_in") val expiresIn: Int,
    @SerialName("refresh_expires_in") val refreshExpiresIn: Int,
    @SerialName("token_type") val tokenType: String,
    @SerialName("id_token") val idToken: String,
    @SerialName("not-before-policy") val notBeforePolicy: Int,
    @SerialName("scope") val scope: String,
) {
    var expiration: TimeMark? = null
}

val timeSource = TimeSource.Monotonic
val expirationMargin: Duration = 10.seconds

// val defaultTokenUrl: String =
// "https://keycloak.arp.ncsc.nl/realms/ncsc-internal/protocol/openid-connect/token"
val defaultTokenUrl: String =
    "https://keycloak.nct.k8s.int.dc2.arp.ncsc.nl/sp/realms/External/protocol/openid-connect/token"
val defaultScope: String = "openid"
val testClientId: String = "dc323c0b-5c27-4b9c-93c7-8a9b379d152f"
val testClientSecret: String = "3o66ORVFOP53thNLLMRjYw9JtO7Fab4P"

var tokenData: TokenData? = null

/**
 * Creates an [HttpClient] with OAuth, retry logic and JSON support.
 *
 * @param engine The HTTP engine to use. Defaults to [defaultHttpClientEngine].
 * @param maxRetries The number of times that HTTP requests are retried on errors.
 * @param retryBase The exponent for exponential delay.
 * @param retryBaseDelayMs Base delay in ms.
 * @param retryMaxDelayMs Max delay in ms.
 * @param clientId Client id string
 * @param clientSecret Client authentication token asscociated with id above.
 * @param tokenUrl Url to the OAuth provider
 * @param scope Features to request access to. Machine - machine connections normally require
 *   'openid'
 * @return Configured [HttpClient].
 */
@JvmOverloads
fun httpClientOAuth(
    engine: HttpClientEngine = defaultHttpClientEngine(),
    maxRetries: Int = 3,
    retryBase: Double = 2.0,
    retryBaseDelayMs: Long = 1000,
    retryMaxDelayMs: Long = 60000,
    clientId: String = testClientId,
    clientSecret: String = testClientSecret,
    tokenUrl: String = defaultTokenUrl,
    scope: String = defaultScope,
): HttpClient {
    return HttpClient(engine) {
        expectSuccess = true

        install(Auth) {
            bearer {
                loadTokens { tokenData?.let { BearerTokens(it.accessToken, null) } }
                refreshTokens {
                    val res: HttpResponse =
                        client.submitForm(
                            url = tokenUrl,
                            formParameters =
                                parameters {
                                    append("grant_type", "client_credentials")
                                    append("scope", scope)
                                    append("client_id", clientId)
                                    append("client_secret", clientSecret)
                                },
                        )
                    tokenData = res.body<TokenData>()
                    tokenData?.let {
                        it.expiration =
                            timeSource.markNow() + it.expiresIn.seconds - expirationMargin
                        BearerTokens(it.accessToken, null)
                    }
                }
                sendWithoutRequest {
                    tokenData == null || (tokenData?.expiration?.hasPassedNow() ?: false)
                }
            }
        }

        install(ContentNegotiation) { json() }

        install(HttpRequestRetry) {
            retryOnServerErrors(maxRetries = maxRetries)
            // Retry on HTTP Too Many Requests
            retryIf(maxRetries = maxRetries) { _, response -> response.status.value == 429 }
            // Use exponential backoff
            exponentialDelay(
                base = retryBase,
                baseDelayMs = retryBaseDelayMs,
                maxDelayMs = retryMaxDelayMs,
            )
        }
    }
}

fun CsafLoader.enableOAuth(
    clientId: String = testClientId,
    clientSecret: String = testClientSecret,
    tokenUrl: String = defaultTokenUrl,
    scope: String = defaultScope,
) { // Return value?
    val client =
        this.getHttpClient().config { // DRY?
            install(Auth) {
                bearer {
                    loadTokens { tokenData?.let { BearerTokens(it.accessToken, null) } }
                    refreshTokens {
                        val res: HttpResponse =
                            client.submitForm(
                                url = tokenUrl,
                                formParameters =
                                    parameters {
                                        append("grant_type", "client_credentials")
                                        append("scope", scope)
                                        append("client_id", clientId)
                                        append("client_secret", clientSecret)
                                    },
                            )
                        tokenData = res.body<TokenData>()
                        tokenData?.let {
                            it.expiration =
                                timeSource.markNow() + it.expiresIn.seconds - expirationMargin
                            BearerTokens(it.accessToken, null)
                        }
                    }
                    sendWithoutRequest {
                        tokenData == null || (tokenData?.expiration?.hasPassedNow() ?: false)
                    }
                }
            }
        }
    this.setHttpClient(client)
}

fun CsafLoader.disableOAuth() {
    this.setHttpClient(defaultHttpClient())
}
