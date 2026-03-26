/*
 * libpqc-dyber - Post-Quantum Cryptography Library
 * Copyright (c) 2024-2026 Dyber, Inc.
 * SPDX-License-Identifier: Apache-2.0 OR MIT
 *
 * JNI implementation for com.dyber.pqc.PQC native methods.
 */

#include "com_dyber_pqc_PQC.h"
#include <pqc/pqc.h>
#include <stdlib.h>
#include <string.h>

/* -------------------------------------------------------------------------- */
/* Helpers                                                                     */
/* -------------------------------------------------------------------------- */

static void throw_pqc_exception(JNIEnv *env, pqc_status_t status, const char *msg)
{
    jclass cls = (*env)->FindClass(env, "com/dyber/pqc/PQCException");
    if (cls == NULL) return; /* exception already pending */

    jmethodID ctor = (*env)->GetMethodID(env, cls, "<init>", "(ILjava/lang/String;)V");
    if (ctor == NULL) return;

    jstring jmsg = (*env)->NewStringUTF(env, msg ? msg : pqc_status_string(status));
    jobject exc = (*env)->NewObject(env, cls, ctor, (jint)status, jmsg);
    if (exc != NULL) {
        (*env)->Throw(env, (jthrowable)exc);
    }
}

/* Create a byte[][] array of size 2, containing two byte arrays. */
static jobjectArray make_byte_pair(JNIEnv *env,
                                   const uint8_t *a, size_t a_len,
                                   const uint8_t *b, size_t b_len)
{
    jclass byteArrayClass = (*env)->FindClass(env, "[B");
    if (byteArrayClass == NULL) return NULL;

    jobjectArray result = (*env)->NewObjectArray(env, 2, byteArrayClass, NULL);
    if (result == NULL) return NULL;

    jbyteArray ja = (*env)->NewByteArray(env, (jsize)a_len);
    if (ja == NULL) return NULL;
    (*env)->SetByteArrayRegion(env, ja, 0, (jsize)a_len, (const jbyte *)a);
    (*env)->SetObjectArrayElement(env, result, 0, ja);

    jbyteArray jb = (*env)->NewByteArray(env, (jsize)b_len);
    if (jb == NULL) return NULL;
    (*env)->SetByteArrayRegion(env, jb, 0, (jsize)b_len, (const jbyte *)b);
    (*env)->SetObjectArrayElement(env, result, 1, jb);

    return result;
}

/* -------------------------------------------------------------------------- */
/* Library lifecycle                                                           */
/* -------------------------------------------------------------------------- */

JNIEXPORT jint JNICALL Java_com_dyber_pqc_PQC_nativeInit(JNIEnv *env, jclass cls)
{
    (void)env; (void)cls;
    return (jint)pqc_init();
}

JNIEXPORT void JNICALL Java_com_dyber_pqc_PQC_nativeCleanup(JNIEnv *env, jclass cls)
{
    (void)env; (void)cls;
    pqc_cleanup();
}

/* -------------------------------------------------------------------------- */
/* Version                                                                     */
/* -------------------------------------------------------------------------- */

JNIEXPORT jstring JNICALL Java_com_dyber_pqc_PQC_nativeVersion(JNIEnv *env, jclass cls)
{
    (void)cls;
    return (*env)->NewStringUTF(env, pqc_version());
}

JNIEXPORT jint JNICALL Java_com_dyber_pqc_PQC_nativeVersionMajor(JNIEnv *env, jclass cls)
{
    (void)env; (void)cls;
    return (jint)pqc_version_major();
}

JNIEXPORT jint JNICALL Java_com_dyber_pqc_PQC_nativeVersionMinor(JNIEnv *env, jclass cls)
{
    (void)env; (void)cls;
    return (jint)pqc_version_minor();
}

JNIEXPORT jint JNICALL Java_com_dyber_pqc_PQC_nativeVersionPatch(JNIEnv *env, jclass cls)
{
    (void)env; (void)cls;
    return (jint)pqc_version_patch();
}

JNIEXPORT jstring JNICALL Java_com_dyber_pqc_PQC_nativeStatusString(JNIEnv *env, jclass cls, jint status)
{
    (void)cls;
    const char *s = pqc_status_string((pqc_status_t)status);
    return s ? (*env)->NewStringUTF(env, s) : (*env)->NewStringUTF(env, "unknown error");
}

/* -------------------------------------------------------------------------- */
/* Algorithm enumeration                                                       */
/* -------------------------------------------------------------------------- */

JNIEXPORT jint JNICALL Java_com_dyber_pqc_PQC_nativeKemAlgorithmCount(JNIEnv *env, jclass cls)
{
    (void)env; (void)cls;
    return (jint)pqc_kem_algorithm_count();
}

JNIEXPORT jstring JNICALL Java_com_dyber_pqc_PQC_nativeKemAlgorithmName(JNIEnv *env, jclass cls, jint index)
{
    (void)cls;
    const char *name = pqc_kem_algorithm_name(index);
    return name ? (*env)->NewStringUTF(env, name) : NULL;
}

JNIEXPORT jboolean JNICALL Java_com_dyber_pqc_PQC_nativeKemIsEnabled(JNIEnv *env, jclass cls, jstring algorithm)
{
    (void)cls;
    const char *alg = (*env)->GetStringUTFChars(env, algorithm, NULL);
    if (alg == NULL) return JNI_FALSE;
    jboolean result = pqc_kem_is_enabled(alg) ? JNI_TRUE : JNI_FALSE;
    (*env)->ReleaseStringUTFChars(env, algorithm, alg);
    return result;
}

JNIEXPORT jint JNICALL Java_com_dyber_pqc_PQC_nativeSigAlgorithmCount(JNIEnv *env, jclass cls)
{
    (void)env; (void)cls;
    return (jint)pqc_sig_algorithm_count();
}

JNIEXPORT jstring JNICALL Java_com_dyber_pqc_PQC_nativeSigAlgorithmName(JNIEnv *env, jclass cls, jint index)
{
    (void)cls;
    const char *name = pqc_sig_algorithm_name(index);
    return name ? (*env)->NewStringUTF(env, name) : NULL;
}

JNIEXPORT jboolean JNICALL Java_com_dyber_pqc_PQC_nativeSigIsEnabled(JNIEnv *env, jclass cls, jstring algorithm)
{
    (void)cls;
    const char *alg = (*env)->GetStringUTFChars(env, algorithm, NULL);
    if (alg == NULL) return JNI_FALSE;
    jboolean result = pqc_sig_is_enabled(alg) ? JNI_TRUE : JNI_FALSE;
    (*env)->ReleaseStringUTFChars(env, algorithm, alg);
    return result;
}

/* -------------------------------------------------------------------------- */
/* Random                                                                      */
/* -------------------------------------------------------------------------- */

JNIEXPORT jbyteArray JNICALL Java_com_dyber_pqc_PQC_nativeRandomBytes(JNIEnv *env, jclass cls, jint length)
{
    (void)cls;
    if (length <= 0) return NULL;

    uint8_t *buf = (uint8_t *)malloc((size_t)length);
    if (buf == NULL) {
        throw_pqc_exception(env, PQC_ERROR_ALLOC, "malloc failed");
        return NULL;
    }

    pqc_status_t status = pqc_randombytes(buf, (size_t)length);
    if (status != PQC_OK) {
        free(buf);
        throw_pqc_exception(env, status, NULL);
        return NULL;
    }

    jbyteArray result = (*env)->NewByteArray(env, length);
    if (result != NULL) {
        (*env)->SetByteArrayRegion(env, result, 0, length, (const jbyte *)buf);
    }
    free(buf);
    return result;
}

/* -------------------------------------------------------------------------- */
/* KEM                                                                         */
/* -------------------------------------------------------------------------- */

JNIEXPORT jlong JNICALL Java_com_dyber_pqc_PQC_nativeKemNew(JNIEnv *env, jclass cls, jstring algorithm)
{
    (void)cls;
    const char *alg = (*env)->GetStringUTFChars(env, algorithm, NULL);
    if (alg == NULL) return 0;
    PQC_KEM *kem = pqc_kem_new(alg);
    (*env)->ReleaseStringUTFChars(env, algorithm, alg);
    return (jlong)(uintptr_t)kem;
}

JNIEXPORT void JNICALL Java_com_dyber_pqc_PQC_nativeKemFree(JNIEnv *env, jclass cls, jlong handle)
{
    (void)env; (void)cls;
    PQC_KEM *kem = (PQC_KEM *)(uintptr_t)handle;
    if (kem != NULL) {
        pqc_kem_free(kem);
    }
}

JNIEXPORT jstring JNICALL Java_com_dyber_pqc_PQC_nativeKemAlgorithm(JNIEnv *env, jclass cls, jlong handle)
{
    (void)cls;
    PQC_KEM *kem = (PQC_KEM *)(uintptr_t)handle;
    const char *name = pqc_kem_algorithm(kem);
    return name ? (*env)->NewStringUTF(env, name) : NULL;
}

JNIEXPORT jint JNICALL Java_com_dyber_pqc_PQC_nativeKemPublicKeySize(JNIEnv *env, jclass cls, jlong handle)
{
    (void)env; (void)cls;
    return (jint)pqc_kem_public_key_size((PQC_KEM *)(uintptr_t)handle);
}

JNIEXPORT jint JNICALL Java_com_dyber_pqc_PQC_nativeKemSecretKeySize(JNIEnv *env, jclass cls, jlong handle)
{
    (void)env; (void)cls;
    return (jint)pqc_kem_secret_key_size((PQC_KEM *)(uintptr_t)handle);
}

JNIEXPORT jint JNICALL Java_com_dyber_pqc_PQC_nativeKemCiphertextSize(JNIEnv *env, jclass cls, jlong handle)
{
    (void)env; (void)cls;
    return (jint)pqc_kem_ciphertext_size((PQC_KEM *)(uintptr_t)handle);
}

JNIEXPORT jint JNICALL Java_com_dyber_pqc_PQC_nativeKemSharedSecretSize(JNIEnv *env, jclass cls, jlong handle)
{
    (void)env; (void)cls;
    return (jint)pqc_kem_shared_secret_size((PQC_KEM *)(uintptr_t)handle);
}

JNIEXPORT jint JNICALL Java_com_dyber_pqc_PQC_nativeKemSecurityLevel(JNIEnv *env, jclass cls, jlong handle)
{
    (void)env; (void)cls;
    return (jint)pqc_kem_security_level((PQC_KEM *)(uintptr_t)handle);
}

JNIEXPORT jobjectArray JNICALL Java_com_dyber_pqc_PQC_nativeKemKeygen(JNIEnv *env, jclass cls, jlong handle)
{
    (void)cls;
    PQC_KEM *kem = (PQC_KEM *)(uintptr_t)handle;

    size_t pk_len = pqc_kem_public_key_size(kem);
    size_t sk_len = pqc_kem_secret_key_size(kem);

    uint8_t *pk = (uint8_t *)malloc(pk_len);
    uint8_t *sk = (uint8_t *)malloc(sk_len);
    if (pk == NULL || sk == NULL) {
        free(pk); free(sk);
        throw_pqc_exception(env, PQC_ERROR_ALLOC, "malloc failed");
        return NULL;
    }

    pqc_status_t status = pqc_kem_keygen(kem, pk, sk);
    if (status != PQC_OK) {
        pqc_memzero(sk, sk_len);
        free(pk); free(sk);
        throw_pqc_exception(env, status, NULL);
        return NULL;
    }

    jobjectArray result = make_byte_pair(env, pk, pk_len, sk, sk_len);
    pqc_memzero(sk, sk_len);
    free(pk); free(sk);
    return result;
}

JNIEXPORT jobjectArray JNICALL Java_com_dyber_pqc_PQC_nativeKemEncaps(JNIEnv *env, jclass cls, jlong handle, jbyteArray jpk)
{
    (void)cls;
    PQC_KEM *kem = (PQC_KEM *)(uintptr_t)handle;

    jsize pk_len = (*env)->GetArrayLength(env, jpk);
    jbyte *pk = (*env)->GetByteArrayElements(env, jpk, NULL);
    if (pk == NULL) return NULL;

    size_t ct_len = pqc_kem_ciphertext_size(kem);
    size_t ss_len = pqc_kem_shared_secret_size(kem);

    uint8_t *ct = (uint8_t *)malloc(ct_len);
    uint8_t *ss = (uint8_t *)malloc(ss_len);
    if (ct == NULL || ss == NULL) {
        free(ct); free(ss);
        (*env)->ReleaseByteArrayElements(env, jpk, pk, JNI_ABORT);
        throw_pqc_exception(env, PQC_ERROR_ALLOC, "malloc failed");
        return NULL;
    }

    pqc_status_t status = pqc_kem_encaps(kem, ct, ss, (const uint8_t *)pk);
    (*env)->ReleaseByteArrayElements(env, jpk, pk, JNI_ABORT);

    if (status != PQC_OK) {
        pqc_memzero(ss, ss_len);
        free(ct); free(ss);
        throw_pqc_exception(env, status, NULL);
        return NULL;
    }

    jobjectArray result = make_byte_pair(env, ct, ct_len, ss, ss_len);
    pqc_memzero(ss, ss_len);
    free(ct); free(ss);
    return result;
}

JNIEXPORT jbyteArray JNICALL Java_com_dyber_pqc_PQC_nativeKemDecaps(JNIEnv *env, jclass cls, jlong handle, jbyteArray jct, jbyteArray jsk)
{
    (void)cls;
    PQC_KEM *kem = (PQC_KEM *)(uintptr_t)handle;

    jbyte *ct = (*env)->GetByteArrayElements(env, jct, NULL);
    jbyte *sk = (*env)->GetByteArrayElements(env, jsk, NULL);
    if (ct == NULL || sk == NULL) {
        if (ct) (*env)->ReleaseByteArrayElements(env, jct, ct, JNI_ABORT);
        if (sk) (*env)->ReleaseByteArrayElements(env, jsk, sk, JNI_ABORT);
        return NULL;
    }

    size_t ss_len = pqc_kem_shared_secret_size(kem);
    uint8_t *ss = (uint8_t *)malloc(ss_len);
    if (ss == NULL) {
        (*env)->ReleaseByteArrayElements(env, jct, ct, JNI_ABORT);
        (*env)->ReleaseByteArrayElements(env, jsk, sk, JNI_ABORT);
        throw_pqc_exception(env, PQC_ERROR_ALLOC, "malloc failed");
        return NULL;
    }

    pqc_status_t status = pqc_kem_decaps(kem, ss, (const uint8_t *)ct, (const uint8_t *)sk);
    (*env)->ReleaseByteArrayElements(env, jct, ct, JNI_ABORT);
    (*env)->ReleaseByteArrayElements(env, jsk, sk, JNI_ABORT);

    if (status != PQC_OK) {
        pqc_memzero(ss, ss_len);
        free(ss);
        throw_pqc_exception(env, status, NULL);
        return NULL;
    }

    jbyteArray result = (*env)->NewByteArray(env, (jsize)ss_len);
    if (result != NULL) {
        (*env)->SetByteArrayRegion(env, result, 0, (jsize)ss_len, (const jbyte *)ss);
    }
    pqc_memzero(ss, ss_len);
    free(ss);
    return result;
}

/* -------------------------------------------------------------------------- */
/* Signature                                                                   */
/* -------------------------------------------------------------------------- */

JNIEXPORT jlong JNICALL Java_com_dyber_pqc_PQC_nativeSigNew(JNIEnv *env, jclass cls, jstring algorithm)
{
    (void)cls;
    const char *alg = (*env)->GetStringUTFChars(env, algorithm, NULL);
    if (alg == NULL) return 0;
    PQC_SIG *sig = pqc_sig_new(alg);
    (*env)->ReleaseStringUTFChars(env, algorithm, alg);
    return (jlong)(uintptr_t)sig;
}

JNIEXPORT void JNICALL Java_com_dyber_pqc_PQC_nativeSigFree(JNIEnv *env, jclass cls, jlong handle)
{
    (void)env; (void)cls;
    PQC_SIG *sig = (PQC_SIG *)(uintptr_t)handle;
    if (sig != NULL) {
        pqc_sig_free(sig);
    }
}

JNIEXPORT jstring JNICALL Java_com_dyber_pqc_PQC_nativeSigAlgorithm(JNIEnv *env, jclass cls, jlong handle)
{
    (void)cls;
    PQC_SIG *sig = (PQC_SIG *)(uintptr_t)handle;
    const char *name = pqc_sig_algorithm(sig);
    return name ? (*env)->NewStringUTF(env, name) : NULL;
}

JNIEXPORT jint JNICALL Java_com_dyber_pqc_PQC_nativeSigPublicKeySize(JNIEnv *env, jclass cls, jlong handle)
{
    (void)env; (void)cls;
    return (jint)pqc_sig_public_key_size((PQC_SIG *)(uintptr_t)handle);
}

JNIEXPORT jint JNICALL Java_com_dyber_pqc_PQC_nativeSigSecretKeySize(JNIEnv *env, jclass cls, jlong handle)
{
    (void)env; (void)cls;
    return (jint)pqc_sig_secret_key_size((PQC_SIG *)(uintptr_t)handle);
}

JNIEXPORT jint JNICALL Java_com_dyber_pqc_PQC_nativeSigMaxSignatureSize(JNIEnv *env, jclass cls, jlong handle)
{
    (void)env; (void)cls;
    return (jint)pqc_sig_max_signature_size((PQC_SIG *)(uintptr_t)handle);
}

JNIEXPORT jint JNICALL Java_com_dyber_pqc_PQC_nativeSigSecurityLevel(JNIEnv *env, jclass cls, jlong handle)
{
    (void)env; (void)cls;
    return (jint)pqc_sig_security_level((PQC_SIG *)(uintptr_t)handle);
}

JNIEXPORT jboolean JNICALL Java_com_dyber_pqc_PQC_nativeSigIsStateful(JNIEnv *env, jclass cls, jlong handle)
{
    (void)env; (void)cls;
    return pqc_sig_is_stateful((PQC_SIG *)(uintptr_t)handle) ? JNI_TRUE : JNI_FALSE;
}

JNIEXPORT jobjectArray JNICALL Java_com_dyber_pqc_PQC_nativeSigKeygen(JNIEnv *env, jclass cls, jlong handle)
{
    (void)cls;
    PQC_SIG *sig = (PQC_SIG *)(uintptr_t)handle;

    size_t pk_len = pqc_sig_public_key_size(sig);
    size_t sk_len = pqc_sig_secret_key_size(sig);

    uint8_t *pk = (uint8_t *)malloc(pk_len);
    uint8_t *sk = (uint8_t *)malloc(sk_len);
    if (pk == NULL || sk == NULL) {
        free(pk); free(sk);
        throw_pqc_exception(env, PQC_ERROR_ALLOC, "malloc failed");
        return NULL;
    }

    pqc_status_t status = pqc_sig_keygen(sig, pk, sk);
    if (status != PQC_OK) {
        pqc_memzero(sk, sk_len);
        free(pk); free(sk);
        throw_pqc_exception(env, status, NULL);
        return NULL;
    }

    jobjectArray result = make_byte_pair(env, pk, pk_len, sk, sk_len);
    pqc_memzero(sk, sk_len);
    free(pk); free(sk);
    return result;
}

JNIEXPORT jbyteArray JNICALL Java_com_dyber_pqc_PQC_nativeSigSign(JNIEnv *env, jclass cls, jlong handle, jbyteArray jmsg, jbyteArray jsk)
{
    (void)cls;
    PQC_SIG *sig = (PQC_SIG *)(uintptr_t)handle;

    jsize msg_len = (*env)->GetArrayLength(env, jmsg);
    jbyte *msg = (*env)->GetByteArrayElements(env, jmsg, NULL);
    jbyte *sk = (*env)->GetByteArrayElements(env, jsk, NULL);
    if (msg == NULL || sk == NULL) {
        if (msg) (*env)->ReleaseByteArrayElements(env, jmsg, msg, JNI_ABORT);
        if (sk) (*env)->ReleaseByteArrayElements(env, jsk, sk, JNI_ABORT);
        return NULL;
    }

    size_t max_sig = pqc_sig_max_signature_size(sig);
    uint8_t *sig_buf = (uint8_t *)malloc(max_sig);
    if (sig_buf == NULL) {
        (*env)->ReleaseByteArrayElements(env, jmsg, msg, JNI_ABORT);
        (*env)->ReleaseByteArrayElements(env, jsk, sk, JNI_ABORT);
        throw_pqc_exception(env, PQC_ERROR_ALLOC, "malloc failed");
        return NULL;
    }

    size_t sig_len = 0;
    pqc_status_t status = pqc_sig_sign(sig, sig_buf, &sig_len,
                                        (const uint8_t *)msg, (size_t)msg_len,
                                        (const uint8_t *)sk);
    (*env)->ReleaseByteArrayElements(env, jmsg, msg, JNI_ABORT);
    (*env)->ReleaseByteArrayElements(env, jsk, sk, JNI_ABORT);

    if (status != PQC_OK) {
        free(sig_buf);
        throw_pqc_exception(env, status, NULL);
        return NULL;
    }

    jbyteArray result = (*env)->NewByteArray(env, (jsize)sig_len);
    if (result != NULL) {
        (*env)->SetByteArrayRegion(env, result, 0, (jsize)sig_len, (const jbyte *)sig_buf);
    }
    free(sig_buf);
    return result;
}

JNIEXPORT jint JNICALL Java_com_dyber_pqc_PQC_nativeSigVerify(JNIEnv *env, jclass cls, jlong handle, jbyteArray jmsg, jbyteArray jsig, jbyteArray jpk)
{
    (void)cls;
    PQC_SIG *sig = (PQC_SIG *)(uintptr_t)handle;

    jsize msg_len = (*env)->GetArrayLength(env, jmsg);
    jsize sig_len = (*env)->GetArrayLength(env, jsig);

    jbyte *msg = (*env)->GetByteArrayElements(env, jmsg, NULL);
    jbyte *sig_data = (*env)->GetByteArrayElements(env, jsig, NULL);
    jbyte *pk = (*env)->GetByteArrayElements(env, jpk, NULL);
    if (msg == NULL || sig_data == NULL || pk == NULL) {
        if (msg) (*env)->ReleaseByteArrayElements(env, jmsg, msg, JNI_ABORT);
        if (sig_data) (*env)->ReleaseByteArrayElements(env, jsig, sig_data, JNI_ABORT);
        if (pk) (*env)->ReleaseByteArrayElements(env, jpk, pk, JNI_ABORT);
        return (jint)PQC_ERROR;
    }

    pqc_status_t status = pqc_sig_verify(sig,
                                          (const uint8_t *)msg, (size_t)msg_len,
                                          (const uint8_t *)sig_data, (size_t)sig_len,
                                          (const uint8_t *)pk);

    (*env)->ReleaseByteArrayElements(env, jmsg, msg, JNI_ABORT);
    (*env)->ReleaseByteArrayElements(env, jsig, sig_data, JNI_ABORT);
    (*env)->ReleaseByteArrayElements(env, jpk, pk, JNI_ABORT);

    return (jint)status;
}
