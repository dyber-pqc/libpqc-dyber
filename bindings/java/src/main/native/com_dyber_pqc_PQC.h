/*
 * libpqc-dyber - Post-Quantum Cryptography Library
 * Copyright (c) 2024-2026 Dyber, Inc.
 * SPDX-License-Identifier: Apache-2.0 OR MIT
 *
 * JNI header for com.dyber.pqc.PQC native methods.
 */

#ifndef COM_DYBER_PQC_PQC_H
#define COM_DYBER_PQC_PQC_H

#include <jni.h>

#ifdef __cplusplus
extern "C" {
#endif

/* ---- Library lifecycle ---- */
JNIEXPORT jint JNICALL Java_com_dyber_pqc_PQC_nativeInit(JNIEnv *, jclass);
JNIEXPORT void JNICALL Java_com_dyber_pqc_PQC_nativeCleanup(JNIEnv *, jclass);

/* ---- Version ---- */
JNIEXPORT jstring JNICALL Java_com_dyber_pqc_PQC_nativeVersion(JNIEnv *, jclass);
JNIEXPORT jint JNICALL Java_com_dyber_pqc_PQC_nativeVersionMajor(JNIEnv *, jclass);
JNIEXPORT jint JNICALL Java_com_dyber_pqc_PQC_nativeVersionMinor(JNIEnv *, jclass);
JNIEXPORT jint JNICALL Java_com_dyber_pqc_PQC_nativeVersionPatch(JNIEnv *, jclass);
JNIEXPORT jstring JNICALL Java_com_dyber_pqc_PQC_nativeStatusString(JNIEnv *, jclass, jint);

/* ---- Algorithm enumeration ---- */
JNIEXPORT jint JNICALL Java_com_dyber_pqc_PQC_nativeKemAlgorithmCount(JNIEnv *, jclass);
JNIEXPORT jstring JNICALL Java_com_dyber_pqc_PQC_nativeKemAlgorithmName(JNIEnv *, jclass, jint);
JNIEXPORT jboolean JNICALL Java_com_dyber_pqc_PQC_nativeKemIsEnabled(JNIEnv *, jclass, jstring);
JNIEXPORT jint JNICALL Java_com_dyber_pqc_PQC_nativeSigAlgorithmCount(JNIEnv *, jclass);
JNIEXPORT jstring JNICALL Java_com_dyber_pqc_PQC_nativeSigAlgorithmName(JNIEnv *, jclass, jint);
JNIEXPORT jboolean JNICALL Java_com_dyber_pqc_PQC_nativeSigIsEnabled(JNIEnv *, jclass, jstring);

/* ---- Random ---- */
JNIEXPORT jbyteArray JNICALL Java_com_dyber_pqc_PQC_nativeRandomBytes(JNIEnv *, jclass, jint);

/* ---- KEM ---- */
JNIEXPORT jlong JNICALL Java_com_dyber_pqc_PQC_nativeKemNew(JNIEnv *, jclass, jstring);
JNIEXPORT void JNICALL Java_com_dyber_pqc_PQC_nativeKemFree(JNIEnv *, jclass, jlong);
JNIEXPORT jstring JNICALL Java_com_dyber_pqc_PQC_nativeKemAlgorithm(JNIEnv *, jclass, jlong);
JNIEXPORT jint JNICALL Java_com_dyber_pqc_PQC_nativeKemPublicKeySize(JNIEnv *, jclass, jlong);
JNIEXPORT jint JNICALL Java_com_dyber_pqc_PQC_nativeKemSecretKeySize(JNIEnv *, jclass, jlong);
JNIEXPORT jint JNICALL Java_com_dyber_pqc_PQC_nativeKemCiphertextSize(JNIEnv *, jclass, jlong);
JNIEXPORT jint JNICALL Java_com_dyber_pqc_PQC_nativeKemSharedSecretSize(JNIEnv *, jclass, jlong);
JNIEXPORT jint JNICALL Java_com_dyber_pqc_PQC_nativeKemSecurityLevel(JNIEnv *, jclass, jlong);
JNIEXPORT jobjectArray JNICALL Java_com_dyber_pqc_PQC_nativeKemKeygen(JNIEnv *, jclass, jlong);
JNIEXPORT jobjectArray JNICALL Java_com_dyber_pqc_PQC_nativeKemEncaps(JNIEnv *, jclass, jlong, jbyteArray);
JNIEXPORT jbyteArray JNICALL Java_com_dyber_pqc_PQC_nativeKemDecaps(JNIEnv *, jclass, jlong, jbyteArray, jbyteArray);

/* ---- Signature ---- */
JNIEXPORT jlong JNICALL Java_com_dyber_pqc_PQC_nativeSigNew(JNIEnv *, jclass, jstring);
JNIEXPORT void JNICALL Java_com_dyber_pqc_PQC_nativeSigFree(JNIEnv *, jclass, jlong);
JNIEXPORT jstring JNICALL Java_com_dyber_pqc_PQC_nativeSigAlgorithm(JNIEnv *, jclass, jlong);
JNIEXPORT jint JNICALL Java_com_dyber_pqc_PQC_nativeSigPublicKeySize(JNIEnv *, jclass, jlong);
JNIEXPORT jint JNICALL Java_com_dyber_pqc_PQC_nativeSigSecretKeySize(JNIEnv *, jclass, jlong);
JNIEXPORT jint JNICALL Java_com_dyber_pqc_PQC_nativeSigMaxSignatureSize(JNIEnv *, jclass, jlong);
JNIEXPORT jint JNICALL Java_com_dyber_pqc_PQC_nativeSigSecurityLevel(JNIEnv *, jclass, jlong);
JNIEXPORT jboolean JNICALL Java_com_dyber_pqc_PQC_nativeSigIsStateful(JNIEnv *, jclass, jlong);
JNIEXPORT jobjectArray JNICALL Java_com_dyber_pqc_PQC_nativeSigKeygen(JNIEnv *, jclass, jlong);
JNIEXPORT jbyteArray JNICALL Java_com_dyber_pqc_PQC_nativeSigSign(JNIEnv *, jclass, jlong, jbyteArray, jbyteArray);
JNIEXPORT jint JNICALL Java_com_dyber_pqc_PQC_nativeSigVerify(JNIEnv *, jclass, jlong, jbyteArray, jbyteArray, jbyteArray);

#ifdef __cplusplus
}
#endif

#endif /* COM_DYBER_PQC_PQC_H */
