/*
 * libpqc-dyber - Post-Quantum Cryptography Library
 * Copyright (c) 2024-2026 Dyber, Inc.
 * SPDX-License-Identifier: Apache-2.0 OR MIT
 */

plugins {
    kotlin("jvm") version "1.9.22"
    `java-library`
    `maven-publish`
}

group = "com.dyber"
version = "1.0.0"

repositories {
    mavenCentral()
}

dependencies {
    // Uses the Java JNI bindings from the Java binding module
    implementation(project(":bindings:java"))
    testImplementation(kotlin("test"))
}

java {
    sourceCompatibility = JavaVersion.VERSION_11
    targetCompatibility = JavaVersion.VERSION_11
}

kotlin {
    jvmToolchain(11)
}

tasks.test {
    useJUnitPlatform()
}

publishing {
    publications {
        create<MavenPublication>("maven") {
            groupId = "com.dyber"
            artifactId = "pqc-kotlin"
            from(components["java"])

            pom {
                name.set("libpqc-dyber Kotlin Bindings")
                description.set("Kotlin wrapper for libpqc-dyber post-quantum cryptography library")
                url.set("https://github.com/dyber/libpqc-dyber")
                licenses {
                    license {
                        name.set("Apache-2.0 OR MIT")
                    }
                }
            }
        }
    }
}
