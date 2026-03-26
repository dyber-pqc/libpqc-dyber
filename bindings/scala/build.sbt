/*
 * libpqc-dyber - Post-Quantum Cryptography Library
 * Copyright (c) 2024-2026 Dyber, Inc.
 * SPDX-License-Identifier: Apache-2.0 OR MIT
 */

lazy val root = (project in file("."))
  .settings(
    name := "pqc-scala",
    organization := "com.dyber",
    version := "1.0.0",
    scalaVersion := "3.3.1",
    crossScalaVersions := Seq("2.13.12", "3.3.1"),

    libraryDependencies ++= Seq(
      "org.scalatest" %% "scalatest" % "3.2.17" % Test,
    ),

    // The Java JNI native library must be on java.library.path
    fork := true,
    javaOptions += s"-Djava.library.path=${baseDirectory.value}/../../build",

    licenses := Seq("Apache-2.0 OR MIT" -> url("https://opensource.org/licenses/Apache-2.0")),
    homepage := Some(url("https://github.com/dyber-pqc/libpqc-dyber")),
  )
