plugins {
    `java-library`
}

group = "org.cachix"

version = providers.gradleProperty("secretspec.version").get()

base {
    archivesName.set("secretspec-jvm")
}

java {
    toolchain {
        languageVersion.set(JavaLanguageVersion.of(11))
    }
    withSourcesJar()
    withJavadocJar()
}

repositories {
    mavenCentral()
}

dependencies {
    val jnaVersion = "5.19.1"
    val jacksonVersion = "2.21.5"
    val junitVersion = "5.14.4"
    val junitPlatformVersion = "1.14.4"
    val assertjVersion = "3.27.7"

    implementation("net.java.dev.jna:jna:$jnaVersion")
    implementation("com.fasterxml.jackson.core:jackson-databind:$jacksonVersion")

    testImplementation("org.junit.jupiter:junit-jupiter-api:$junitVersion")
    testImplementation("org.assertj:assertj-core:$assertjVersion")

    testRuntimeOnly("org.junit.jupiter:junit-jupiter-engine:$junitVersion")
    testRuntimeOnly("org.junit.platform:junit-platform-launcher:$junitPlatformVersion")
}

tasks.test {
    useJUnitPlatform()
    testLogging {
        events("passed", "skipped", "failed")
    }
}

tasks.named<Jar>("sourcesJar") {
    exclude("**/*.so")
    exclude("**/*.dll")
    exclude("**/*.dylib")
}