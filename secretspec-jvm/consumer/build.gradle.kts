plugins {
    `java`
}

group = "org.cachix"

version = providers.gradleProperty("secretspec.version").get()

val secretspecJar = providers.gradleProperty("secretspec.jar")

repositories {
    mavenCentral()
}

dependencies {
    val jnaVersion = "5.19.1"
    val junitVersion = "5.14.4"
    val junitPlatformVersion = "1.14.4"
    val assertjVersion = "3.27.7"

    if (secretspecJar.isPresent) {
        val multiPlatformJarFile = file(secretspecJar.get())
        testImplementation(files(multiPlatformJarFile))
    }

    testImplementation("net.java.dev.jna:jna:$jnaVersion")
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

tasks.jar {
    enabled = false
}