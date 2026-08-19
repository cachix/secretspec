plugins {
    `java`
}

group = "org.cachix"

version = providers.gradleProperty("secretspec.version").get()

repositories {
    mavenCentral()
}

dependencies {
    val jnaVersion = "5.19.1"
    val jacksonVersion = "2.21.5"

    implementation(project(":library"))
    implementation("net.java.dev.jna:jna:$jnaVersion")
    implementation("com.fasterxml.jackson.core:jackson-databind:$jacksonVersion")
}

tasks.jar {
    enabled = false
}