plugins {
    `java-library`
    `maven-publish`
}

group = "org.cachix"

version = providers.gradleProperty("secretspec.version").get()

publishing {
    publications {
        create<MavenPublication>("maven") {
            from(components["java"])

            artifactId = "secretspec-jvm"
            version = project.version.toString().removeSuffix("-SNAPSHOT")

            pom {
                name.set("SecretSpec JVM SDK")
                description.set("JVM SDK for SecretSpec secret resolution")
                url.set("https://secretspec.dev")
                scm {
                    connection.set("scm:git:https://github.com/cachix/secretspec.git")
                    developerConnection.set("scm:git:ssh://github.com/cachix/secretspec.git")
                    url.set("https://github.com/cachix/secretspec")
                }
                licenses {
                    license {
                        name.set("Apache-2.0")
                        url.set("https://www.apache.org/licenses/LICENSE-2.0.txt")
                    }
                }
                developers {
                    developer {
                        id.set("cachix-oss")
                        name.set("Cachix Team & Open-Source Contributors")
                        organization.set("Cachix")
                        organizationUrl.set("https://www.cachix.org")
                    }
                }
                issueManagement {
                    system.set("GitHub Issues")
                    url.set("https://github.com/cachix/secretspec/issues")
                }
                ciManagement {
                    system.set("GitHub Actions")
                    url.set("https://github.com/cachix/secretspec/actions")
                }
            }
        }
    }
}

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

tasks.named<Jar>("jar") {
    manifest {
        attributes["Automatic-Module-Name"] = "org.cachix.secretspec"
    }
}

tasks.named<Jar>("sourcesJar") {
    exclude("**/*.so")
    exclude("**/*.dll")
    exclude("**/*.dylib")
}
