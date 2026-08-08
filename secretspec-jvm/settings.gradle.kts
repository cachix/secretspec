rootProject.name = "secretspec-jvm"

include("library")

val secretspecJar = providers.gradleProperty("secretspec.jar")
if (secretspecJar.isPresent) {
    include("consumer")
}