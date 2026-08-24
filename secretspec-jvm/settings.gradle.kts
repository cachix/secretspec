rootProject.name = "secretspec-jvm"

include("library")
include("examples")

val secretspecJar = providers.gradleProperty("secretspec.jar")
if (secretspecJar.isPresent) {
    include("consumer")
}