---
"dart:monosecret_builder": breaking
---

# Move the Dart builder package entrypoint

Expose the builder factory from `package:monosecret_builder/monosecret_builder.dart`, update `build.yaml` to use that package-named library, and remove the previous `package:monosecret_builder/builder.dart` entrypoint. Consumers importing the builder directly should update to the new package-named library.
