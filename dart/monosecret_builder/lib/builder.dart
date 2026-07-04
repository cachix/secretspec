import 'package:build/build.dart';
import 'package:source_gen/source_gen.dart';

import 'src/source_gen_adapter.dart';

/// Creates the Monosecret source_gen builder.
Builder monosecretBuilder(BuilderOptions options) {
  return SharedPartBuilder([MonosecretGenerator()], 'monosecret');
}
