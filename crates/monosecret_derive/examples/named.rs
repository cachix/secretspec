use monosecret::NamedResolution;
use monosecret::Secrets;

fn main() -> Result<(), Box<dyn std::error::Error>> {
	// Resolving one secret reads only that secret and its composition inputs,
	// so an unrelated missing required secret cannot fail the call.
	let spec = Secrets::load()?.with_default_reason("cache warmup");

	match spec.resolve_named("REDIS_URL")? {
		NamedResolution::Resolved(secret) => {
			// Exactly one of `value` and `path` is set; `path` for `as_path`.
			println!("resolved from {:?}", secret.source);
		}
		// Declared, but nothing provided it. `required` says whether a
		// whole-profile resolve would treat that as an error.
		NamedResolution::Missing { required } => {
			println!("no value (required: {required})");
		}
		// Not declared in this profile, or hidden by the active scope.
		NamedResolution::Undeclared => println!("not on this profile's surface"),
	}

	Ok(())
}
