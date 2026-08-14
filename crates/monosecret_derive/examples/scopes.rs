use monosecret::Secrets;

fn main() -> Result<(), Box<dyn std::error::Error>> {
	let mut spec = Secrets::load()?;
	spec.set_scope("api");

	let resolved = spec.resolve()?;
	assert_eq!(resolved.scope.as_deref(), Some("api"));

	Ok(())
}
