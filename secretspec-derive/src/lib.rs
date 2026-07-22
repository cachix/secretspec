//! # SecretSpec Derive Macros
//!
//! This crate provides procedural macros for the SecretSpec library, enabling compile-time
//! generation of strongly-typed secret structs from `secretspec.toml` configuration files.
//!
//! ## Overview
//!
//! The macro system reads your `secretspec.toml` at compile time and generates:
//! - A `SecretSpec` struct with all secrets as fields (union of all profiles)
//! - A `SecretSpecProfile` enum with profile-specific structs
//! - A `Profile` enum representing available profiles
//! - Type-safe loading methods with automatic validation
//!
//! ## Key Features
//!
//! - **Compile-time validation**: Invalid configurations are caught during compilation
//! - **Type safety**: Secrets are accessed as struct fields, not strings
//! - **Profile awareness**: Different types for different profiles (e.g., production vs development)
//! - **Builder pattern**: Flexible configuration with method chaining
//! - **Environment integration**: Automatic environment variable handling

use proc_macro::TokenStream;
use quote::{format_ident, quote};
use secretspec::Config;
use secretspec::codegen::{CodegenIr, IrField, build_ir, capitalize};
use std::collections::{BTreeMap, HashSet};
use syn::{LitStr, parse_macro_input};

/// Holds metadata about a field in the generated struct.
///
/// This struct contains all the information needed to generate:
/// - Struct field declarations
/// - Field assignments from secret maps
/// - Environment variable setters
///
/// # Fields
///
/// * `name` - The original secret name (e.g., "DATABASE_URL")
/// * `field_type` - The Rust type for this field (String, PathBuf, or Option variants)
/// * `is_optional` - Whether this field is optional across all profiles
/// * `as_path` - Whether this field represents a path to a temporary file
#[derive(Clone)]
struct FieldInfo {
    name: String,
    field_type: proc_macro2::TokenStream,
    is_optional: bool,
    as_path: bool,
}

impl FieldInfo {
    /// Creates a new FieldInfo instance.
    ///
    /// # Arguments
    ///
    /// * `name` - The secret name as defined in the config
    /// * `field_type` - The generated Rust type (String, PathBuf, or Option variants)
    /// * `is_optional` - Whether the field should be optional
    /// * `as_path` - Whether this field represents a path to a temporary file
    fn new(
        name: String,
        field_type: proc_macro2::TokenStream,
        is_optional: bool,
        as_path: bool,
    ) -> Self {
        Self {
            name,
            field_type,
            is_optional,
            as_path,
        }
    }

    /// Build a `FieldInfo` from a shared-IR field. The IR is the single source
    /// of the optionality/as_path decisions; this only maps them to a Rust type.
    fn from_ir(field: &IrField) -> Self {
        Self::new(
            field.name.clone(),
            ir_field_type(field),
            field.optional,
            field.as_path,
        )
    }

    /// Get the field name as a Rust identifier.
    ///
    /// Converts the secret name to a valid Rust field name by:
    /// - Converting to lowercase
    /// - Preserving underscores
    ///
    /// # Example
    ///
    /// - "DATABASE_URL" becomes `database_url`
    /// - "API_KEY" becomes `api_key`
    fn field_name(&self) -> proc_macro2::Ident {
        field_name_ident(&self.name)
    }

    /// Generate the struct field declaration.
    ///
    /// Creates a public field declaration for use in the generated struct.
    ///
    /// # Returns
    ///
    /// A token stream representing `pub field_name: FieldType`
    ///
    /// # Example Output
    ///
    /// ```ignore
    /// pub database_url: String
    /// pub api_key: Option<String>
    /// ```
    fn generate_struct_field(&self) -> proc_macro2::TokenStream {
        let field_name = self.field_name();
        let field_type = &self.field_type;
        quote! { pub #field_name: #field_type }
    }

    /// Generate a field assignment from a secrets map.
    ///
    /// Creates code to assign a value from a HashMap<String, String> to this field.
    /// Handles both required and optional fields appropriately.
    ///
    /// # Arguments
    ///
    /// * `source` - The token stream representing the source map (e.g., `secrets`)
    ///
    /// # Returns
    ///
    /// Token stream for the field assignment, with proper error handling for required fields
    fn generate_assignment(&self, source: proc_macro2::TokenStream) -> proc_macro2::TokenStream {
        generate_secret_assignment(
            &self.field_name(),
            &self.name,
            source,
            self.is_optional,
            self.as_path,
        )
    }

    /// Generate environment variable setter.
    ///
    /// Creates code to set an environment variable from this field's value.
    /// For optional fields, only sets the variable if a value is present.
    /// For PathBuf fields, converts to string using to_string_lossy().
    ///
    /// # Safety
    ///
    /// The generated code uses `unsafe` because `std::env::set_var` is unsafe
    /// in multi-threaded contexts. Users should ensure thread safety when calling
    /// the generated `set_as_env_vars` method.
    ///
    /// # Returns
    ///
    /// Token stream that sets the environment variable when executed
    fn generate_env_setter(&self) -> proc_macro2::TokenStream {
        let field_name = self.field_name();
        let env_name = &self.name;

        match (self.is_optional, self.as_path) {
            (true, true) => {
                // Optional PathBuf
                quote! {
                    if let Some(ref value) = self.#field_name {
                        unsafe {
                            std::env::set_var(#env_name, value.to_string_lossy().as_ref());
                        }
                    }
                }
            }
            (true, false) => {
                // Optional String
                quote! {
                    if let Some(ref value) = self.#field_name {
                        unsafe {
                            std::env::set_var(#env_name, value);
                        }
                    }
                }
            }
            (false, true) => {
                // Required PathBuf
                quote! {
                    unsafe {
                        std::env::set_var(#env_name, self.#field_name.to_string_lossy().as_ref());
                    }
                }
            }
            (false, false) => {
                // Required String
                quote! {
                    unsafe {
                        std::env::set_var(#env_name, &self.#field_name);
                    }
                }
            }
        }
    }
}

/// Profile variant information for enum generation.
///
/// Represents a profile that will become an enum variant in the generated code.
/// Handles the conversion from profile names to valid Rust enum variants.
///
/// # Fields
///
/// * `name` - The original profile name (e.g., "production", "development")
/// * `capitalized` - The capitalized variant name (e.g., "Production", "Development")
struct ProfileVariant {
    name: String,
    capitalized: String,
}

impl ProfileVariant {
    /// Creates a new ProfileVariant with automatic capitalization.
    ///
    /// # Arguments
    ///
    /// * `name` - The profile name from the configuration
    ///
    /// # Example
    ///
    /// ```ignore
    /// let variant = ProfileVariant::new("production".to_string());
    /// // variant.name == "production"
    /// // variant.capitalized == "Production"
    /// ```
    fn new(name: String) -> Self {
        let capitalized = capitalize(&name);
        Self { name, capitalized }
    }

    /// Convert the variant to a Rust identifier.
    ///
    /// # Returns
    ///
    /// A proc_macro2::Ident suitable for use as an enum variant
    fn as_ident(&self) -> proc_macro2::Ident {
        format_ident!("{}", self.capitalized)
    }
}

/// Generates typed SecretSpec structs from your secretspec.toml file.
///
/// # Example
/// ```ignore
/// // In your main.rs or lib.rs:
/// secretspec_derive::declare_secrets!("secretspec.toml");
///
/// use secretspec::Provider;
///
/// fn main() -> Result<(), Box<dyn std::error::Error>> {
///     // Load with union types (safe for any profile) using the builder pattern
///     let secrets = SecretSpec::builder()
///         .with_provider(Provider::Keyring)
///         .load()?;
///     println!("Database URL: {}", secrets.secrets.database_url);
///
///     // Load with profile-specific types
///     let profile_secrets = SecretSpec::builder()
///         .with_provider(Provider::Keyring)
///         .with_profile(Profile::Production)
///         .load_profile()?;
///     
///     match profile_secrets.secrets {
///         SecretSpecProfile::Production { api_key, database_url, .. } => {
///             println!("Production API key: {}", api_key);
///         }
///         _ => unreachable!(),
///     }
///
///     Ok(())
/// }
/// ```
#[proc_macro]
pub fn declare_secrets(input: TokenStream) -> TokenStream {
    let path = parse_macro_input!(input as LitStr).value();

    // Get the manifest directory of the crate using the macro
    let manifest_dir = std::env::var("CARGO_MANIFEST_DIR").unwrap_or_else(|_| ".".to_string());
    let full_path = std::path::Path::new(&manifest_dir).join(&path);

    let config: Config = match Config::try_from(full_path.as_path()) {
        Ok(config) => config,
        Err(e) => {
            let error = format!("Failed to parse TOML: {}", e);
            return quote! { compile_error!(#error); }.into();
        }
    };

    // Validate the configuration at compile time
    if let Err(validation_errors) = validate_config_for_codegen(&config) {
        let error_message = format!(
            "Invalid secretspec configuration:\n{}",
            validation_errors.join("\n")
        );
        return quote! { compile_error!(#error_message); }.into();
    }

    // Generate all the code
    let output = generate_secret_spec_code(config);
    output.into()
}

// ===== Core Helper Functions =====

/// Validate configuration for code generation concerns only.
///
/// This performs compile-time validation to ensure the configuration can be
/// converted into valid Rust code. This is different from runtime validation -
/// we only check things that would prevent generating valid Rust code.
///
/// # Validation Checks
///
/// - Secret names must produce valid Rust identifiers
/// - Secret names must not be Rust keywords
/// - Profile names must produce valid enum variants
/// - No duplicate field names within a profile (case-insensitive)
///
/// # Arguments
///
/// * `config` - The parsed project configuration
///
/// # Returns
///
/// - `Ok(())` if validation passes
/// - `Err(Vec<String>)` containing all validation errors if any are found
fn validate_config_for_codegen(config: &Config) -> Result<(), Vec<String>> {
    let mut errors = Vec::new();

    // Validate secret names produce valid Rust identifiers
    validate_rust_identifiers(config, &mut errors);

    // Validate profile names produce valid Rust enum variants
    validate_profile_identifiers(config, &mut errors);

    if errors.is_empty() {
        Ok(())
    } else {
        Err(errors)
    }
}

/// Validate all secret names produce valid Rust identifiers.
///
/// Checks that each secret name, when converted to a field name:
/// - Forms a valid Rust identifier (alphanumeric + underscores)
/// - Doesn't conflict with Rust keywords
/// - Doesn't create duplicate field names within a profile
///
/// # Arguments
///
/// * `config` - The project configuration to validate
/// * `errors` - Mutable vector to collect error messages
///
/// # Error Cases
///
/// - Secret names with invalid characters (e.g., "my-secret" with hyphen)
/// - Secret names that are Rust keywords (e.g., "TYPE", "IMPL")
/// - Multiple secrets producing the same field name (e.g., "API_KEY" and "api_key")
fn validate_rust_identifiers(config: &Config, errors: &mut Vec<String>) {
    let rust_keywords = [
        "as", "async", "await", "break", "const", "continue", "crate", "dyn", "else", "enum",
        "extern", "false", "fn", "for", "if", "impl", "in", "let", "loop", "match", "mod", "move",
        "mut", "pub", "ref", "return", "self", "Self", "static", "struct", "super", "trait",
        "true", "type", "unsafe", "use", "where", "while", "abstract", "become", "box", "do",
        "final", "macro", "override", "priv", "typeof", "unsized", "virtual", "yield", "try",
    ];

    for (profile_name, profile_config) in &config.profiles {
        let mut profile_field_names = HashSet::new();

        for secret_name in profile_config.secrets.keys() {
            let field_name = secret_name.to_lowercase();

            // Check if it produces a valid Rust identifier
            if !is_valid_rust_identifier(&field_name) {
                errors.push(format!(
                    "Secret '{}' in profile '{}' produces invalid Rust field name '{}'",
                    secret_name, profile_name, field_name
                ));
            }

            // Check for Rust keywords
            if rust_keywords.contains(&field_name.as_str()) {
                errors.push(format!(
                    "Secret '{}' in profile '{}' produces Rust keyword '{}' as field name",
                    secret_name, profile_name, field_name
                ));
            }

            // Check for duplicate field names within the same profile
            if !profile_field_names.insert(field_name.clone()) {
                errors.push(format!(
                    "Profile '{}' has multiple secrets that produce the same field name '{}' (names are case-insensitive)",
                    profile_name, field_name
                ));
            }
        }
    }
}

/// Check if a string is a valid Rust identifier.
///
/// A valid Rust identifier must:
/// - Start with a letter or underscore
/// - Contain only letters, numbers, and underscores
/// - Not be empty
///
/// # Arguments
///
/// * `s` - The string to validate
///
/// # Returns
///
/// `true` if the string is a valid Rust identifier, `false` otherwise
///
/// # Examples
///
/// ```ignore
/// assert!(is_valid_rust_identifier("my_var"));
/// assert!(is_valid_rust_identifier("_private"));
/// assert!(!is_valid_rust_identifier("123start"));
/// assert!(!is_valid_rust_identifier("my-var"));
/// ```
fn is_valid_rust_identifier(s: &str) -> bool {
    if s.is_empty() {
        return false;
    }

    let mut chars = s.chars();
    if let Some(first) = chars.next() {
        // First character must be alphabetic or underscore
        if !first.is_alphabetic() && first != '_' {
            return false;
        }
        // Remaining characters must be alphanumeric or underscore
        chars.all(|c| c.is_alphanumeric() || c == '_')
    } else {
        false
    }
}

/// Validate profile names produce valid Rust enum variants.
///
/// Ensures that each profile name, when capitalized, forms a valid Rust enum variant.
///
/// # Arguments
///
/// * `config` - The project configuration to validate
/// * `errors` - Mutable vector to collect error messages
///
/// # Error Cases
///
/// - Profile names that start with numbers (e.g., "1production")
/// - Profile names with invalid characters (e.g., "prod-env")
fn validate_profile_identifiers(config: &Config, errors: &mut Vec<String>) {
    for profile_name in config.profiles.keys() {
        let variant_name = capitalize(profile_name);
        if !is_valid_rust_identifier(&variant_name) {
            errors.push(format!(
                "Profile '{}' produces invalid Rust enum variant '{}'",
                profile_name, variant_name
            ));
        }
    }
}

/// Convert a secret name to a field identifier.
///
/// Converts environment variable style names to Rust field names by:
/// - Converting to lowercase
/// - Preserving underscores
///
/// # Arguments
///
/// * `name` - The secret name (typically uppercase with underscores)
///
/// # Returns
///
/// A proc_macro2::Ident suitable for use as a struct field
///
/// # Example
///
/// ```ignore
/// let ident = field_name_ident("DATABASE_URL");
/// // Generates: database_url
/// ```
fn field_name_ident(name: &str) -> proc_macro2::Ident {
    format_ident!("{}", name.to_lowercase())
}

/// Map a shared-IR field's optionality and path-ness to its Rust type.
///
/// This is the only typing decision the derive macro still makes locally; the
/// underlying optional/as_path facts come from [`secretspec::codegen`].
fn ir_field_type(field: &IrField) -> proc_macro2::TokenStream {
    match (field.optional, field.as_path) {
        (true, true) => quote! { Option<std::path::PathBuf> },
        (true, false) => quote! { Option<String> },
        (false, true) => quote! { std::path::PathBuf },
        (false, false) => quote! { String },
    }
}

/// Generate a unified secret assignment from a HashMap.
///
/// Creates the code to assign a value from a secrets map to a struct field,
/// with appropriate error handling based on whether the field is optional.
///
/// # Arguments
///
/// * `field_name` - The struct field identifier
/// * `secret_name` - The key to look up in the map
/// * `source` - Token stream representing the source map
/// * `is_optional` - Whether to generate Option<T> or T assignment
/// * `as_path` - Whether to generate PathBuf or String
///
/// # Generated Code
///
/// For required String fields:
/// ```ignore
/// field_name: source.get("SECRET_NAME")
///     .ok_or_else(|| SecretSpecError::RequiredSecretMissing("SECRET_NAME".to_string()))?
///     .expose_secret().to_string()
/// ```
///
/// For required PathBuf fields:
/// ```ignore
/// field_name: std::path::PathBuf::from(source.get("SECRET_NAME")
///     .ok_or_else(|| SecretSpecError::RequiredSecretMissing("SECRET_NAME".to_string()))?
///     .expose_secret())
/// ```
///
/// For optional fields:
/// ```ignore
/// field_name: source.get("SECRET_NAME").map(|s| s.expose_secret().to_string())
/// field_name: source.get("SECRET_NAME").map(|s| std::path::PathBuf::from(s.expose_secret()))
/// ```
fn generate_secret_assignment(
    field_name: &proc_macro2::Ident,
    secret_name: &str,
    source: proc_macro2::TokenStream,
    is_optional: bool,
    as_path: bool,
) -> proc_macro2::TokenStream {
    match (is_optional, as_path) {
        (true, true) => {
            // Optional PathBuf
            quote! {
                #field_name: #source.get(#secret_name).map(|s| std::path::PathBuf::from(s.expose_secret()))
            }
        }
        (true, false) => {
            // Optional String
            quote! {
                #field_name: #source.get(#secret_name).map(|s| s.expose_secret().to_string())
            }
        }
        (false, true) => {
            // Required PathBuf
            quote! {
                #field_name: std::path::PathBuf::from(
                    #source.get(#secret_name)
                        .ok_or_else(|| secretspec::SecretSpecError::RequiredSecretMissing(#secret_name.to_string()))?
                        .expose_secret()
                )
            }
        }
        (false, false) => {
            // Required String
            quote! {
                #field_name: #source.get(#secret_name)
                    .ok_or_else(|| secretspec::SecretSpecError::RequiredSecretMissing(#secret_name.to_string()))?
                    .expose_secret()
                    .to_string()
            }
        }
    }
}

/// Build the union struct's fields from the shared IR.
///
/// The IR already determined the union field set and each field's
/// optionality/as_path; this just maps them to `FieldInfo`, keyed and ordered
/// by name (the IR union is pre-sorted).
fn union_field_info(ir: &CodegenIr) -> BTreeMap<String, FieldInfo> {
    ir.union
        .iter()
        .map(|field| (field.name.clone(), FieldInfo::from_ir(field)))
        .collect()
}

/// Profile variants for enum generation, taken from the shared IR.
///
/// The IR's profile list is already sorted and already substitutes a single
/// `default` profile when the manifest declares none, so this is a direct map.
fn profile_variants_from_ir(ir: &CodegenIr) -> Vec<ProfileVariant> {
    ir.profiles
        .iter()
        .map(|name| ProfileVariant::new(name.clone()))
        .collect()
}

// ===== Profile Generation Module =====

/// Module for generating Profile enum and related implementations.
///
/// This module handles:
/// - Profile enum definition
/// - TryFrom implementations for string conversion
/// - as_str() method for profile serialization
mod profile_generation {
    use super::*;

    /// Generate just the Profile enum.
    ///
    /// Creates an enum with variants for each profile in the configuration.
    ///
    /// # Arguments
    ///
    /// * `variants` - List of profile variants to generate
    ///
    /// # Generated Code Example
    ///
    /// ```ignore
    /// #[derive(Debug, Clone, Copy)]
    /// pub enum Profile {
    ///     Development,
    ///     Production,
    ///     Staging,
    /// }
    /// ```
    pub fn generate_enum(variants: &[ProfileVariant]) -> proc_macro2::TokenStream {
        let enum_variants = variants.iter().map(|v| {
            let ident = v.as_ident();
            quote! { #ident }
        });

        quote! {
            #[derive(Debug, Clone, Copy)]
            pub enum Profile {
                #(#enum_variants,)*
            }
        }
    }

    /// Generate TryFrom implementations for Profile.
    ///
    /// Creates implementations to convert strings to Profile enum variants,
    /// supporting both &str and String inputs.
    ///
    /// # Arguments
    ///
    /// * `variants` - List of profile variants
    ///
    /// # Generated Code
    ///
    /// - `TryFrom<&str>` implementation with match arms for each profile
    /// - `TryFrom<String>` implementation that delegates to &str
    /// - Returns `SecretSpecError::InvalidProfile` for unknown profiles
    pub fn generate_try_from_impls(variants: &[ProfileVariant]) -> proc_macro2::TokenStream {
        let from_str_arms = variants.iter().map(|v| {
            let ident = v.as_ident();
            let str_val = &v.name;
            quote! { #str_val => Ok(Profile::#ident) }
        });

        quote! {
            impl std::convert::TryFrom<&str> for Profile {
                type Error = secretspec::SecretSpecError;

                fn try_from(value: &str) -> Result<Self, Self::Error> {
                    match value {
                        #(#from_str_arms,)*
                        _ => Err(secretspec::SecretSpecError::InvalidProfile(value.to_string())),
                    }
                }
            }

            impl std::convert::TryFrom<String> for Profile {
                type Error = secretspec::SecretSpecError;

                fn try_from(value: String) -> Result<Self, Self::Error> {
                    Profile::try_from(value.as_str())
                }
            }
        }
    }

    /// Generate as_str implementation for Profile.
    ///
    /// Creates a method to convert Profile enum variants back to their string representation.
    ///
    /// # Arguments
    ///
    /// * `variants` - List of profile variants
    ///
    /// # Generated Code Example
    ///
    /// ```ignore
    /// impl Profile {
    ///     fn as_str(&self) -> &'static str {
    ///         match self {
    ///             Profile::Development => "development",
    ///             Profile::Production => "production",
    ///         }
    ///     }
    /// }
    /// ```
    pub fn generate_as_str_impl(variants: &[ProfileVariant]) -> proc_macro2::TokenStream {
        let to_str_arms = variants.iter().map(|v| {
            let ident = v.as_ident();
            let str_val = &v.name;
            quote! { Profile::#ident => #str_val }
        });

        quote! {
            impl Profile {
                fn as_str(&self) -> &'static str {
                    match self {
                        #(#to_str_arms,)*
                    }
                }
            }
        }
    }

    /// Generate all profile-related code.
    ///
    /// Combines all profile generation functions into a single token stream.
    ///
    /// # Arguments
    ///
    /// * `variants` - List of profile variants
    ///
    /// # Returns
    ///
    /// Complete token stream containing:
    /// - Profile enum definition
    /// - TryFrom implementations
    /// - as_str() method
    pub fn generate_all(variants: &[ProfileVariant]) -> proc_macro2::TokenStream {
        let enum_def = generate_enum(variants);
        let try_from_impls = generate_try_from_impls(variants);
        let as_str_impl = generate_as_str_impl(variants);

        quote! {
            #enum_def
            #try_from_impls
            #as_str_impl
        }
    }
}

// ===== SecretSpec Generation Module =====

/// Module for generating SecretSpec struct and related implementations.
///
/// This module handles:
/// - SecretSpec struct (union of all secrets)
/// - SecretSpecProfile enum (profile-specific types)
/// - Loading implementations
/// - Environment variable integration
mod secret_spec_generation {
    use super::*;

    /// Generate the SecretSpec struct.
    ///
    /// Creates a struct containing all secrets from all profiles as fields.
    /// This is the "union" type that can safely hold secrets from any profile.
    ///
    /// # Arguments
    ///
    /// * `field_info` - Map of all fields with their type information
    ///
    /// # Generated Code Example
    ///
    /// ```ignore
    /// #[derive(Debug, serde::Serialize, serde::Deserialize)]
    /// pub struct SecretSpec {
    ///     pub database_url: String,
    ///     pub api_key: Option<String>,
    ///     pub redis_url: Option<String>,
    /// }
    /// ```
    pub fn generate_struct(field_info: &BTreeMap<String, FieldInfo>) -> proc_macro2::TokenStream {
        let fields = field_info.values().map(|info| info.generate_struct_field());

        quote! {
            #[derive(Debug, serde::Serialize, serde::Deserialize)]
            pub struct SecretSpec {
                #(#fields,)*
            }
        }
    }

    /// Generate the SecretSpecProfile enum.
    ///
    /// Creates an enum where each variant contains only the secrets defined
    /// for that specific profile. This provides stronger type safety when
    /// working with profile-specific secrets.
    ///
    /// # Arguments
    ///
    /// * `profile_variants` - Generated enum variant definitions
    ///
    /// # Generated Code Example
    ///
    /// ```ignore
    /// #[derive(Debug, serde::Serialize, serde::Deserialize)]
    /// pub enum SecretSpecProfile {
    ///     Development {
    ///         database_url: String,
    ///         redis_url: Option<String>,
    ///     },
    ///     Production {
    ///         database_url: String,
    ///         api_key: String,
    ///         redis_url: String,
    ///     },
    /// }
    /// ```
    pub fn generate_profile_enum(
        profile_variants: &[proc_macro2::TokenStream],
    ) -> proc_macro2::TokenStream {
        quote! {
            #[derive(Debug, serde::Serialize, serde::Deserialize)]
            pub enum SecretSpecProfile {
                #(#profile_variants,)*
            }
        }
    }

    /// Generate SecretSpecProfile enum variants.
    ///
    /// Creates the individual variants for the SecretSpecProfile enum,
    /// each containing only the fields defined for that profile.
    ///
    /// # Arguments
    ///
    /// * `config` - The project configuration
    /// * `field_info` - Field information (used for empty profile case)
    /// * `variants` - Profile variants to generate
    ///
    /// # Returns
    ///
    /// Vector of token streams, each representing one enum variant
    ///
    /// # Special Cases
    ///
    /// - Empty profiles → generates a Default variant with all fields
    /// - Each profile → generates variant with profile-specific fields
    pub fn generate_profile_enum_variants(ir: &CodegenIr) -> Vec<proc_macro2::TokenStream> {
        // The IR's per-profile field sets already handle the empty-profiles case
        // (a single `default` profile carrying the union), so there is no special
        // branch here: one variant per IR profile, with that profile's exact
        // (raw, non-merged) fields.
        ir.profile_fields
            .iter()
            .map(|profile| {
                let variant_ident = ProfileVariant::new(profile.name.clone()).as_ident();
                let fields = profile.fields.iter().map(|field| {
                    let field_name = field_name_ident(&field.name);
                    let field_type = ir_field_type(field);
                    quote! { #field_name: #field_type }
                });
                quote! {
                    #variant_ident {
                        #(#fields,)*
                    }
                }
            })
            .collect()
    }

    /// Generate load_profile match arms.
    ///
    /// Creates the match arms for loading profile-specific secrets into
    /// the appropriate SecretSpecProfile variant.
    ///
    /// # Arguments
    ///
    /// * `config` - The project configuration
    /// * `field_info` - Field information (for empty profile case)
    /// * `variants` - Profile variants to generate arms for
    ///
    /// # Returns
    ///
    /// Vector of match arms for the profile loading logic
    ///
    /// # Generated Code Example
    ///
    /// ```ignore
    /// Profile::Production => Ok(SecretSpecProfile::Production {
    ///     database_url: secrets.get("DATABASE_URL")
    ///         .ok_or_else(|| SecretSpecError::RequiredSecretMissing("DATABASE_URL".to_string()))?
    ///         .clone(),
    ///     api_key: secrets.get("API_KEY").cloned(),
    /// })
    /// ```
    pub fn generate_load_profile_arms(ir: &CodegenIr) -> Vec<proc_macro2::TokenStream> {
        // One arm per IR profile, assigning that profile's exact fields. The
        // empty-profiles case is already a single `default` profile in the IR.
        ir.profile_fields
            .iter()
            .map(|profile| {
                let variant_ident = ProfileVariant::new(profile.name.clone()).as_ident();
                let assignments = profile.fields.iter().map(|field| {
                    generate_secret_assignment(
                        &field_name_ident(&field.name),
                        &field.name,
                        quote! { secrets },
                        field.optional,
                        field.as_path,
                    )
                });
                quote! {
                    Profile::#variant_ident => Ok(SecretSpecProfile::#variant_ident {
                        #(#assignments,)*
                    })
                }
            })
            .collect()
    }

    /// Generate the shared load_internal implementation.
    ///
    /// Creates a helper function that handles the common loading logic
    /// for both SecretSpec and SecretSpecProfile loading methods.
    ///
    /// # Generated Function
    ///
    /// The function:
    /// 1. Loads the SecretSpec configuration
    /// 2. Validates it with the given provider and profile
    /// 3. Returns the validation result containing loaded secrets
    pub fn generate_load_internal() -> proc_macro2::TokenStream {
        quote! {
            fn load_internal(
                provider_str: Option<String>,
                profile_str: Option<String>,
                reason: Option<String>,
            ) -> Result<secretspec::ValidatedSecrets, secretspec::SecretSpecError> {
                let mut spec = secretspec::Secrets::load()?;
                if let Some(provider) = provider_str {
                    spec.set_provider(provider);
                }
                if let Some(profile) = profile_str {
                    spec.set_profile(profile);
                }
                // Apply an explicit builder reason on top of any SECRETSPEC_REASON
                // already resolved by `Secrets::load`. Required to satisfy the
                // `require_reason` policy (default "agents") from typed SDK code,
                // which otherwise has no way to supply a reason. A blank reason is
                // ignored by `with_reason`, leaving the env-resolved value intact.
                if let Some(reason) = reason {
                    spec = spec.with_reason(reason);
                }
                match spec.validate()? {
                    Ok(valid_secrets) => Ok(valid_secrets),
                    Err(validation_errors) if validation_errors.constraint_violations.is_empty() => {
                        Err(secretspec::SecretSpecError::RequiredSecretMissing(
                            validation_errors.missing_required.join(", ")
                        ))
                    }
                    Err(validation_errors) => Err(secretspec::SecretSpecError::ValidationFailed(
                        Box::new(validation_errors)
                    ))
                }
            }
        }
    }

    /// Generate SecretSpec implementation.
    ///
    /// Creates the impl block for SecretSpec with:
    /// - builder() method for creating a builder
    /// - load() method for loading with union types
    /// - set_as_env_vars() method for environment variable integration
    ///
    /// # Arguments
    ///
    /// * `load_assignments` - Field assignments for the load method
    /// * `env_setters` - Environment variable setter statements
    /// * `_field_info` - Field information (currently unused)
    ///
    /// # Generated Methods
    ///
    /// - `builder()` - Creates a new SecretSpecBuilder
    /// - `load()` - Loads secrets with optional provider/profile
    /// - `set_as_env_vars()` - Sets all secrets as environment variables
    pub fn generate_impl(
        load_assignments: &[proc_macro2::TokenStream],
        env_setters: Vec<proc_macro2::TokenStream>,
        _field_info: &BTreeMap<String, FieldInfo>,
    ) -> proc_macro2::TokenStream {
        quote! {
            impl SecretSpec {
                /// Create a new builder for loading secrets
                pub fn builder() -> SecretSpecBuilder {
                    SecretSpecBuilder::new()
                }

                /// Load secrets with optional provider and/or profile
                /// Provider can be any type that implements Into<String> (e.g., &str, String, etc.)
                /// If provider is None, uses SECRETSPEC_PROVIDER env var or global config
                /// If profile is None, uses SECRETSPEC_PROFILE env var if set
                pub fn load<P>(provider: Option<P>, profile: Option<Profile>) -> Result<secretspec::Resolved<Self>, secretspec::SecretSpecError>
                where
                    P: Into<String>,
                {
                    // Convert options to strings
                    let provider_str = provider.map(Into::into).or_else(|| std::env::var("SECRETSPEC_PROVIDER").ok());

                    let profile_str = match profile {
                        Some(p) => Some(p.as_str().to_string()),
                        None => std::env::var("SECRETSPEC_PROFILE").ok(),
                    };

                    // The static `load` has no reason parameter; a reason is supplied
                    // via the SECRETSPEC_REASON env var (honored by `Secrets::load`)
                    // or through `SecretSpec::builder().with_reason(...)`.
                    let validation_result = load_internal(provider_str, profile_str, None)?;
                    let provider_name = validation_result.resolved.provider.clone();
                    let profile = validation_result.resolved.profile.clone();
                    let secrets = validation_result.resolved.secrets;

                    let data = Self {
                        #(#load_assignments,)*
                    };

                    Ok(secretspec::Resolved::new(
                        data,
                        provider_name,
                        profile
                    ))
                }

                pub fn set_as_env_vars(&self) {
                    #(#env_setters)*
                }
            }
        }
    }
}

// ===== Builder Generation Module =====

/// Module for generating the builder pattern implementation.
///
/// The builder provides a fluent API for configuring how secrets are loaded,
/// with support for:
/// - Custom providers (via URIs)
/// - Profile selection
/// - Type-safe loading (union or profile-specific)
mod builder_generation {
    use super::*;

    /// Generate the builder struct definition.
    ///
    /// The builder uses boxed closures to defer provider/profile resolution
    /// until load time, allowing for flexible configuration.
    ///
    /// # Generated Struct
    ///
    /// ```ignore
    /// pub struct SecretSpecBuilder {
    ///     provider: Option<Box<dyn FnOnce() -> Result<Box<dyn secretspec::Provider>, String>>>,
    ///     profile: Option<Box<dyn FnOnce() -> Result<Profile, String>>>,
    ///     reason: Option<String>,
    /// }
    /// ```
    pub fn generate_struct() -> proc_macro2::TokenStream {
        quote! {
            pub struct SecretSpecBuilder {
                provider: Option<Box<dyn FnOnce() -> Result<Box<dyn secretspec::Provider>, String>>>,
                profile: Option<Box<dyn FnOnce() -> Result<Profile, String>>>,
                reason: Option<String>,
            }
        }
    }

    /// Generate builder basic methods.
    ///
    /// Creates the foundational builder methods:
    /// - Default implementation
    /// - new() constructor
    /// - with_provider() for setting provider
    /// - with_profile() for setting profile
    ///
    /// # Type Flexibility
    ///
    /// Both with_provider and with_profile accept anything that can be
    /// converted to the target type (Uri or Profile), providing flexibility:
    ///
    /// ```ignore
    /// builder.with_provider("keyring://")           // &str
    ///        .with_provider(Provider::Keyring)      // Provider enum
    ///        .with_profile("production")            // &str
    ///        .with_profile(Profile::Production)      // Profile enum
    /// ```
    pub fn generate_basic_methods() -> proc_macro2::TokenStream {
        quote! {
            impl Default for SecretSpecBuilder {
                fn default() -> Self {
                    Self::new()
                }
            }

            impl SecretSpecBuilder {
                pub fn new() -> Self {
                    Self {
                        provider: None,
                        profile: None,
                        reason: None,
                    }
                }

                /// Set a human-readable reason for this session's secret access.
                ///
                /// Required to satisfy the project's `require_reason` policy
                /// (`[project].require_reason` in secretspec.toml, default `"agents"`)
                /// when loading from agent contexts, and recorded in the audit log.
                /// Mirrors the CLI `--reason` flag and `Secrets::with_reason`. A blank
                /// reason is ignored, falling back to the `SECRETSPEC_REASON` env var.
                pub fn with_reason<T>(mut self, reason: T) -> Self
                where
                    T: Into<String>,
                {
                    self.reason = Some(reason.into());
                    self
                }

                pub fn with_provider<T>(mut self, provider: T) -> Self
                where
                    T: TryInto<Box<dyn secretspec::Provider>> + 'static,
                    T::Error: std::fmt::Display + 'static,
                {
                    self.provider = Some(Box::new(move || {
                        provider.try_into()
                            .map_err(|e| format!("Invalid provider: {}", e))
                    }));
                    self
                }

                pub fn with_profile<T>(mut self, profile: T) -> Self
                where
                    T: TryInto<Profile>,
                    T::Error: std::fmt::Display
                {
                    match profile.try_into() {
                        Ok(p) => {
                            self.profile = Some(Box::new(move || Ok(p)));
                        }
                        Err(e) => {
                            let error_msg = format!("{}", e);
                            self.profile = Some(Box::new(move || Err(error_msg)));
                        }
                    }
                    self
                }
            }
        }
    }

    /// Generate provider resolution logic.
    ///
    /// Creates code to resolve a provider from the builder's boxed closure.
    ///
    /// # Arguments
    ///
    /// * `provider_expr` - Expression to access the provider option
    ///
    /// # Generated Logic
    ///
    /// 1. If provider is set, call the closure to get the Provider instance
    /// 2. Convert any errors to SecretSpecError
    /// 3. Extract the provider name to pass to the loading system
    fn generate_provider_resolution(
        provider_expr: proc_macro2::TokenStream,
    ) -> proc_macro2::TokenStream {
        quote! {
            let provider_str = if let Some(provider_fn) = #provider_expr {
                let provider_box = provider_fn()
                    .map_err(|e| secretspec::SecretSpecError::ProviderOperationFailed(e))?;
                // Get the full URI to pass as a string to set_provider (preserves vault info)
                Some(provider_box.uri())
            } else {
                None
            };
        }
    }

    /// Generate profile resolution logic.
    ///
    /// Creates code to resolve a profile from the builder's boxed closure.
    ///
    /// # Arguments
    ///
    /// * `profile_expr` - Expression to access the profile option
    ///
    /// # Generated Logic
    ///
    /// 1. If profile is set, call the closure to get the Profile
    /// 2. Convert any errors to SecretSpecError
    /// 3. Convert Profile to string for the loading system
    fn generate_profile_resolution(
        profile_expr: proc_macro2::TokenStream,
    ) -> proc_macro2::TokenStream {
        quote! {
            let profile_str = if let Some(profile_fn) = #profile_expr {
                let profile = profile_fn()
                    .map_err(|e| secretspec::SecretSpecError::InvalidProfile(e))?;
                Some(profile.as_str().to_string())
            } else {
                None
            };
        }
    }

    /// Generate load methods for the builder.
    ///
    /// Creates two loading methods:
    /// - `load()` - Returns SecretSpec (union type)
    /// - `load_profile()` - Returns SecretSpecProfile (profile-specific type)
    ///
    /// # Arguments
    ///
    /// * `load_assignments` - Field assignments for union type
    /// * `load_profile_arms` - Match arms for profile-specific loading
    /// * `first_profile_variant` - Default profile if none specified
    ///
    /// # Key Differences
    ///
    /// - `load()` returns all secrets with optional fields for safety
    /// - `load_profile()` returns only profile-specific secrets with exact types
    pub fn generate_load_methods(
        load_assignments: &[proc_macro2::TokenStream],
        load_profile_arms: &[proc_macro2::TokenStream],
        first_profile_variant: &proc_macro2::Ident,
    ) -> proc_macro2::TokenStream {
        let resolve_provider_load = generate_provider_resolution(quote! { self.provider.take() });
        let resolve_profile_load = generate_profile_resolution(quote! { self.profile.take() });
        let resolve_provider_profile =
            generate_provider_resolution(quote! { self.provider.take() });

        quote! {
            impl SecretSpecBuilder {
                pub fn load(mut self) -> Result<secretspec::Resolved<SecretSpec>, secretspec::SecretSpecError> {
                    #resolve_provider_load
                    #resolve_profile_load
                    let reason_str = self.reason.take();

                    let validation_result = load_internal(provider_str, profile_str, reason_str)?;
                    let provider_name = validation_result.resolved.provider.clone();
                    let profile = validation_result.resolved.profile.clone();
                    let secrets = validation_result.resolved.secrets;

                    let data = SecretSpec {
                        #(#load_assignments,)*
                    };

                    Ok(secretspec::Resolved::new(
                        data,
                        provider_name,
                        profile
                    ))
                }

                pub fn load_profile(mut self) -> Result<secretspec::Resolved<SecretSpecProfile>, secretspec::SecretSpecError> {
                    #resolve_provider_profile
                    let reason_str = self.reason.take();

                    let (profile_str, selected_profile) = if let Some(profile_fn) = self.profile.take() {
                        let profile = profile_fn()
                            .map_err(|e| secretspec::SecretSpecError::InvalidProfile(e))?;
                        (Some(profile.as_str().to_string()), profile)
                    } else {
                        // Check env var for profile. A blank value is treated as
                        // unset (matching `secretspec::Secrets`) and a padded
                        // value is trimmed, so a stray empty var or a `$(cat
                        // file)` trailing newline neither errors here nor selects
                        // a nonexistent profile.
                        let profile_str = std::env::var("SECRETSPEC_PROFILE")
                            .ok()
                            .map(|s| s.trim().to_string())
                            .filter(|s| !s.is_empty());
                        let selected_profile = if let Some(ref profile_name) = profile_str {
                            Profile::try_from(profile_name.as_str())?
                        } else {
                            Profile::#first_profile_variant
                        };
                        (profile_str, selected_profile)
                    };

                    let validation_result = load_internal(provider_str, profile_str, reason_str)?;
                    let provider_name = validation_result.resolved.provider.clone();
                    let profile = validation_result.resolved.profile.clone();
                    let secrets = validation_result.resolved.secrets;

                    let data_result: LoadResult<SecretSpecProfile> = match selected_profile {
                        #(#load_profile_arms,)*
                    };
                    let data = data_result?;

                    Ok(secretspec::Resolved::new(
                        data,
                        provider_name,
                        profile
                    ))
                }
            }
        }
    }

    /// Generate all builder-related code.
    ///
    /// Combines all builder components into a complete implementation.
    ///
    /// # Arguments
    ///
    /// * `load_assignments` - Field assignments for union loading
    /// * `load_profile_arms` - Match arms for profile loading
    /// * `first_profile_variant` - Default profile variant
    ///
    /// # Returns
    ///
    /// Complete token stream containing:
    /// - Builder struct definition
    /// - Basic builder methods
    /// - Loading methods (load and load_profile)
    pub fn generate_all(
        load_assignments: &[proc_macro2::TokenStream],
        load_profile_arms: &[proc_macro2::TokenStream],
        first_profile_variant: &proc_macro2::Ident,
    ) -> proc_macro2::TokenStream {
        let struct_def = generate_struct();
        let basic_methods = generate_basic_methods();
        let load_methods =
            generate_load_methods(load_assignments, load_profile_arms, first_profile_variant);

        quote! {
            #struct_def
            #basic_methods
            #load_methods
        }
    }
}

/// Main code generation function.
///
/// Orchestrates the entire code generation process, coordinating all modules
/// to produce the complete macro output.
///
/// # Arguments
///
/// * `config` - The validated project configuration
///
/// # Returns
///
/// Complete token stream containing all generated code
///
/// # Generation Process
///
/// 1. Analyze profiles and field types
/// 2. Generate Profile enum and implementations
/// 3. Generate SecretSpec struct (union type)
/// 4. Generate SecretSpecProfile enum (profile-specific types)
/// 5. Generate builder pattern implementation
/// 6. Combine all components with necessary imports
fn generate_secret_spec_code(config: Config) -> proc_macro2::TokenStream {
    // Reduce the manifest to the shared codegen IR once. Every typing decision
    // (union vs per-profile fields, optionality, as_path, profile list) comes
    // from here, so this macro and the other-language emitters cannot drift.
    let ir = build_ir(&config);

    let profile_variants = profile_variants_from_ir(&ir);

    // Union struct fields.
    let field_info = union_field_info(&ir);

    // Generate field assignments for load()
    let load_assignments: Vec<_> = field_info
        .values()
        .map(|info| info.generate_assignment(quote! { secrets }))
        .collect();

    // Generate env var setters
    let env_setters: Vec<_> = field_info
        .values()
        .map(|info| info.generate_env_setter())
        .collect();

    // Generate profile components
    let profile_code = profile_generation::generate_all(&profile_variants);

    // Generate SecretSpec components
    let secret_spec_struct = secret_spec_generation::generate_struct(&field_info);
    let profile_enum_variants = secret_spec_generation::generate_profile_enum_variants(&ir);
    let secret_spec_profile_enum =
        secret_spec_generation::generate_profile_enum(&profile_enum_variants);
    let load_profile_arms = secret_spec_generation::generate_load_profile_arms(&ir);
    let load_internal = secret_spec_generation::generate_load_internal();
    let secret_spec_impl =
        secret_spec_generation::generate_impl(&load_assignments, env_setters, &field_info);

    // Get first profile variant for defaults
    // Get first profile variant for defaults
    let first_profile_variant = profile_variants
        .first()
        .map(|v| v.as_ident())
        .unwrap_or_else(|| format_ident!("Default"));

    // Generate builder
    let builder_code = builder_generation::generate_all(
        &load_assignments,
        &load_profile_arms,
        &first_profile_variant,
    );

    // Combine all components
    quote! {
        use ::secrecy::ExposeSecret;

        #secret_spec_struct
        #secret_spec_profile_enum
        #profile_code


        // Type alias to help with type inference
        type LoadResult<T> = Result<T, secretspec::SecretSpecError>;

        #load_internal
        #builder_code
        #secret_spec_impl
    }
}

#[cfg(test)]
#[path = "tests.rs"]
mod derive_tests;
