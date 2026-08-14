const { Monosecret } = require("monosecret");

const resolved = Monosecret.builder()
  .withProvider("keyring://")
  .withProfile("production")
  .withReason("boot web app")
  .load();

console.log(resolved.provider, resolved.profile);
const db = resolved.secrets.DATABASE_URL;
console.log(db.get()); // the value, or the file path for as_path secrets
resolved.setAsEnv(); // export everything into process.env
