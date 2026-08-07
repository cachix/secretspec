import { Convert } from './secrets_gen'; // typed, generated

const typed = Convert.toSecretSpec(resolved.fieldsJson());
console.log(typed.DATABASE_URL);
